"""Import osquery result logs and explicit ad-hoc snapshots without querying hosts."""

import base64
import binascii
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO
from uuid import UUID, uuid5

from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "OSQuery Results Import",
    "description": (
        "Import osquery snapshots and differential results with host, query/pack and source-indicator provenance."
    ),
    "module-type": ["import"],
    "logo": "osquery.png",
    "requirements": ["PyMISP"],
    "features": (
        "Completes the return path from OSQuery Export and OSQuery Pack Publish. Accepts JSON/JSONL event, batch"
        " and snapshot logs, plus explicitly identified ad-hoc snapshots. Preserves host/query/pack identity, execution"
        " time, schedule epoch/counter, row action, decorations, raw rows and hunting source references. Empty results"
        " remain separate from matches, and removed rows do not delete MISP data. Includes an osquery-result template."
        " No SQL execution, endpoint access or new dependencies. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/osquery_import.md)."
    ),
    "references": ["https://osquery.readthedocs.io/en/stable/deployment/logging/"],
    "input": "Base64-encoded UTF-8 JSON/JSONL result export; optional collector context and exporter sources map.",
    "output": "Exact source file and unreviewed osquery-result objects, including explicit empty-result records.",
}
MAX_INPUT = 20 * 1024 * 1024
MAX_ROWS = 1000
MAX_ROW = 128 * 1024
MAX_DEPTH = 32
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
NAMESPACE = UUID("88b50e3a-99d6-4705-a54d-d04860eb986a")
CONTEXT = ("host_identifier", "query_name", "pack_name", "executed_at", "osquery_version")
PAYLOADS = ("columns", "snapshot", "diffResults")


@lru_cache(maxsize=1)
def _template():
    return json.loads(resources.files("misp_modules").joinpath("data", "osquery-result", "definition.json").read_text())


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Non-finite JSON number: " + value)


def _loads(text):
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)


def _text(value, field):
    if (
        isinstance(value, bool)
        or not isinstance(value, (str, int))
        or not str(value).strip()
        or "\x00" in str(value)
        or len(str(value)) > 4096
    ):
        raise ValueError(f"{field} must be non-empty text or an integer identifier, at most 4096 characters.")
    return str(value)


def _bounded(value):
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ValueError("Result nesting exceeds 32 levels.")
        if isinstance(item, dict):
            for key in item:
                key.encode("utf-8")
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            item.encode("utf-8")
    if len(_json(value).encode()) > MAX_ROW:
        raise ValueError("A normalized record, row or source-reference list exceeds 128 KiB.")


def _read(text, format_):
    automatic = format_ == "auto"
    if automatic:
        format_ = "json"
    if format_ == "json":
        try:
            value = _loads(text)
        except json.JSONDecodeError:
            if not automatic or text.lstrip().startswith("["):
                raise
        else:
            return value, "json"
    records = []
    for line in text.split("\n"):
        if line.strip():
            if len(records) >= MAX_ROWS:
                raise ValueError("Export exceeds 1000 source records.")
            records.append(_loads(line))
    return records, "jsonl"


def _sources(value):
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        value = _loads(value)
    if not isinstance(value, dict) or len(value) > MAX_ROWS:
        raise ValueError("sources must be an exporter sources map with at most 1000 query keys.")
    if len(_json(value).encode()) > MAX_INPUT:
        raise ValueError("sources exceeds 20 MiB.")
    for key, refs in value.items():
        _text(key, "source query key")
        if not isinstance(refs, list) or len(refs) > MAX_ROWS:
            raise ValueError("Each source query must map to a list of at most 1000 references.")
        _bounded(refs)
        for ref in refs:
            if not isinstance(ref, dict):
                raise ValueError("Each source indicator reference must be an object.")
            for field in ("event", "attribute", "misp_type"):
                _text(ref.get(field), "source " + field)
            if "object" in ref:
                _text(ref["object"], "source object")
    return value


def _expand(record):
    if not isinstance(record, dict):
        raise ValueError("Every native source record must be an object.")
    kinds = [key for key in PAYLOADS if key in record]
    if len(kinds) != 1:
        raise ValueError(
            "Expected exactly one native columns, snapshot or diffResults payload; use input_type=snapshot for ad-hoc"
            " rows."
        )
    payload = kinds[0]
    action = record.get("action")
    if payload == "columns":
        if action not in ("added", "removed", "snapshot") or not isinstance(record["columns"], dict):
            raise ValueError("Event logs require an added/removed/snapshot action and a columns object.")
        return "snapshot" if action == "snapshot" else "differential", [(action, record["columns"])], action
    if payload == "snapshot":
        if action not in (None, "snapshot") or not isinstance(record["snapshot"], list):
            raise ValueError("Snapshot logs require a snapshot array and a compatible action.")
        if len(record["snapshot"]) > MAX_ROWS:
            raise ValueError("Export exceeds 1000 result rows.")
        return "snapshot", [("snapshot", row) for row in record["snapshot"]], "snapshot"
    diff = record["diffResults"]
    if action is not None or not isinstance(diff, dict) or set(diff) != {"added", "removed"}:
        raise ValueError("Batch logs require exactly added/removed arrays and no top-level action.")
    if any(not isinstance(diff[key], list) for key in ("removed", "added")):
        raise ValueError("Differential added/removed values must be arrays.")
    if sum(len(diff[key]) for key in ("removed", "added")) > MAX_ROWS:
        raise ValueError("Export exceeds 1000 result rows.")
    return "differential", [(key, row) for key in ("removed", "added") for row in diff[key]], None


def _identity(record, defaults):
    host = _text(record.get("hostIdentifier", defaults.get("host_identifier")), "hostIdentifier")
    scheduled = _text(record.get("name", defaults.get("query_name")), "query name")
    pack = record.get("pack_name", defaults.get("pack_name"))
    if pack not in (None, ""):
        pack = _text(pack, "pack_name")
    query = scheduled
    match = re.fullmatch(r"pack_(.+)_(misp_[0-9a-f]{64})", scheduled)
    if match:
        inferred_pack, query = match.groups()
        if pack and pack != inferred_pack:
            raise ValueError("Explicit pack_name conflicts with the MISP-generated scheduled name.")
        pack = inferred_pack
    elif pack and scheduled.startswith("pack_" + pack + "_"):
        query = _text(scheduled[len("pack_" + pack + "_") :], "query name")
    if defaults.get("query_name") and defaults["query_name"] not in (scheduled, query):
        raise ValueError("Explicit query_name conflicts with the native scheduled name.")
    return host, scheduled, query, pack


def _instant(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T"
            r" ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
            value,
        )
        or value.endswith("-00:00")
    ):
        raise ValueError("Execution time requires a known offset and at most microsecond precision.")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class _Builder:
    def __init__(self, raw, filename, defaults, sources, format_):
        self.event, self.warnings = MISPEvent(), Counter()
        self.defaults, self.sources, self.format = defaults, sources, format_
        self.digest = hashlib.sha256(raw).hexdigest()
        self.source = MISPObject("file", strict=True, standalone=False)
        self.source.uuid = str(uuid5(NAMESPACE, _json([self.digest, filename])))
        self.source.comment = (
            "Exact osquery result export; SQL and referenced host/source paths are not executed or fetched."
        )
        for relation, value in {"filename": filename, "sha256": self.digest, "size-in-bytes": len(raw)}.items():
            self.add(self.source, relation, value)
        self.add(self.source, "attachment", filename, data=BytesIO(raw))
        self.event.add_object(self.source)
        self.rows = self.empty = self.objects = 0

    def add(self, obj, relation, value, **kwargs):
        attribute = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
        attribute.uuid = str(uuid5(UUID(str(obj.uuid)), _json([relation, str(value)])))

    def time(self, obj, record):
        if record.get("unixTime") not in (None, ""):
            value = record["unixTime"]
            self.add(obj, "unix-time", value if isinstance(value, str) else _json(value))
            try:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (str, int))
                    or not re.fullmatch(r"[+-]?[0-9]{1,20}", str(value))
                ):
                    raise ValueError()
                parsed = EPOCH + timedelta(seconds=int(value))
            except (ValueError, OverflowError):
                self.warnings["Invalid unixTime seconds; original time retained without normalization"] += 1
            else:
                self.add(obj, "execution-time", parsed.isoformat())
        elif self.defaults.get("executed_at"):
            value = self.defaults["executed_at"]
            self.add(obj, "execution-time-raw", value)
            try:
                self.add(obj, "execution-time", _instant(value).isoformat())
            except (ValueError, OverflowError):
                self.warnings["Unsupported collector execution time; retained without normalization"] += 1
        else:
            self.warnings["No unixTime or collector executed_at; execution time not inferred"] += 1
        if record.get("calendarTime") not in (None, ""):
            self.add(obj, "calendar-time", _text(record["calendarTime"], "calendarTime"))

    def record(self, record, number):
        kind, rows, empty_action = _expand(record)
        if len(rows) > MAX_ROWS or self.objects + max(1, len(rows)) > MAX_ROWS:
            raise ValueError("Export exceeds 1000 result rows/empty-result records.")
        if any(not isinstance(row, dict) for _, row in rows):
            raise ValueError("Every returned row must be an object.")
        metadata = {key: value for key, value in record.items() if key not in PAYLOADS}
        _bounded(metadata)
        host, scheduled, query, pack = _identity(record, self.defaults)
        refs = self.sources.get(scheduled, self.sources.get(query, []))
        if re.fullmatch(r"misp_[0-9a-f]{64}", query) and not refs:
            self.warnings["No source-indicator map entry for MISP query; indicator origins not inferred"] += 1
        for index, (action, row) in enumerate(rows or [(empty_action, None)], 1):
            if row is not None:
                _bounded(row)
            obj = MISPObject("osquery-result", strict=True, standalone=False, misp_objects_template_custom=_template())
            obj.uuid = str(
                uuid5(
                    NAMESPACE,
                    _json(
                        [
                            str(self.source.uuid),
                            number,
                            index,
                            host,
                            scheduled,
                            query,
                            pack,
                            self.defaults,
                            refs,
                        ]
                    ),
                )
            )
            values = {
                "host-identifier": host,
                "scheduled-name": scheduled,
                "query-name": query,
                "record-index": number,
                "row-count": len(rows),
                "result-kind": kind,
                "record-type": "row" if row is not None else "empty-result",
                "record-context": _json(metadata),
                "source-sha256": self.digest,
                "source-format": self.format,
                "review-status": "unreviewed",
            }
            if pack:
                values["pack-name"] = pack
            if action:
                values["row-action"] = action
            if row is not None:
                values.update({"row": _json(row), "row-index": index})
            if refs:
                values["source-indicators"] = _json(refs)
            version = record.get("osquery_version", self.defaults.get("osquery_version"))
            if version not in (None, ""):
                values["osquery-version"] = _text(version, "osquery_version")
            for key, relation in (("epoch", "epoch"), ("counter", "counter")):
                if record.get(key) is not None:
                    values[relation] = _text(record[key], key)
            if "decorations" in record:
                values["decorations"] = _json(record["decorations"])
            if "numerics" in record:
                if not isinstance(record["numerics"], bool):
                    raise ValueError("numerics must be a JSON boolean.")
                values["numerics"] = record["numerics"]
            for relation, value in values.items():
                self.add(obj, relation, value)
            self.time(obj, record)
            self.event.add_object(obj)
            reference = self.source.add_reference(obj.uuid, "derived-from")
            reference.uuid = str(uuid5(UUID(str(self.source.uuid)), str(obj.uuid)))
            self.objects += 1
            self.rows += row is not None
            self.empty += row is None


def handler(q=False):
    if q is False:
        return False
    try:
        request = _loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an import request object.")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        format_, input_type = config.get("format", "auto"), config.get("input_type", "auto")
        if format_ in (None, ""):
            format_ = "auto"
        if input_type in (None, ""):
            input_type = "auto"
        if format_ not in ("auto", "json", "jsonl") or input_type not in ("auto", "snapshot"):
            raise ValueError("format must be auto/json/jsonl; input_type must be auto/snapshot.")
        encoded = request.get("data")
        if not isinstance(encoded, str) or not encoded or len(encoded) > 4 * ((MAX_INPUT + 2) // 3):
            raise ValueError("data must be a base64-encoded export of at most 20 MiB.")
        raw = base64.b64decode(encoded, validate=True)
        if not raw or len(raw) > MAX_INPUT:
            raise ValueError("Export must be non-empty and at most 20 MiB.")
        data, format_ = _read(raw.decode("utf-8-sig"), format_)
        metadata, sources = {}, {}
        if isinstance(data, dict) and "results" in data and not any(key in data for key in PAYLOADS):
            metadata = data.get("metadata", {})
            if not isinstance(metadata, dict):
                raise ValueError("metadata must be an object.")
            sources = _sources(data.get("sources"))
            data = data["results"]
        for key, refs in _sources(config.get("sources")).items():
            if key in sources and _json(sources[key]) != _json(refs):
                raise ValueError("Conflicting sources map entries: " + key)
            sources[key] = refs
        defaults = {}
        for key in CONTEXT:
            values = [_text(c[key], key) for c in (metadata, config) if c.get(key) not in (None, "")]
            if values and len(set(values)) != 1:
                raise ValueError("Conflicting metadata/config " + key)
            if values:
                defaults[key] = values[0]
        records = data if isinstance(data, list) else [data]
        if len(records) > MAX_ROWS or (not records and input_type != "snapshot"):
            raise ValueError("Native export must contain 1–1000 source records.")
        if input_type == "snapshot":
            records = [{"snapshot": records, "action": "snapshot"}]
        filename = request.get("filename")
        if filename in (None, ""):
            filename = "osquery-results." + format_
        filename = _text(filename, "filename").replace("\\", "/").rsplit("/", 1)[-1]
        if filename in ("", ".", "..") or any(ord(c) < 32 for c in filename):
            raise ValueError("filename requires a basename without control characters.")
        builder = _Builder(raw, filename, defaults, sources, format_)
        for number, record in enumerate(records, 1):
            builder.record(record, number)
        return {
            "results": {"Object": json.loads(builder.event.to_json())["Object"]},
            "summary": {
                "records": len(records),
                "rows": builder.rows,
                "empty_results": builder.empty,
                "source_sha256": builder.digest,
            },
            "warnings": [f"{message}: {count}" for message, count in sorted(builder.warnings.items())],
        }
    except (ValueError, TypeError, UnicodeError, binascii.Error, PyMISPError, RecursionError, OverflowError) as error:
        return {"error": f"Unable to import osquery results: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "format": {"type": "String", "message": "auto (default), json or jsonl"},
            "input_type": {"type": "String", "message": "auto for native logs; snapshot for explicit ad-hoc rows"},
            "host_identifier": {
                "type": "String",
                "message": "Host default when absent from native logs; required for ad-hoc rows",
            },
            "query_name": {
                "type": "String",
                "message": "Query identity for ad-hoc rows; must agree with native logs if supplied",
            },
            "pack_name": {"type": "String", "message": "Optional explicit pack identity for ambiguous scheduled names"},
            "executed_at": {
                "type": "String",
                "message": "Optional known-offset ISO execution time when unixTime is absent",
            },
            "osquery_version": {"type": "String", "message": "Optional producing osquery version"},
            "sources": {
                "type": "String",
                "message": "Optional JSON sources map returned by OSQuery Export/Pack Publish",
            },
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
