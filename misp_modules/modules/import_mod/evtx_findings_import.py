"""Import Hayabusa timelines and Chainsaw hunt detections without running either tool."""

import base64
import binascii
import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO, StringIO
from uuid import UUID, uuid5

from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

moduleconfig = []
mispattributes = {"inputSource": ["file"], "output": ["MISP objects"], "format": "misp_standard"}
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Hayabusa and Chainsaw Findings Import",
    "description": (
        "Import Hayabusa timelines and Chainsaw hunt results as unreviewed detections with linked Windows event"
        " context."
    ),
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Accepts Hayabusa JSON, JSONL and CSV timelines and Chainsaw hunt JSON/JSONL, including aggregate and cached"
        " results. Preserves the original export, rule identity/severity, host, channel, provider, Windows Event ID,"
        " record ID, EVTX references and unmapped data. Aggregate event contexts remain separate linked objects. A rule"
        " match is unreviewed, not an analyst-confirmed malicious finding. All attributes are non-IDS and"
        " non-correlating. Includes compatible object templates; no tool execution, network access or new dependencies."
        " See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/evtx_findings_import.md)."
    ),
    "references": [
        "https://github.com/Yamato-Security/hayabusa/blob/main/config/profiles.yaml",
        "https://github.com/WithSecureOpenSource/chainsaw/blob/master/src/cli.rs",
    ],
    "input": "Base64-encoded UTF-8 detection export in data; optional filename and tool/format settings.",
    "output": "Source file, windows-event-log-detection and windows-event-log-record objects.",
}

MAX_INPUT = 20 * 1024 * 1024
MAX_RESULTS = 1000
MAX_EVENTS = 5000
MAX_RESULT = 256 * 1024
MAX_DEPTH = 32
NAMESPACE = UUID("d9032043-a2b9-4ac4-8108-7f2953ea97b6")
HAYABUSA_EVENT_FIELDS = (
    "Timestamp",
    "datetime",
    "Computer",
    "Channel",
    "Provider",
    "EventID",
    "RecordID",
    "EvtxFile",
    "Details",
    "AllFieldInfo",
    "ExtraFieldInfo",
)


@lru_cache(maxsize=2)
def _template(name):
    # Identical copies of the proposed MISP/misp-objects templates.
    return json.loads(resources.files("misp_modules").joinpath("data", name, "definition.json").read_text())


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


def _rows(text, format_):
    automatic = format_ == "auto"
    if automatic:
        format_ = "json" if text.lstrip().startswith(("{", "[")) else "csv"
    if format_ == "json":
        try:
            value = _loads(text)
        except json.JSONDecodeError:
            if not automatic or text.lstrip().startswith("["):
                raise
            # Hayabusa's native JSON output is a stream of pretty-printed objects,
            # not necessarily an array or one object per physical line.
            decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)
            result, offset = [], 0
            whitespace = re.compile(r"\s*")
            while True:
                offset = whitespace.match(text, offset).end()
                if offset == len(text):
                    break
                if len(result) >= MAX_RESULTS:
                    raise ValueError("Export exceeds the 1000-result limit.")
                row, offset = decoder.raw_decode(text, offset)
                result.append(row)
            if len(result) == len([line for line in text.split("\n") if line.strip()]):
                return result, "jsonl"
            return result, "hayabusa-json"
        else:
            return value if isinstance(value, list) else [value], "json"
    result = []
    if format_ == "hayabusa-json":
        # Reuse automatic JSON-stream parsing while retaining this explicit contract.
        rows, actual = _rows(text, "auto")
        if actual == "csv":
            raise ValueError("hayabusa-json requires JSON objects, not CSV.")
        return rows, "hayabusa-json"
    if format_ == "jsonl":
        for line in text.split("\n"):
            if not line.strip():
                continue
            if len(result) >= MAX_RESULTS:
                raise ValueError("Export exceeds the 1000-result limit.")
            result.append(_loads(line))
        return result, "jsonl"
    reader = csv.DictReader(StringIO(text, newline=""), strict=True)
    headers = reader.fieldnames
    if not headers or any(not name for name in headers) or len(set(headers)) != len(headers):
        raise ValueError("CSV requires unique non-empty column headers.")
    if not {"RuleTitle", "Level"}.issubset(headers) and not {"timestamp_desc", "message", "Level"}.issubset(headers):
        raise ValueError("CSV requires Hayabusa timeline headers; use Chainsaw hunt --json or --jsonl.")
    for row in reader:
        if len(result) >= MAX_RESULTS:
            raise ValueError("Export exceeds the 1000-result limit.")
        if None in row or any(value is None for value in row.values()):
            raise ValueError("CSV row does not match its header column count.")
        result.append(row)
    return result, "csv"


def _bounded(row):
    if not isinstance(row, dict) or not row:
        raise ValueError("Each result must be a non-empty object.")
    stack = [(row, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ValueError("Result nesting exceeds 32 levels.")
        if isinstance(value, dict):
            for key in value:
                key.encode("utf-8")
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            value.encode("utf-8")
    if len(_json(row).encode()) > MAX_RESULT:
        raise ValueError("A normalized result exceeds the 256 KiB limit.")


def _time(value):
    # Hayabusa's default format has a space before the explicit UTC offset.
    value = re.sub(r" (?=[+-]\d{2}:\d{2}$)", "", value)
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)", value
    ) or value.endswith("-00:00"):
        raise ValueError("Time requires an explicit known offset and microsecond precision or less.")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()


def _tool(row):
    hayabusa = (
        "RuleTitle" in row
        and "Level" in row
        or (row.get("timestamp_desc") == "hayabusa" and "message" in row and "Level" in row)
    )
    chainsaw = (
        "name" in row
        and row.get("source") in ("sigma", "chainsaw")
        and row.get("kind") in ("individual", "aggregate", "cached")
    )
    if bool(hayabusa) == bool(chainsaw):
        raise ValueError("Result does not unambiguously match a supported Hayabusa timeline or Chainsaw hunt schema.")
    return "hayabusa" if hayabusa else "chainsaw"


class _Builder:
    def __init__(self, raw, filename, config):
        self.event = MISPEvent()
        self.warnings = Counter()
        self.events = 0
        self.config = config
        self.digest = hashlib.sha256(raw).hexdigest()
        self.source = self.object("file", _json(["source", self.digest, filename]))
        for relation, value in {"filename": filename, "sha256": self.digest, "size-in-bytes": len(raw)}.items():
            self.add(self.source, relation, value)
        self.add(self.source, "attachment", filename, data=BytesIO(raw))
        self.source.comment = "Original detection export; its hash does not describe the referenced EVTX files."

    def object(self, name, identity):
        custom = {"misp_objects_template_custom": _template(name)} if name != "file" else {}
        obj = MISPObject(name, strict=True, standalone=False, **custom)
        obj.uuid = str(uuid5(NAMESPACE, identity))
        self.event.add_object(obj)
        return obj

    def add(self, obj, relation, value, **kwargs):
        attribute = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
        attribute.uuid = str(uuid5(UUID(str(obj.uuid)), _json([relation, str(value)])))

    def link(self, source, target, relationship):
        ref = source.add_reference(target.uuid, relationship)
        ref.uuid = str(uuid5(UUID(str(source.uuid)), _json([str(target.uuid), relationship])))

    def text(self, value, field, required=False):
        if value is None or isinstance(value, str) and value.strip().lower() in ("", "-", "n/a"):
            if required:
                raise ValueError(f"Missing {field}.")
            return None
        if (
            isinstance(value, bool)
            or not isinstance(value, (str, int))
            or len(str(value)) > 4096
            or "\x00" in str(value)
        ):
            if required:
                raise ValueError(f"Invalid {field}.")
            self.warnings[f"Invalid {field}; retained in source result"] += 1
            return None
        return str(value)

    def fields(self, obj, data, mapping):
        for key, relation in mapping.items():
            value = self.text(data.get(key), key)
            if value is not None:
                self.add(obj, relation, value)

    def timestamp(self, obj, value, relation):
        text = self.text(value, relation)
        if text is None:
            return
        self.add(obj, "timestamp-raw", text)
        try:
            self.add(obj, relation, _time(text))
        except ValueError:
            self.warnings[f"Unmapped {relation}; exact timestamp retained"] += 1

    def counter(self, obj, relation, value, maximum):
        text = self.text(value, relation)
        if text is None:
            return
        if re.fullmatch(r"[0-9]{1,20}", text.strip()) and int(text) <= maximum:
            self.add(obj, relation, int(text))
        else:
            self.warnings[f"Invalid {relation}; retained in source result"] += 1

    def record(self, detection, index, context, raw):
        if self.events >= MAX_EVENTS:
            raise ValueError("Export exceeds the 5000-event-context limit.")
        self.events += 1
        obj = self.object("windows-event-log-record", _json([str(detection.uuid), "event", index]))
        self.add(obj, "event-index", index)
        self.add(obj, "raw-event", _json(raw))
        self.fields(
            obj,
            context,
            {
                "computer": "computer",
                "channel": "channel",
                "provider": "provider",
                "evtx": "source-evtx",
                "level": "event-level",
            },
        )
        for field, maximum in (("event-id", 65535), ("record-id", 2**64 - 1)):
            self.counter(obj, field, context.get(field), maximum)
        self.timestamp(obj, context.get("time"), "event-time")
        for field in ("provider", "evtx"):
            if not self.text(context.get(field), field):
                self.warnings[f"Source does not provide {field}; not inferred"] += 1
        # Catalogue direction: target information is based on source information.
        self.link(self.source, obj, "derived-from")
        self.link(obj, detection, "derived-from")
        self.link(detection, obj, "describes")

    def hayabusa(self, detection, row):
        self.fields(
            detection,
            row,
            {
                "RuleID": "rule-id",
                "RuleFile": "rule-file",
                "Level": "severity",
                "Status": "rule-status",
            },
        )
        self.add(detection, "detection-kind", "timeline")
        time = row.get("Timestamp", row.get("datetime"))
        self.timestamp(detection, time, "detection-time")
        context = {
            target: row.get(key)
            for key, target in {
                "Computer": "computer",
                "Channel": "channel",
                "Provider": "provider",
                "EventID": "event-id",
                "RecordID": "record-id",
                "EvtxFile": "evtx",
            }.items()
        }
        if not self.text(context["evtx"], "EvtxFile"):
            context["evtx"] = self.config.get("source_evtx")
        context["time"] = time
        event = {key: row[key] for key in HAYABUSA_EVENT_FIELDS if key in row}
        if event:
            self.record(detection, 1, context, event)
        else:
            self.warnings["Timeline entry has no event context; detection retained"] += 1

    def chainsaw(self, detection, row):
        self.fields(
            detection, row, {"id": "rule-id", "level": "severity", "status": "rule-status", "source": "rule-source"}
        )
        self.add(detection, "detection-kind", row["kind"])
        self.timestamp(detection, row.get("timestamp"), "detection-time")
        if row["kind"] == "aggregate":
            documents = row.get("documents")
            if not isinstance(documents, list) or not documents:
                raise ValueError("Chainsaw aggregate must contain a non-empty documents array.")
        else:
            documents = [row.get("document")]
        if len(documents) > MAX_EVENTS - self.events:
            raise ValueError("Export exceeds the 5000-event-context limit.")
        for index, document in enumerate(documents, 1):
            if not isinstance(document, dict):
                raise ValueError("Chainsaw document must be an object.")
            if document.get("kind") != "evtx":
                self.warnings["Non-EVTX Chainsaw document retained without Windows event mapping"] += 1
                continue
            data = document.get("data")
            event = data.get("Event") if isinstance(data, dict) else None
            system = event.get("System") if isinstance(event, dict) else None
            if not isinstance(system, dict):
                system = {}
                self.warnings["EVTX document has no Event.System; reference/raw context retained"] += 1
            provider = system.get("Provider_attributes")
            created = system.get("TimeCreated_attributes")
            context = {
                "computer": system.get("Computer"),
                "channel": system.get("Channel"),
                "provider": provider.get("Name") if isinstance(provider, dict) else None,
                "time": created.get("SystemTime") if isinstance(created, dict) else None,
                "event-id": system.get("EventID"),
                "record-id": system.get("EventRecordID"),
                "level": system.get("Level"),
                "evtx": document.get("path") or self.config.get("source_evtx"),
            }
            self.record(detection, index, context, document)

    def result(self, row, index, tool, format_):
        if format_ == "hayabusa-json" and tool != "hayabusa":
            raise ValueError("Pretty-printed object streams require the Hayabusa schema; use Chainsaw JSON/JSONL.")
        if tool == "chainsaw" and format_ == "csv":
            raise ValueError(
                "Use Chainsaw hunt --json or --jsonl; grouped CSV cannot preserve complete rule/event context."
            )
        title = row.get("RuleTitle", row.get("message")) if tool == "hayabusa" else row.get("name")
        title = self.text(title, "rule title", required=True)
        detection = self.object("windows-event-log-detection", _json([str(self.source.uuid), index, tool, self.config]))
        for relation, value in {
            "tool": tool,
            "rule-title": title,
            "review-status": "unreviewed",
            "result-index": index,
            "source-sha256": self.digest,
            "source-format": format_,
            "raw-result": _json(row),
        }.items():
            self.add(detection, relation, value)
        if self.config.get("tool_version"):
            self.add(detection, "tool-version", self.config["tool_version"])
        self.link(self.source, detection, "derived-from")
        if tool == "hayabusa":
            self.hayabusa(detection, row)
        else:
            self.chainsaw(detection, row)
        rule_id = row.get("RuleID") if tool == "hayabusa" else row.get("id")
        if not self.text(rule_id, "rule ID"):
            self.warnings["Source does not provide rule ID; not fabricated"] += 1


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
        tool = config.get("tool", "auto")
        format_ = config.get("format", "auto")
        if tool in (None, ""):
            tool = "auto"
        if format_ in (None, ""):
            format_ = "auto"
        if tool not in ("auto", "hayabusa", "chainsaw") or format_ not in (
            "auto",
            "json",
            "jsonl",
            "csv",
            "hayabusa-json",
        ):
            raise ValueError("tool must be auto/hayabusa/chainsaw; format must be auto/json/jsonl/csv/hayabusa-json.")
        context = {}
        for key in ("tool_version", "source_evtx"):
            value = config.get(key)
            if value not in (None, ""):
                if (
                    not isinstance(value, str)
                    or not value.strip()
                    or len(value) > 4096
                    or any(ord(c) < 32 for c in value)
                ):
                    raise ValueError(f"{key} must be text without control characters (maximum 4096 characters).")
                context[key] = value
        encoded = request.get("data")
        if not isinstance(encoded, str) or not encoded or len(encoded) > 4 * ((MAX_INPUT + 2) // 3):
            raise ValueError("data must contain a base64-encoded export of at most 20 MiB.")
        raw = base64.b64decode(encoded, validate=True)
        if not raw or len(raw) > MAX_INPUT:
            raise ValueError("Export must be non-empty and at most 20 MiB.")
        rows, actual_format = _rows(raw.decode("utf-8-sig"), format_)
        if not rows or len(rows) > MAX_RESULTS:
            raise ValueError("Export must contain 1–1000 detection results.")
        filename = request.get("filename")
        if filename in (None, ""):
            filename = "evtx-findings." + actual_format
        if not isinstance(filename, str) or len(filename) > 4096 or any(ord(c) < 32 for c in filename):
            raise ValueError("filename must be text without control characters.")
        filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
        if not filename.strip() or filename in (".", ".."):
            raise ValueError("filename must have a non-empty basename.")
        builder = _Builder(raw, filename, context)
        tools = Counter()
        for index, row in enumerate(rows, 1):
            _bounded(row)
            actual_tool = _tool(row)
            if tool != "auto" and tool != actual_tool:
                raise ValueError("Result schema does not match the explicitly selected tool.")
            tools[actual_tool] += 1
            builder.result(row, index, actual_tool, actual_format)
        return {
            "results": {"Object": json.loads(builder.event.to_json())["Object"]},
            "summary": {
                "detections": len(rows),
                "format": actual_format,
                "event_contexts": builder.events,
                "tools": dict(tools),
                "source_sha256": builder.digest,
            },
            "warnings": [f"{message}: {count}" for message, count in sorted(builder.warnings.items())],
        }
    except (
        ValueError,
        TypeError,
        UnicodeError,
        binascii.Error,
        csv.Error,
        PyMISPError,
        RecursionError,
        OverflowError,
    ) as error:
        return {"error": f"Unable to import EVTX findings: {error}"}


def introspection():
    return dict(
        mispattributes,
        userConfig={
            "tool": {"type": "String", "message": "auto (default), hayabusa or chainsaw"},
            "format": {"type": "String", "message": "auto (default), json, jsonl, csv or hayabusa-json"},
            "tool_version": {"type": "String", "message": "Optional version of the producing tool"},
            "source_evtx": {"type": "String", "message": "Optional source EVTX reference when absent from the export"},
        },
    )


def version():
    return dict(moduleinfo, config=moduleconfig)
