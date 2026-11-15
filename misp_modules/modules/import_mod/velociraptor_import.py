"""Import offline Velociraptor result rows without executing VQL or fetching files."""

import base64
import binascii
import csv
import hashlib
import ipaddress
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

mispattributes = {"inputSource": ["file"], "output": ["MISP objects"], "format": "misp_standard"}
moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Velociraptor Results Import",
    "description": "Import Velociraptor JSON, JSONL or CSV results with linked forensic observations and provenance.",
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Preserves the original export and every result row, including unmapped fields. Maps Windows.System.Pslist,"
        " Windows.System.Services, Windows.Network.NetstatEnriched/Netstat and Windows.Search.FileFinder into process,"
        " file, network-socket and windows-service objects. Other artifacts are retained as provenance rows with"
        " warnings. All attributes have to_ids disabled. No credentials, network access, VQL execution or additional"
        " dependencies are required. Includes the velociraptor-result template for older PyMISP. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/velociraptor_import.md)."
    ),
    "references": [
        "https://docs.velociraptor.app/",
        "https://github.com/Velocidex/velociraptor/tree/master/artifacts/definitions",
    ],
    "input": "Base64-encoded UTF-8 JSON, JSONL or CSV in data; artifact/context in config or row metadata.",
    "output": "MISP source file, velociraptor-result and derived observation objects in misp_standard format.",
}

MAX_INPUT = 20 * 1024 * 1024
MAX_ROWS = 1000
MAX_ROW = 64 * 1024
MAX_DEPTH = 32
NAMESPACE = UUID("465f2b18-153b-4fb5-b09a-62f248977eec")
CONTEXT = {
    "artifact": ("_Source", "Artifact", "artifact"),
    "server_id": ("ServerId", "server_id"),
    "client_id": ("ClientId", "_ClientId", "client_id"),
    "hostname": ("Fqdn", "Hostname", "hostname"),
    "flow_id": ("FlowId", "_FlowId", "flow_id"),
    "hunt_id": ("HuntId", "_HuntId", "hunt_id"),
}
PROFILES = {
    "Windows.System.Pslist": "process",
    "Windows.System.Services": "service",
    "Windows.Network.NetstatEnriched": "socket",
    "Windows.Network.NetstatEnriched/Netstat": "socket",
    "Windows.Search.FileFinder": "file",
}


@lru_cache(maxsize=1)
def _template():
    # Keep identical to MISP/misp-objects/objects/velociraptor-result/definition.json.
    return json.loads(
        resources.files("misp_modules").joinpath("data", "velociraptor-result", "definition.json").read_text()
    )


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


def _loads(value):
    return json.loads(value, object_pairs_hook=_pairs, parse_constant=_constant)


def _rows(text, format_):
    auto_detect = format_ == "auto"
    if auto_detect:
        format_ = "json" if text.lstrip().startswith(("{", "[")) else "csv"
    if format_ == "json":
        try:
            data = _loads(text)
        except json.JSONDecodeError:
            if not auto_detect or text.lstrip().startswith("["):
                raise
            format_ = "jsonl"
        else:
            return (data if isinstance(data, list) else [data]), format_
    if format_ == "jsonl":
        result = []
        for line in text.splitlines():
            if line.strip():
                if len(result) >= MAX_ROWS:
                    raise ValueError("Export exceeds the 1000-row limit; select fewer results.")
                result.append(_loads(line))
        return result, format_
    reader = csv.DictReader(StringIO(text, newline=""), strict=True)
    header = reader.fieldnames
    if not header or any(not field for field in header) or len(set(header)) != len(header):
        raise ValueError("CSV requires unique non-empty column headers.")
    result = []
    for row in reader:
        if len(result) >= MAX_ROWS:
            raise ValueError("Export exceeds the 1000-row limit; select fewer results.")
        if None in row or any(value is None for value in row.values()):
            raise ValueError("CSV row does not match its header column count.")
        result.append(row)
    return result, "csv"


def _bounded(row):
    if not isinstance(row, dict) or not row:
        raise ValueError("Each result row must be a non-empty JSON object.")
    stack = [(row, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ValueError("Result row nesting exceeds 32 levels.")
        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            value.encode("utf-8")  # Reject unpaired surrogate escapes.
    if len(_json(row).encode()) > MAX_ROW:
        raise ValueError("A normalized result row exceeds the 64 KiB limit.")


def _context_text(value, field):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise ValueError(f"{field} must be non-empty text without control characters (maximum 4096 characters).")
    return value


def _context(row, config):
    context = {}
    for field, aliases in CONTEXT.items():
        values = [_context_text(row[key], key) for key in aliases if row.get(key) not in (None, "")]
        if len(set(values)) > 1:
            raise ValueError(f"Conflicting row metadata for {field}.")
        value = values[0] if values else config.get(field)
        if value:
            context[field] = value
    if not context.get("artifact"):
        raise ValueError("Specify config.artifact or an artifact/_Source field on every row.")
    if config.get("collected_at"):
        context["collected_at"] = config["collected_at"]
    return context


def _time(value):
    # Do not guess numeric epoch units, timezone, or truncate nanosecond evidence.
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)", value
    ):
        raise ValueError("Expected a complete timezone-qualified time at microsecond precision or less.")
    if value.endswith("-00:00"):
        raise ValueError("A -00:00 offset denotes an unknown local offset.")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()


class _Builder:
    def __init__(self, raw, filename, format_):
        self.event = MISPEvent()
        self.warnings = Counter()
        self.digest = hashlib.sha256(raw).hexdigest()
        self.format = format_
        self.source = self.object("file", f"source:{self.digest}:{filename}")
        self.add(self.source, "filename", filename)
        self.add(self.source, "sha256", self.digest)
        self.add(self.source, "size-in-bytes", len(raw))
        self.add(self.source, "attachment", filename, data=BytesIO(raw))
        self.source.comment = "Original Velociraptor result export; attachment bytes are unchanged."

    def object(self, name, identity):
        options = {"misp_objects_template_custom": _template()} if name == "velociraptor-result" else {}
        obj = MISPObject(name, strict=True, standalone=False, **options)
        obj.uuid = str(uuid5(NAMESPACE, identity))
        self.event.add_object(obj)
        return obj

    def add(self, obj, relation, value, **kwargs):
        attribute = obj.add_attribute(relation, value=value, to_ids=False, **kwargs)
        attribute.uuid = str(uuid5(UUID(str(obj.uuid)), relation + ":" + str(value)))
        if attribute.type in {"text", "counter", "size-in-bytes", "datetime"} or obj.name == "velociraptor-result":
            attribute.disable_correlation = True

    def warn(self, message):
        self.warnings[message] += 1

    def scalar(self, row, key):
        value = row.get(key)
        if value is None or value == "":
            return None
        if isinstance(value, (dict, list, bool)) or not isinstance(value, (str, int)):
            self.warn(f"Invalid {key}; preserved in result row")
            return None
        return str(value)

    def fields(self, obj, row, mapping):
        for key, relation in mapping.items():
            value = self.scalar(row, key)
            if value is not None:
                self.add(obj, relation, value)

    def times(self, obj, row, mapping):
        for key, relation in mapping.items():
            if row.get(key) not in (None, ""):
                try:
                    self.add(obj, relation, _time(row[key]))
                except ValueError:
                    self.warn(f"Unmapped {key} timestamp; preserved in result row")

    def hashes(self, value):
        fields = {}
        if value in (None, ""):
            return fields
        if isinstance(value, str):
            try:
                value = _loads(value)  # Native CSV serializes nested cells as JSON.
            except (ValueError, RecursionError):
                value = None
        if not isinstance(value, dict):
            self.warn("Invalid hash object; preserved in result row")
            return fields
        for key, length in (("MD5", 32), ("SHA1", 40), ("SHA256", 64)):
            digest = value.get(key)
            if digest in (None, ""):
                continue
            if isinstance(digest, str) and re.fullmatch(rf"[a-fA-F0-9]{{{length}}}", digest):
                fields[key.lower()] = digest.lower()
            else:
                self.warn(f"Invalid {key}; preserved in result row")
        return fields

    def link(self, obj, target, relationship, comment=None):
        reference = obj.add_reference(target.uuid, relationship, comment)
        reference.uuid = str(uuid5(UUID(str(obj.uuid)), _json([str(target.uuid), relationship, comment])))

    def derived(self, record, name, role):
        obj = self.object(name, str(record.uuid) + ":" + role)
        self.link(record, obj, "derived-from")
        self.link(record, obj, "describes")
        return obj

    def file(self, record, row, path_key, hash_key="Hash"):
        path = self.scalar(row, path_key)
        hashes = self.hashes(row.get(hash_key))
        if path is None and not hashes:
            return None
        obj = self.derived(record, "file", path_key)
        if path is not None:
            self.add(obj, "fullpath", path)
            basename = path.replace("\\", "/").rsplit("/", 1)[-1]
            if basename:
                self.add(obj, "filename", basename)
        for relation, value in hashes.items():
            self.add(obj, relation, value)
        return obj

    def process(self, record, row, image="Exe"):
        # These are row-local observations. PID alone never joins independent rows/collections.
        mapping = {
            "Pid": "pid",
            "Ppid": "parent-pid",
            "Name": "name",
            "CommandLine": "command-line",
            "Username": "user-process",
            image: "image",
        }
        values = {relation: self.scalar(row, key) for key, relation in mapping.items()}
        for relation in ("pid", "parent-pid"):
            value = values.get(relation)
            if value is not None and not re.fullmatch(r"[0-9]+", value):
                self.warn(f"Invalid {relation}; preserved in result row")
                values[relation] = None
        if not any(values.get(relation) is not None for relation in ("pid", "name", "image", "command-line")):
            return None
        obj = self.derived(record, "process", "process")
        for relation, value in values.items():
            if value is not None:
                self.add(obj, relation, value)
        self.times(obj, row, {"CreateTime": "creation-time"})
        binary = self.file(record, row, image)
        if binary is not None:
            self.link(obj, binary, "executes")
        return obj

    def socket(self, record, row):
        fields = {}
        for key, relation in (("Laddr", "ip-src"), ("Raddr", "ip-dst")):
            if row.get(key) not in (None, ""):
                try:
                    value = row[key]
                    if not isinstance(value, str) or "%" in value:
                        raise ValueError
                    fields[relation] = str(ipaddress.ip_address(value))
                except ValueError:
                    self.warn(f"Invalid {key}; preserved in result row")
        for key, relation in (("Lport", "src-port"), ("Rport", "dst-port")):
            value = self.scalar(row, key)
            if value is not None:
                if re.fullmatch(r"[0-9]{1,5}", value) and 0 <= int(value) <= 65535:
                    fields[relation] = int(value)
                else:
                    self.warn(f"Invalid {key}; preserved in result row")
        process = self.process(record, row, image="Path")
        if fields:
            obj = self.derived(record, "network-socket", "socket")
            for relation, value in fields.items():
                self.add(obj, relation, value)
            self.fields(obj, row, {"Family": "address-family", "Type": "protocol", "Status": "state"})
            if process is not None:
                self.link(process, obj, "related-to", "Process and socket reported in the same Velociraptor row.")
        # Timestamp in this artifact is not asserted to be first-packet-seen.

    def service(self, record, row):
        name = self.scalar(row, "Name")
        if name is None:
            return
        if len(name.encode()) > 256 or "/" in name or "\\" in name:
            self.warn("Invalid service Name; preserved in result row")
            return
        obj = self.derived(record, "windows-service", "service")
        self.add(obj, "name", name)
        display = self.scalar(row, "DisplayName")
        if display is not None:
            if len(display.encode()) <= 256 and "/" not in display and "\\" not in display:
                self.add(obj, "display", display)
            else:
                self.warn("Invalid DisplayName; preserved in result row")
        self.fields(obj, row, {"PathName": "image-path", "StartMode": "start", "ServiceType": "type"})
        binary = self.file(record, row, "AbsoluteExePath", "HashServiceExe")
        if binary is not None:
            self.link(obj, binary, "related-to", "Service executable reported by Velociraptor.")
        # Do not split PathName into an executable: it may be an ambiguous unquoted command line.

    def row(self, row, number, config):
        context = _context(row, config)
        identity = _json([str(self.source.uuid), number, context])
        record = self.object("velociraptor-result", identity)
        for key, value in context.items():
            self.add(record, key.replace("_", "-"), value)
        for key, value in {
            "row-number": number,
            "row": _json(row),
            "source-sha256": self.digest,
            "source-format": self.format,
            "parser-version": "velociraptor_import/1.0",
        }.items():
            self.add(record, key, value)
        self.link(self.source, record, "derived-from")
        profile = PROFILES.get(context["artifact"])
        before = len(self.event.objects)
        if profile == "process":
            self.process(record, row)
        elif profile == "socket":
            self.socket(record, row)
        elif profile == "service":
            self.service(record, row)
        elif profile == "file":
            is_dir = row.get("IsDir")
            if is_dir in (False, "false", "False", "N", "0", 0, None, ""):
                obj = self.file(record, row, "OSPath")
                if obj is not None:
                    size = self.scalar(row, "Size")
                    if size is not None:
                        if size.isascii() and size.isdecimal():
                            self.add(obj, "size-in-bytes", size)
                        else:
                            self.warn("Invalid Size; preserved in result row")
                    self.times(
                        obj, row, {"BTime": "creation-time", "MTime": "modification-time", "ATime": "access-time"}
                    )
                    # CTime is metadata-change time, not creation-time.
        if profile is None:
            self.warn("Unsupported artifact; preserved as result row without mapping")
        elif len(self.event.objects) == before:
            self.warn("Row has no mappable observation; preserved as result row")


def handler(q=False):
    if q is False:
        return False
    try:
        request = _loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an import request object.")
        encoded = request.get("data")
        if not isinstance(encoded, str) or not encoded:
            raise ValueError("data must contain a base64-encoded UTF-8 export.")
        if len(encoded) > 4 * ((MAX_INPUT + 2) // 3):
            raise ValueError("Export exceeds the 20 MiB limit.")
        raw = base64.b64decode(encoded, validate=True)
        if not raw or len(raw) > MAX_INPUT:
            raise ValueError("Export must be non-empty and at most 20 MiB.")
        text = raw.decode("utf-8-sig")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        config = dict(config)
        for field in (*CONTEXT, "collected_at"):
            if config.get(field) not in (None, ""):
                config[field] = _context_text(config[field], field)
        if config.get("collected_at"):
            config["collected_at"] = _time(config["collected_at"])
        format_ = config.get("format")
        if format_ in (None, ""):
            format_ = "auto"
        if format_ not in ("auto", "json", "jsonl", "csv"):
            raise ValueError("format must be auto, json, jsonl or csv.")
        rows, format_ = _rows(text, format_)
        if not rows or len(rows) > MAX_ROWS:
            raise ValueError("Export must contain 1–1000 result rows.")
        filename = request.get("filename")
        if filename in (None, ""):
            filename = "velociraptor-results." + format_
        filename = _context_text(filename, "filename").replace("\\", "/").rsplit("/", 1)[-1]
        if not filename or filename in (".", ".."):
            raise ValueError("filename must have a non-empty basename.")
        builder = _Builder(raw, filename, format_)
        for number, row in enumerate(rows, 1):
            _bounded(row)
            builder.row(row, number, config)
        return {
            "results": {"Object": json.loads(builder.event.to_json())["Object"]},
            "summary": {"rows": len(rows), "objects": len(builder.event.objects), "source_sha256": builder.digest},
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
        return {"error": f"Unable to import Velociraptor results: {error}"}


def introspection():
    return dict(
        mispattributes,
        userConfig={
            "format": {"type": "String", "message": "auto (default), json, jsonl or csv"},
            "artifact": {"type": "String", "message": "Default artifact/source, e.g. Windows.System.Pslist"},
            **{
                field: {"type": "String", "message": "Default " + field.replace("_", " ")}
                for field in CONTEXT
                if field != "artifact"
            },
            "collected_at": {"type": "String", "message": "Optional explicit collection time, including timezone"},
        },
    )


def version():
    return dict(moduleinfo, config=moduleconfig)
