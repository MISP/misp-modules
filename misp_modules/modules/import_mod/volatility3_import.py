"""Import native Volatility 3 JSON results without opening a memory image."""

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
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
    "name": "Volatility 3 Results Import",
    "description": (
        "Import Volatility 3 process, network, suspicious-memory and YARA results with memory-image provenance."
    ),
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Accepts native JSON/JSONL from Windows pslist, psscan, pstree, cmdline, netscan, netstat, malfind and"
        " vadyarascan, plus layer-wide yarascan. Preserves exact exports, image hashes, plugin/framework versions,"
        " offsets, process creation times, renderer hierarchy and unmapped fields. Reuses process and network-socket"
        " objects and includes a volatility3-result template. Suspicious memory and YARA matches remain unreviewed."
        " No image access, Volatility execution, network calls or new dependencies. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/volatility3_import.md)."
    ),
    "references": ["https://github.com/volatilityfoundation/volatility3", "https://volatility3.readthedocs.io/"],
    "input": (
        "Base64-encoded native JSON/JSONL in data, with plugin and optional image/version context in config or"
        " metadata."
    ),
    "output": "Source export, optional memory-image file, volatility3-result, process and network-socket objects.",
}
MAX_INPUT = 20 * 1024 * 1024
MAX_ROWS = 1000
MAX_ROW = 128 * 1024
MAX_DEPTH = 32
NAMESPACE = UUID("fdb3c1e2-4245-4184-a782-63a762654458")
CONTEXT = ("plugin", "plugin_version", "volatility_version", "image_sha256", "image_name", "layer_name")
# Explicit plugin identity is required: columns alone cannot distinguish pslist/psscan.
PLUGINS = {
    "windows.pslist": ("PsList", "process", {"PID", "PPID", "ImageFileName", "CreateTime"}),
    "windows.psscan": ("PsScan", "process", {"PID", "PPID", "ImageFileName", "CreateTime"}),
    "windows.pstree": ("PsTree", "process-tree", {"PID", "PPID", "ImageFileName", "CreateTime"}),
    "windows.cmdline": ("CmdLine", "command-line", {"PID", "Process", "Args"}),
    "windows.netscan": ("NetScan", "network", {"Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort"}),
    "windows.netstat": ("NetStat", "network", {"Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort"}),
    "windows.malfind": ("Malfind", "suspicious-memory", {"PID", "Process", "Start VPN", "End VPN", "Protection"}),
    "windows.malware.malfind": (
        "Malfind",
        "suspicious-memory",
        {"PID", "Process", "Start VPN", "End VPN", "Protection"},
    ),
    "windows.vadyarascan": ("VadYaraScan", "yara-match", {"PID", "Offset", "Rule"}),
    "yarascan": ("YaraScan", "yara-match", {"Offset", "Rule"}),
}


@lru_cache(maxsize=1)
def _template():
    return json.loads(
        resources.files("misp_modules").joinpath("data", "volatility3-result", "definition.json").read_text()
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


def _loads(text):
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)


def _text(value, field):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not str(value).strip() or "\x00" in str(value):
        raise ValueError(f"{field} must be non-empty text or an integer.")
    return str(value)


def _plugin(value):
    value = _text(value, "plugin")
    for short, (class_name, kind, columns) in PLUGINS.items():
        canonical = short + "." + class_name
        if value.lower() in (short, canonical.lower()):
            return canonical, kind, columns
    raise ValueError("Unsupported plugin; use an explicitly supported fully qualified Volatility 3 plugin.")


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
            format_ = "jsonl"
        else:
            metadata = {}
            if isinstance(value, dict) and "results" in value:
                metadata = value.get("metadata", {})
                if not isinstance(metadata, dict):
                    raise ValueError("metadata must be an object.")
                value = value["results"]
            return value if isinstance(value, list) else [value], metadata, "json"
    rows = []
    for line in text.split("\n"):
        if line.strip():
            if len(rows) >= MAX_ROWS:
                raise ValueError("Export exceeds 1000 result rows.")
            rows.append(_loads(line))
    return rows, {}, "jsonl"


def _bounded(row):
    stack = [(row, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ValueError("Result column nesting exceeds 32 levels.")
        if isinstance(value, dict):
            for key in value:
                key.encode("utf-8")
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            value.encode("utf-8")
    if len(_json(row).encode()) > MAX_ROW:
        raise ValueError("A normalized result row exceeds 128 KiB.")


def _flatten(rows):
    if not isinstance(rows, list) or not rows:
        raise ValueError("Export must contain at least one result row.")
    if len(rows) > MAX_ROWS:
        raise ValueError("Export exceeds 1000 result rows, including children.")
    stack = [(row, (index,), None) for index, row in reversed(list(enumerate(rows, 1)))]
    result = []
    while stack:
        row, path, parent = stack.pop()
        if len(result) >= MAX_ROWS:
            raise ValueError("Export exceeds 1000 result rows, including children.")
        if len(path) > MAX_DEPTH:
            raise ValueError("Renderer hierarchy exceeds 32 levels.")
        if not isinstance(row, dict):
            raise ValueError("Every result row must be an object.")
        children = row.get("__children", [])
        if not isinstance(children, list):
            raise ValueError("__children must be a list of result objects.")
        columns = {key: value for key, value in row.items() if key != "__children"}
        if not columns:
            raise ValueError("Result row has no columns.")
        _bounded(columns)
        result.append((columns, ".".join(map(str, path)), parent))
        if len(children) > MAX_ROWS - len(result):
            raise ValueError("Export exceeds 1000 result rows, including children.")
        stack.extend(
            (child, (*path, index), len(result) - 1) for index, child in reversed(list(enumerate(children, 1)))
        )
    return result


def _time(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T"
            r" ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
            value,
        )
        or value.endswith("-00:00")
    ):
        raise ValueError("Time needs a known offset and at most microsecond precision.")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except OverflowError:
        raise ValueError("Time is outside the supported UTC range.") from None


def _integer(value, maximum):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r"[0-9]{1,20}", str(value)):
        raise ValueError("Expected a non-negative integer.")
    integer = int(value)
    if integer > maximum:
        raise ValueError("Integer outside the supported range.")
    return integer


class _Builder:
    def __init__(self, raw, filename, context, kind, format_):
        self.event, self.warnings = MISPEvent(), Counter()
        self.context, self.kind, self.format = context, kind, format_
        self.digest = hashlib.sha256(raw).hexdigest()
        self.source = self.object("file", ["export", self.digest, filename])
        self.source.comment = "Exact Volatility result export; its SHA-256 does not identify the memory image."
        for relation, value in {"filename": filename, "sha256": self.digest, "size-in-bytes": len(raw)}.items():
            self.add(self.source, relation, value)
        self.add(self.source, "attachment", filename, data=BytesIO(raw))
        if context.get("image_sha256") or context.get("image_name"):
            image = self.object(
                "file", ["image", context.get("image_sha256") or self.digest, context.get("image_name")]
            )
            image.comment = "Producer-supplied memory image reference; no image was opened or hashed by this importer."
            if context.get("image_sha256"):
                self.add(image, "sha256", context["image_sha256"])
            if context.get("image_name"):
                name = context["image_name"].replace("\\", "/").rsplit("/", 1)[-1]
                if name.strip():
                    self.add(image, "filename", name)
            self.link(image, self.source, "derived-from")
        for field in ("image_sha256", "volatility_version", "plugin_version"):
            if not context.get(field):
                self.warnings[f"Source does not provide {field}; not inferred from result bytes or columns"] += 1

    def object(self, name, identity):
        custom = {"misp_objects_template_custom": _template()} if name == "volatility3-result" else {}
        obj = MISPObject(name, strict=True, standalone=False, **custom)
        obj.uuid = str(uuid5(NAMESPACE, _json(identity)))
        self.event.add_object(obj)
        return obj

    def add(self, obj, relation, value, **kwargs):
        attribute = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
        attribute.uuid = str(uuid5(UUID(str(obj.uuid)), _json([relation, str(value)])))

    def link(self, source, target, relationship):
        reference = source.add_reference(target.uuid, relationship)
        reference.uuid = str(uuid5(UUID(str(source.uuid)), _json([str(target.uuid), relationship])))

    def text(self, value, field):
        if value is None or value in ("", "N/A", "-"):
            return None
        try:
            return _text(value, field)
        except ValueError:
            self.warnings[f"Invalid {field}; retained in raw-result"] += 1
            return None

    def fields(self, obj, row, mapping):
        for column, relation in mapping.items():
            value = self.text(row.get(column), column)
            if value is not None:
                self.add(obj, relation, value)

    def number(self, value, name, maximum):
        if value is None or value in ("", "N/A", "-"):
            return None
        try:
            return _integer(value, maximum)
        except ValueError:
            self.warnings[f"Invalid {name}; retained in raw-result"] += 1
            return None

    def timestamp(self, result, value, relation):
        if value is None or value == "":
            return None
        self.add(result, relation + "-raw", str(value) if isinstance(value, (str, int)) else _json(value))
        try:
            parsed = _time(value)
        except ValueError:
            self.warnings[f"Unnormalized {relation}; exact source value retained"] += 1
            return None
        self.add(result, relation, parsed.isoformat())
        return parsed

    def addresses(self, result, row):
        for column, relation in {
            "Offset": "offset",
            "Offset(V)": "offset-virtual",
            "Offset(P)": "offset-physical",
            "Start VPN": "memory-start",
            "End VPN": "memory-end",
        }.items():
            value = row.get(column)
            if value is None or value in ("", "N/A", "-"):
                continue
            try:
                if isinstance(value, str) and re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", value):
                    address = int(value, 16)
                else:
                    address = _integer(value, 2**64 - 1)
            except ValueError:
                self.warnings[f"Invalid {column}; retained in raw-result"] += 1
                continue
            self.add(result, relation, hex(address))

    def process(self, result, row, created):
        pid = self.number(row.get("PID"), "PID", 2**32 - 1)
        if pid is None:
            self.warnings["No valid PID; process observation not constructed"] += 1
            return None, None
        obj = self.object("process", [str(result.uuid), "process"])
        self.add(obj, "pid", str(pid))
        ppid = self.number(row.get("PPID"), "PPID", 2**32 - 1)
        if ppid is not None:
            self.add(obj, "parent-pid", str(ppid))
        name_column = "ImageFileName" if "ImageFileName" in row else "Process" if "Process" in row else "Owner"
        self.fields(obj, row, {name_column: "name"})
        if self.kind == "command-line":
            self.fields(obj, row, {"Args": "command-line"})
        elif self.kind == "process-tree":
            self.fields(obj, row, {"Cmd": "command-line", "Path": "image"})
        if created is not None:
            self.add(obj, "creation-time", created.isoformat())
        self.link(result, obj, "derived-from")
        self.link(result, obj, "describes")
        return obj, (pid, ppid, created)

    def network(self, result, row):
        values, versions = {}, set()
        for column, relation in (("LocalAddr", "ip-src"), ("ForeignAddr", "ip-dst")):
            value = row.get(column)
            if value is None or value in ("", "*", "N/A", "-"):
                continue
            try:
                address = ipaddress.ip_address(value) if isinstance(value, str) else None
                if address is None:
                    raise ValueError()
                values[relation] = str(address)
                versions.add(address.version)
            except ValueError:
                self.warnings[f"Invalid {column}; retained in raw-result"] += 1
        for column, relation in (("LocalPort", "src-port"), ("ForeignPort", "dst-port")):
            value = self.number(row.get(column), column, 65535)
            if value is not None:
                values[relation] = value
        if not values:
            self.warnings["No valid network endpoints; socket observation not constructed"] += 1
            return
        obj = self.object("network-socket", [str(result.uuid), "network"])
        for relation, value in values.items():
            self.add(obj, relation, value)
        proto = row.get("Proto")
        if isinstance(proto, str) and re.fullmatch(r"(?:TCP|UDP)v[46]", proto):
            self.add(obj, "protocol", proto[:3].lower())
            self.add(obj, "socket-type", "SOCK_STREAM" if proto.startswith("TCP") else "SOCK_DGRAM")
            versions.add(int(proto[-1]))
        else:
            self.warnings["Unknown Proto; transport/family not inferred"] += 1
        if len(versions) == 1:
            self.add(obj, "address-family", "AF_INET6" if 6 in versions else "AF_INET")
        elif len(versions) > 1:
            self.warnings["Conflicting network address families; family not normalized"] += 1
        self.fields(obj, row, {"State": "state"})
        self.link(result, obj, "derived-from")
        self.link(result, obj, "describes")

    def result(self, row, path, index):
        result = self.object("volatility3-result", [str(self.source.uuid), self.context, path])
        for relation, value in {
            "result-kind": self.kind,
            "review-status": "unreviewed",
            "result-index": index,
            "row-path": path,
            "source-sha256": self.digest,
            "source-format": self.format,
            "raw-result": _json(row),
        }.items():
            self.add(result, relation, value)
        for field, value in self.context.items():
            self.add(result, field.replace("_", "-"), value)
        self.fields(
            result,
            row,
            {
                "PID": "process-id",
                "PPID": "parent-process-id",
                "Protection": "memory-protection",
                "Tag": "vad-tag",
                "Rule": "rule-name",
                "Component": "yara-component",
                "Value": "match-data",
            },
        )
        name_column = "ImageFileName" if "ImageFileName" in row else "Process" if "Process" in row else "Owner"
        self.fields(result, row, {name_column: "process-name"})
        self.addresses(result, row)
        created = self.timestamp(result, row.get("CreateTime"), "process-created")
        self.timestamp(result, row.get("ExitTime"), "process-exited")
        self.timestamp(result, row.get("Created"), "network-created")
        self.link(self.source, result, "derived-from")
        process, identity = (None, None)
        if self.kind != "yara-match" or self.context["plugin"].startswith("windows."):
            process, identity = self.process(result, row, created)
        if self.kind == "network":
            self.network(result, row)
        return result, process, identity


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
        format_ = config.get("format", "auto")
        if format_ in (None, ""):
            format_ = "auto"
        if format_ not in ("auto", "json", "jsonl"):
            raise ValueError("format must be auto, json or jsonl.")
        encoded = request.get("data")
        if not isinstance(encoded, str) or not encoded or len(encoded) > 4 * ((MAX_INPUT + 2) // 3):
            raise ValueError("data must be a base64-encoded export of at most 20 MiB.")
        raw = base64.b64decode(encoded, validate=True)
        if not raw or len(raw) > MAX_INPUT:
            raise ValueError("Export must be non-empty and at most 20 MiB.")
        rows, metadata, format_ = _read(raw.decode("utf-8-sig"), format_)
        context = {}
        for field in CONTEXT:
            values = [
                _text(container[field], field)
                for container in (metadata, config)
                if container.get(field) not in (None, "")
            ]
            if field == "plugin":
                values = [_plugin(value)[0] for value in values]
            elif field == "image_sha256":
                values = [value.lower() for value in values]
                if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in values):
                    raise ValueError("image_sha256 must contain exactly 64 hexadecimal digits.")
            if values:
                if len(set(values)) != 1:
                    raise ValueError("Conflicting metadata/config " + field)
                if len(values[0]) > 4096:
                    raise ValueError(field + " exceeds 4096 characters.")
                context[field] = values[0]
        if context.get("image_name"):
            basename = context["image_name"].replace("\\", "/").rsplit("/", 1)[-1]
            if not basename.strip() or basename in (".", "..") or any(ord(char) < 32 for char in basename):
                raise ValueError("image_name requires a non-empty basename without control characters.")
        plugin, kind, required = _plugin(context.get("plugin"))
        context["plugin"] = plugin
        rows = _flatten(rows)
        for row, _, _ in rows:
            if not required.issubset(row):
                raise ValueError("Result columns do not match the explicitly selected plugin: " + plugin)
        filename = request.get("filename")
        if filename in (None, ""):
            filename = "volatility3-results." + format_
        filename = _text(filename, "filename").replace("\\", "/").rsplit("/", 1)[-1]
        if len(filename) > 4096 or filename in ("", ".", "..") or any(ord(char) < 32 for char in filename):
            raise ValueError("filename requires a basename without control characters.")
        builder = _Builder(raw, filename, context, kind, format_)
        built = []
        for index, (row, path, parent) in enumerate(rows, 1):
            result, process, identity = builder.result(row, path, index)
            if parent is not None:
                parent_result, parent_process, parent_identity = built[parent]
                builder.link(parent_result, result, "contains")
                if kind == "process-tree" and process is not None and parent_process is not None:
                    pid, ppid, created = identity
                    parent_pid, _, parent_created = parent_identity
                    if (
                        ppid == parent_pid
                        and pid != parent_pid
                        and not (created and parent_created and parent_created > created)
                    ):
                        builder.link(parent_process, process, "parent-of")
                    else:
                        builder.warnings[
                            "Renderer ancestry conflicts with PID/creation context; process parent link omitted"
                        ] += 1
            built.append((result, process, identity))
        return {
            "results": {"Object": json.loads(builder.event.to_json())["Object"]},
            "summary": {"rows": len(rows), "plugin": plugin, "source_sha256": builder.digest, "format": format_},
            "warnings": [f"{message}: {count}" for message, count in sorted(builder.warnings.items())],
        }
    except (
        ValueError,
        TypeError,
        UnicodeError,
        binascii.Error,
        PyMISPError,
        RecursionError,
        OverflowError,
    ) as error:
        return {"error": f"Unable to import Volatility 3 results: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "plugin": {"type": "String", "message": "Required producing plugin, for example windows.pslist.PsList"},
            "format": {"type": "String", "message": "auto (default), json or jsonl"},
            "image_sha256": {
                "type": "String",
                "message": "Optional producer-supplied memory image SHA-256; never the export hash",
            },
            "image_name": {"type": "String", "message": "Optional memory image name/reference; never opened"},
            "plugin_version": {"type": "String", "message": "Optional producing plugin class version"},
            "volatility_version": {"type": "String", "message": "Optional Volatility 3 version"},
            "layer_name": {"type": "String", "message": "Optional scanned memory layer name"},
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
