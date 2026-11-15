"""Network-free evidence mapping for selected Zeek records and Suricata EVE."""

import base64
import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from importlib import resources
from io import BytesIO
from uuid import UUID, uuid5

from pymisp import MISPEvent, MISPObject

MAX_INPUT = 20 * 1024 * 1024
MAX_ROWS = 1000
MAX_ROW = 128 * 1024
MAX_DEPTH = 32
NAMESPACE = UUID("c81c553e-3dfa-453c-ae42-2c123e6a0f61")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
CONTEXT = ("sensor", "tool_version", "capture_file", "capture_sha256", "capture_url", "log_type", "timestamp_unit")
ISO_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T"
    r" ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):?[0-5][0-9])"
)


def dumps(value):
    # Preserve native Zeek numeric tokens exactly without adding a JSON dependency.
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("Non-finite JSON number.")
        return str(value)
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=True) + ":" + dumps(v) for k, v in sorted(value.items())) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(dumps(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Non-finite JSON number: " + value)


def loads(text):
    return json.loads(text, parse_float=Decimal, object_pairs_hook=_pairs, parse_constant=_constant)


def _text(value, field):
    if (
        isinstance(value, bool)
        or not isinstance(value, (str, int))
        or not str(value).strip()
        or "\x00" in str(value)
        or len(str(value)) > 4096
    ):
        raise ValueError(f"{field} must be non-empty text or an integer identifier of at most 4096 characters.")
    return str(value)


def _bounded(value):
    stack = [(value, 1)]
    while stack:
        child, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ValueError("Record nesting exceeds 32 levels.")
        if isinstance(child, dict):
            for key in child:
                key.encode("utf-8")
            stack.extend((v, depth + 1) for v in child.values())
        elif isinstance(child, list):
            stack.extend((v, depth + 1) for v in child)
        elif isinstance(child, str):
            child.encode("utf-8")
    if len(dumps(value).encode()) > MAX_ROW:
        raise ValueError("A normalized source record exceeds 128 KiB.")


def _integer(value, maximum):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r"[0-9]{1,20}", str(value)):
        raise ValueError("Expected an unsigned integer.")
    integer = int(value)
    if integer > maximum:
        raise ValueError("Integer outside its source range.")
    return integer


def _instant(value):
    if not isinstance(value, str) or not ISO_TIMESTAMP.fullmatch(value) or value.endswith(("-00:00", "-0000")):
        raise ValueError("Timestamp needs a known offset and at most microsecond precision.")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _epoch(value, unit):
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)) or len(str(value)) > 96:
        raise ValueError("Zeek epoch must be an exact decimal number.")
    number = Decimal(value)
    if not number.is_finite() or number and not -10 <= number.adjusted() <= 20:
        raise ValueError("Epoch outside the supported range or precision.")
    if not number:
        return EPOCH
    numerator, denominator = number.as_integer_ratio()
    numerator *= {"s": 1000000, "ms": 1000, "us": 1, "ns": 1}[unit]
    if unit == "ns":
        denominator *= 1000
    micros, remainder = divmod(numerator, denominator)
    if remainder:
        raise ValueError("Timestamp cannot be represented without sub-microsecond rounding.")
    return EPOCH + timedelta(microseconds=micros)


def _unescape(value, warnings):
    raw = re.sub(rb"\\x([0-9a-fA-F]{2})", lambda m: bytes([int(m[1], 16)]), value.encode())
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        warnings["Non-UTF-8 Zeek string retained in its original escaped form"] += 1
        return value


def _tsv(text, warnings):
    header, fields, types, rows, separator, closed = {}, None, None, [], None, False

    def column(value, type_):
        if value == header.get("unset_field", "-"):
            return None
        container = re.fullmatch(r"(?:set|vector)\[(.+)\]", type_)
        if value == header.get("empty_field", "(empty)"):
            return [] if container else ""
        if container:
            return [column(v, container[1]) for v in value.split(header.get("set_separator", ","))]
        decoded = _unescape(value, warnings)
        if type_ == "bool" and decoded in ("T", "F"):
            return decoded == "T"
        # Keep exact numeric time/interval tokens; only mapped fields are normalized.
        return decoded

    for line in text.split("\n"):
        line = line.removesuffix("\r")
        if not line:
            continue
        if line.startswith("#separator "):
            separator = _unescape(line[len("#separator ") :], warnings)
            if len(separator) != 1 or separator in ("\n", "\r", "#"):
                raise ValueError("Zeek requires a single safe field separator.")
            header, fields, types, closed = {}, None, None, False
            continue
        if separator is None:
            raise ValueError("Zeek TSV requires its #separator header.")
        if line.startswith("#"):
            key, sep, value = line[1:].partition(separator)
            if key == "fields":
                fields = value.split(separator)
                if not sep or any(not f for f in fields) or len(set(fields)) != len(fields):
                    raise ValueError("Zeek #fields must be non-empty and unique.")
            elif key == "types":
                types = value.split(separator)
            elif key == "close":
                closed = True
            elif sep:
                header[key] = _unescape(value, warnings)
            continue
        if closed or not fields or not types or len(fields) != len(types) or not header.get("path"):
            raise ValueError("Zeek TSV requires active #path, #fields and matching #types headers.")
        values = line.split(separator)
        if len(values) != len(fields):
            raise ValueError("Zeek TSV row width does not match #fields.")
        if len(rows) >= MAX_ROWS:
            raise ValueError("Export exceeds 1000 records.")
        data = {key: column(value, type_) for key, type_, value in zip(fields, types, values)}
        raw = {
            "line": line,
            "columns": dict(zip(fields, values)),
            "types": dict(zip(fields, types)),
            "headers": {**header, "separator": separator},
            "decoded": data,
        }
        rows.append((data, raw, header["path"]))
    return rows


def _read(text, format_, tool, warnings):
    automatic = format_ == "auto"
    if automatic:
        format_ = "tsv" if tool == "zeek" and text.lstrip().startswith("#separator ") else "json"
    if format_ == "tsv":
        return _tsv(text, warnings), {}, "zeek-tsv"
    if format_ == "json":
        try:
            value = loads(text)
        except json.JSONDecodeError:
            if not automatic or text.lstrip().startswith("["):
                raise
        else:
            metadata = {}
            if isinstance(value, dict) and "records" in value and "ts" not in value and "timestamp" not in value:
                metadata = value.get("metadata", {})
                if not isinstance(metadata, dict):
                    raise ValueError("metadata must be an object.")
                value = value["records"]
            value = value if isinstance(value, list) else [value]
            return [(v, v, None) for v in value], metadata, "json"
    rows = []
    for line in text.split("\n"):
        if line.strip():
            if len(rows) >= MAX_ROWS:
                raise ValueError("Export exceeds 1000 records.")
            value = loads(line)
            rows.append((value, value, None))
    return rows, {}, "jsonl"


def _selection(value, field):
    if value in (None, ""):
        return None
    if isinstance(value, str):
        value = [v.strip() for v in value.split(",")]
    if not isinstance(value, list) or not value or len(value) > MAX_ROWS:
        raise ValueError(field + " must be a non-empty comma-separated string or a list of at most 1000 identifiers.")
    if field == "flow_ids":
        return {str(_integer(v, 2**64 - 1)) for v in value}
    return {_text(v, field) for v in value}


@lru_cache(maxsize=1)
def _template():
    return json.loads(
        resources.files("misp_modules").joinpath("data", "network-observation", "definition.json").read_text()
    )


class _Builder:
    def __init__(self, raw, filename, tool, context, format_, attach, warnings):
        self.event, self.warnings, self.captures = MISPEvent(), warnings, {}
        self.tool, self.context, self.format = tool, context, format_
        self.digest = hashlib.sha256(raw).hexdigest()
        self.source = self.object("file", ["source", self.digest, filename])
        self.source.comment = "Input log export; its SHA-256 does not identify an underlying packet capture."
        for relation, value in {"filename": filename, "sha256": self.digest, "size-in-bytes": len(raw)}.items():
            self.add(self.source, relation, value)
        if attach:
            self.add(self.source, "attachment", filename, data=BytesIO(raw))
        else:
            self.warnings[
                "Full source attachment omitted to avoid including excluded records; original export hash retained"
            ] += 1

    def object(self, name, identity):
        custom = {"misp_objects_template_custom": _template()} if name == "network-observation" else {}
        obj = MISPObject(name, strict=True, standalone=False, **custom)
        obj.uuid = str(uuid5(NAMESPACE, dumps(identity)))
        self.event.add_object(obj)
        return obj

    def add(self, obj, relation, value, **kwargs):
        attribute = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
        attribute.uuid = str(uuid5(UUID(str(obj.uuid)), dumps([relation, str(value)])))

    def link(self, source, target, relationship):
        ref = source.add_reference(target.uuid, relationship)
        ref.uuid = str(uuid5(UUID(str(source.uuid)), dumps([str(target.uuid), relationship])))

    def text(self, value, field):
        if value is None or value == "":
            return None
        try:
            return _text(value, field)
        except ValueError:
            self.warnings[f"Invalid {field}; retained in raw record"] += 1
            return None

    def number(self, value, field, maximum):
        if value is None or value == "":
            return None
        try:
            return _integer(value, maximum)
        except ValueError:
            self.warnings[f"Invalid {field}; retained in raw record"] += 1
            return None

    def timestamp(self, value, relation, obj, store=True):
        try:
            if self.tool == "zeek" and relation == "event-time":
                parsed = (
                    _instant(value)
                    if isinstance(value, str) and ISO_TIMESTAMP.fullmatch(value)
                    else _epoch(value, self.context.get("timestamp_unit", "s"))
                )
            else:
                parsed = _instant(value)
        except (ValueError, InvalidOperation, OverflowError):
            self.warnings[
                f"Unsupported {relation}; original source retained without rounding or timezone guessing"
            ] += 1
            return None
        if store:
            self.add(obj, relation, parsed.isoformat())
        return parsed

    def capture(self, obj, row, sensor):
        native = row.get("pcap_filename") if self.tool == "suricata" else row.get("_capture_file")
        name = self.text(native, "capture file") if native is not None else self.context.get("capture_file")
        digest = self.context.get("capture_sha256")
        url = self.context.get("capture_url")
        if native is not None and digest and not self.context.get("capture_file"):
            digest = None
            self.warnings[
                "Native capture name needs matching collector capture_file before a default hash is applied"
            ] += 1
        if native is not None and self.context.get("capture_file") and name != self.context["capture_file"]:
            digest = None
            url = None
            self.warnings[
                "Native capture reference differs from collector default; default capture hash/URL not applied"
            ] += 1
        if name:
            self.add(obj, "capture-file", name)
        if digest:
            self.add(obj, "capture-sha256", digest)
        if url:
            self.add(obj, "capture-url", url)
        if not name and not digest:
            return
        key = (name, digest, sensor)
        if key not in self.captures:
            capture = self.object("pcap-metadata", ["capture", key, str(self.source.uuid)])
            self.add(
                capture,
                "text",
                "Producer-supplied packet capture reference; capture bytes were not opened or hashed by this importer.",
            )
            if name:
                self.add(capture, "file-name", name)
            if digest:
                self.add(capture, "file-hash-sha256", digest)
            self.link(capture, self.source, "derived-from")
            self.captures[key] = capture
        self.link(self.captures[key], obj, "derived-from")

    def record(self, row, raw, log_type, index):
        obj = self.object("network-observation", [str(self.source.uuid), self.tool, self.context, index, log_type])
        values = {
            "tool": self.tool,
            "log-type": log_type,
            "record-index": index,
            "raw-record": dumps(raw),
            "source-sha256": self.digest,
            "source-format": self.format,
            "review-status": "unreviewed",
        }
        if self.context:
            values["source-context"] = dumps(self.context)
        sensor = (
            self.text(row.get("host"), "sensor")
            if self.tool == "suricata" and row.get("host") is not None
            else self.context.get("sensor")
        )
        if sensor:
            values["sensor"] = sensor
        if self.context.get("tool_version"):
            values["tool-version"] = self.context["tool_version"]
        for relation, value in values.items():
            self.add(obj, relation, value)
        self.link(self.source, obj, "derived-from")
        self.capture(obj, row, sensor)
        stamp = row.get("ts") if self.tool == "zeek" else row.get("timestamp")
        self.add(obj, "timestamp-raw", stamp if isinstance(stamp, str) else dumps(stamp))
        parsed = self.timestamp(stamp, "event-time", obj)
        start, end = None, None
        if self.tool == "zeek":
            uid = self.text(row.get("uid"), "uid")
            if uid is not None:
                self.add(obj, "zeek-uid", uid)
            for column, relation in {
                "note": "notice-type",
                "msg": "message",
                "sig_id": "signature-id",
                "event_msg": "signature",
            }.items():
                value = self.text(row.get(column), column)
                if value is not None:
                    self.add(obj, relation, value)
            if log_type == "conn" and parsed is not None:
                start = parsed
                self.add(obj, "flow-start", start.isoformat())
            addresses = (("id.orig_h", "ip-src"), ("id.resp_h", "ip-dst"))
            ports = (("id.orig_p", "src-port"), ("id.resp_p", "dst-port"))
        else:
            for column, relation in (
                ("flow_id", "flow-id"),
                ("pcap_cnt", "packet-number"),
                ("tx_id", "transaction-id"),
            ):
                number = self.number(row.get(column), column, 2**64 - 1)
                if number is not None:
                    self.add(obj, relation, str(number))
            if "alert" in row:
                if not isinstance(row["alert"], dict):
                    raise ValueError("EVE alert must be an object.")
                alert = row["alert"]
                for column, relation in (
                    ("signature_id", "signature-id"),
                    ("gid", "generator-id"),
                    ("rev", "signature-revision"),
                    ("severity", "severity"),
                ):
                    number = self.number(alert.get(column), "alert." + column, 2**32 - 1)
                    if number is not None:
                        self.add(obj, relation, str(number))
                for column, relation in (("signature", "signature"), ("category", "category"), ("action", "action")):
                    value = self.text(alert.get(column), column)
                    if value is not None:
                        self.add(obj, relation, value)
            flow = row.get("flow", {})
            if not isinstance(flow, dict):
                raise ValueError("EVE flow must be an object.")
            if flow.get("start"):
                start = self.timestamp(flow["start"], "flow-start", obj, store=False)
            if flow.get("end"):
                end = self.timestamp(flow["end"], "flow-end", obj, store=False)
            if start and end and end < start:
                self.warnings["Flow end precedes start; bounds retained raw without normalization"] += 1
                start, end = None, None
            if start:
                self.add(obj, "flow-start", start.isoformat())
            if end:
                self.add(obj, "flow-end", end.isoformat())
            iface = self.text(row.get("in_iface"), "in_iface")
            if iface:
                self.add(obj, "interface", iface)
            addresses = (("src_ip", "ip-src"), ("dest_ip", "ip-dst"))
            ports = (("src_port", "src-port"), ("dest_port", "dst-port"))
        community = row.get("community_id")
        valid_community = None
        if community is not None:
            self.add(obj, "community-id-raw", community if isinstance(community, str) else dumps(community))
            try:
                if (
                    not isinstance(community, str)
                    or not re.fullmatch(r"1:[A-Za-z0-9+/]{27}=", community)
                    or len(base64.b64decode(community[2:], validate=True)) != 20
                ):
                    raise ValueError()
            except ValueError:
                self.warnings["Unsupported Community ID; original retained without normalization"] += 1
            else:
                valid_community = community
                self.add(obj, "community-id", community)
        network, versions = {}, set()
        for column, relation in addresses:
            value = row.get(column)
            if value is None or value == "":
                continue
            try:
                if not isinstance(value, str) or "%" in value:
                    raise ValueError()
                address = ipaddress.ip_address(value)
                network[relation] = str(address)
                versions.add(address.version)
            except ValueError:
                self.warnings[f"Invalid {column}; original retained without IP normalization"] += 1
        for column, relation in ports:
            number = self.number(row.get(column), column, 65535)
            if number is not None:
                network[relation] = number
        if not network and not valid_community:
            return
        connection = self.object("network-connection", [str(obj.uuid), "connection"])
        for relation, value in network.items():
            self.add(connection, relation, value)
        if valid_community:
            self.add(connection, "community-id", valid_community)
        if len(versions) == 1:
            self.add(connection, "layer3-protocol", "IPV6" if 6 in versions else "IPV4")
        elif len(versions) > 1:
            self.warnings["Mixed endpoint IP families; layer-3 protocol not inferred"] += 1
        proto = row.get("proto")
        if isinstance(proto, str) and proto.lower() in ("tcp", "udp", "icmp", "icmpv6", "ipv6-icmp", "sctp", "igmp"):
            self.add(connection, "layer4-protocol", proto.upper())
        if start:
            self.add(connection, "first-packet-seen", start.isoformat())
        if end:
            self.add(connection, "last-packet-seen", end.isoformat())
        self.link(obj, connection, "derived-from")
        self.link(obj, connection, "describes")


def import_observations(request, tool):
    config = request.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    format_ = config.get("format", "auto")
    if format_ in (None, ""):
        format_ = "auto"
    if format_ not in (("auto", "json", "jsonl", "tsv") if tool == "zeek" else ("auto", "json", "jsonl")):
        raise ValueError("Unsupported explicit input format.")
    encoded = request.get("data")
    if not isinstance(encoded, str) or not encoded or len(encoded) > 4 * ((MAX_INPUT + 2) // 3):
        raise ValueError("data must be a base64-encoded export of at most 20 MiB.")
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > MAX_INPUT:
        raise ValueError("Export must be non-empty and at most 20 MiB.")
    warnings = Counter()
    rows, metadata, format_ = _read(raw.decode("utf-8-sig"), format_, tool, warnings)
    if not rows or len(rows) > MAX_ROWS:
        raise ValueError("Export must contain 1–1000 records before selection.")
    context = {}
    for key in CONTEXT:
        values = [_text(c[key], key) for c in (metadata, config) if c.get(key) not in (None, "")]
        if key == "capture_sha256":
            values = [v.lower() for v in values]
            if any(not re.fullmatch(r"[0-9a-f]{64}", v) for v in values):
                raise ValueError("capture_sha256 requires exactly 64 hexadecimal digits.")
        if values:
            if len(set(values)) != 1:
                raise ValueError("Conflicting metadata/config " + key)
            context[key] = values[0]
    if context.get("timestamp_unit", "s") not in ("s", "ms", "us", "ns"):
        raise ValueError("timestamp_unit must be s, ms, us or ns.")
    if format_ == "zeek-tsv" and context.get("timestamp_unit", "s") != "s":
        raise ValueError("Zeek TSV time columns use seconds; numeric JSON units do not apply.")
    types = _selection(config.get("event_types"), "event_types") if tool == "suricata" else None
    ids = _selection(config.get("uids" if tool == "zeek" else "flow_ids"), "uids" if tool == "zeek" else "flow_ids")
    chosen = []
    for index, (row, original, path) in enumerate(rows, 1):
        if not isinstance(row, dict) or not row:
            raise ValueError("Every source record must be a non-empty object.")
        _bounded(original)
        stamp_key = "ts" if tool == "zeek" else "timestamp"
        if stamp_key not in row:
            raise ValueError("Source record lacks " + stamp_key)
        log_type = (
            _text(path or row.get("_path", context.get("log_type")), "Zeek log_type")
            if tool == "zeek"
            else _text(row.get("event_type"), "EVE event_type")
        )
        if tool == "zeek" and path and context.get("log_type") and path != context["log_type"]:
            raise ValueError("Explicit log_type conflicts with native Zeek #path.")
        if types is not None and log_type not in types:
            continue
        if ids is not None:
            value = row.get("uid") if tool == "zeek" else row.get("flow_id")
            try:
                identity = _text(value, "uid") if tool == "zeek" else str(_integer(value, 2**64 - 1))
            except ValueError:
                continue
            if identity not in ids:
                continue
        chosen.append((row, original, log_type, index))
    if not chosen:
        raise ValueError("No records match the requested selection.")
    filename = request.get("filename")
    if filename in (None, ""):
        filename = tool + "-observations." + ("log" if format_ == "zeek-tsv" else format_)
    filename = _text(filename, "filename").replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or any(ord(c) < 32 for c in filename):
        raise ValueError("filename requires a basename without control characters.")
    builder = _Builder(raw, filename, tool, context, format_, len(chosen) == len(rows), warnings)
    for row, original, log_type, index in chosen:
        builder.record(row, original, log_type, index)
    return {
        "results": {"Object": json.loads(builder.event.to_json())["Object"]},
        "summary": {
            "input_records": len(rows),
            "imported": len(chosen),
            "excluded": len(rows) - len(chosen),
            "source_sha256": builder.digest,
        },
        "warnings": [f"{message}: {count}" for message, count in sorted(warnings.items())],
    }
