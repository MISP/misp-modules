"""Import locally supplied Open Cybersecurity Schema Framework event data."""

import base64
import binascii
import gzip
import hashlib
import ipaddress
import json
import re
import zlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO
from urllib.parse import urlsplit
from uuid import UUID, uuid5

from pymisp import MISPObject
from pymisp.exceptions import PyMISPError

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "OCSF Event Import",
    "description": "Import OCSF events and selected observables from a local JSON or JSON Lines export.",
    "module-type": ["import"],
    "data-source": "internal",
    "requirements": ["PyMISP"],
    "features": (
        "Preserves exact per-event JSON, schema and product provenance, and the source file SHA-256. "
        "Supports gzip, mixed event classes and extension fields, and extracts typed observables and "
        "selected endpoint, identity, process, file and finding fields. See the "
        "[usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/ocsf_import.md)."
    ),
    "references": [
        "https://schema.ocsf.io/",
        "https://github.com/ocsf/examples",
        "https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html",
    ],
    "input": "A UTF-8 JSON object, JSON array or JSON Lines upload, optionally gzip-compressed.",
    "output": "A source file and linked ocsf-event objects.",
}

MAX_UPLOAD = 10 * 1024 * 1024
MAX_JSON = 20 * 1024 * 1024
MAX_RECORDS = 1000
MAX_RECORD_BYTES = 512 * 1024
MAX_PIVOTS = 64
MAX_PIVOT_ITEMS = 128
RAW_TEXT_LIMIT = 32 * 1024
RAW_PART_SIZE = 4096
NAMESPACE = UUID("98f8d4d2-0174-4cb0-972e-5114a49710b0")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
JSON_WHITESPACE = re.compile(r"[ \t\r\n]*")
ISO_TIME = re.compile(
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})[Tt ](?P<clock>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]+))?(?P<offset>[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
MILLISECOND = timedelta(milliseconds=1)
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
OBSERVABLE_NAME = re.compile(r"[a-zA-Z0-9_.\[\]-]{1,160}")

NUMBER_FIELDS = {
    "category_uid": "category-id",
    "activity_id": "activity-id",
    "type_uid": "type-id",
    "severity_id": "severity-id",
    "status_id": "status-id",
}
TEXT_FIELDS = {
    "class_name": "class-name",
    "category_name": "category-name",
    "activity_name": "activity-name",
    "severity": "severity",
    "status": "status",
    "message": "message",
    "metadata.uid": "event-id",
    "metadata.original_event_uid": "original-event-id",
    "metadata.version": "schema-version",
    "metadata.product.name": "product-name",
    "metadata.product.vendor_name": "vendor-name",
    "metadata.product.version": "product-version",
    "metadata.tenant_uid": "tenant-id",
    "metadata.event_code": "event-code",
    "cloud.account.uid": "cloud-account-id",
    "cloud.region": "cloud-region",
}
TIME_FIELDS = {
    "time": "event-time",
    "start_time": "start-time",
    "end_time": "end-time",
    "metadata.logged_time": "logged-time",
}
ENDPOINTS = {
    "src_endpoint": "source-ip",
    "dst_endpoint": "destination-ip",
    "device": "ip-address",
    "endpoint": "ip-address",
}
USER_PATHS = ("user", "actor.user", "process.user", "actor.process.user")
PROCESS_PATHS = ("process", "actor.process", "process.parent_process", "actor.process.parent_process")
FILE_PATHS = ("file", "file_result", *(f"{p}.file" for p in PROCESS_PATHS))
OBSERVABLES = {
    1: "hostname",
    2: "ip-address",
    3: "mac-address",
    4: "user-name",
    5: "email-address",
    6: "url",
    7: "file-name",
    9: "process-name",
    10: "resource-id",
    13: "command-line",
    45: "file-path",
}
HASH_TYPES = {
    1: ("md5", 32),
    2: ("sha1", 40),
    3: ("sha256", 64),
    4: ("sha512", 128),
    8: ("sha224", 56),
    9: ("sha384", 96),
    10: ("sha512/224", 56),
    11: ("sha512/256", 64),
    12: ("sha3-224", 56),
    13: ("sha3-256", 64),
    14: ("sha3-384", 96),
    15: ("sha3-512", 128),
}
CORRELATABLE = {
    "source-ip",
    "destination-ip",
    "ip-address",
    "hostname",
    "domain",
    "mac-address",
    "url",
    *(relation for relation, _ in HASH_TYPES.values()),
}


def _unique_keys(pairs):
    record = {}
    for key, value in pairs:
        if key in record:
            raise ValueError("Duplicate JSON object key.")
        record[key] = value
    return record


def _invalid_constant(_):
    raise ValueError("Non-finite numbers are invalid in JSON.")


DECODER = json.JSONDecoder(object_pairs_hook=_unique_keys, parse_constant=_invalid_constant)


def _json(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _uuid(namespace, *parts):
    return str(uuid5(namespace, _json(parts)))


@lru_cache(maxsize=1)
def _template():
    return json.loads(
        resources.files("misp_modules").joinpath("data", "ocsf-event", "definition.json").read_text(encoding="utf-8")
    )


def _add(obj, relation, value, *, key=None, **kwargs):
    attr = obj.add_attribute(
        relation, value=value, to_ids=False, disable_correlation=relation not in CORRELATABLE, **kwargs
    )
    attr.uuid = _uuid(UUID(obj.uuid), relation, key)


def _upload(request):
    encoded = request.get("data")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_UPLOAD + 2) // 3):
        raise ValueError("Provide base64-encoded OCSF file data of at most 10 MiB.")
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > MAX_UPLOAD:
        raise ValueError("Upload must contain between 1 byte and 10 MiB.")
    compressed = raw.startswith(b"\x1f\x8b")
    if compressed:
        with gzip.GzipFile(fileobj=BytesIO(raw)) as archive:
            payload = archive.read(MAX_JSON + 1)
        if len(payload) > MAX_JSON:
            raise ValueError("Decompressed OCSF upload exceeds 20 MiB.")
    else:
        payload = raw
    if payload.startswith(b"PAR1"):
        raise ValueError("This is a Parquet file. Export the OCSF rows as JSON Lines before importing.")

    filename = request.get("filename")
    if filename in (None, ""):
        filename = "ocsf.json.gz" if compressed else "ocsf.json"
    if not isinstance(filename, str):
        raise ValueError("filename must be text.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255 or not filename.isprintable():
        raise ValueError("Provide a printable filename of at most 255 characters.")

    config = request.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    include_source = config.get("include_source")
    if isinstance(include_source, str):
        include_source = include_source.strip().lower()
    if include_source in (None, False, "", "false", "0", "no"):
        attach = False
    elif include_source in (True, "true", "1", "yes"):
        attach = True
    else:
        raise ValueError("include_source must be a boolean.")
    return raw, payload.decode("utf-8-sig"), filename, compressed, attach


def _skip_space(text, position):
    return JSON_WHITESPACE.match(text, position).end()


def _records(text):
    """Yield each decoded record and its original JSON text."""
    start = _skip_space(text, 0)
    if start == len(text):
        return
    array = text[start] == "["
    if array:
        start = _skip_space(text, start + 1)
        if text[start : start + 1] == "]" and _skip_space(text, start + 1) == len(text):
            return
    index = 0
    while True:
        index += 1
        if index > MAX_RECORDS:
            raise ValueError("Upload exceeds 1,000 OCSF records.")
        try:
            record, end = DECODER.raw_decode(text, start)
        except json.JSONDecodeError as error:
            raise ValueError(f"Record {index} is not valid JSON.") from error
        next_start = _skip_space(text, end)
        if array:
            marker = text[next_start : next_start + 1]
            if marker == "]" and _skip_space(text, next_start + 1) == len(text):
                yield record, text[start:end], "json-array"
                return
            if marker != ",":
                raise ValueError("Expected a comma or the end of the JSON array.")
            yield record, text[start:end], "json-array"
            start = _skip_space(text, next_start + 1)
        else:
            if next_start < len(text) and "\n" not in text[end:next_start]:
                raise ValueError("JSON Lines requires a newline between records.")
            format_ = "json" if index == 1 and next_start == len(text) else "json-lines"
            if format_ == "json-lines" and "\n" in text[start:end]:
                format_ = "json-stream"
            yield record, text[start:end], format_
            if next_start == len(text):
                return
            start = next_start


def _get(record, path):
    for key in path.split("."):
        if not isinstance(record, dict):
            return None
        record = record.get(key)
    return record


def _number(value, *, signed=False):
    pattern = r"-?[0-9]{1,19}" if signed else r"[0-9]{1,19}"
    if type(value) not in (int, str) or not re.fullmatch(pattern, str(value)):
        return None
    parsed = int(value)
    return parsed if -(2**63) <= parsed < 2**63 else None


def _text(value, maximum=2048):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > maximum or any(ord(c) > 0xFFFF or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        return None
    if any(not c.isprintable() and c not in "\r\n\t" for c in value):
        return None
    return value


def _date(value):
    match = ISO_TIME.fullmatch(value) if isinstance(value, str) else None
    if match is None or match["offset"] == "-00:00":
        raise ValueError("Timestamp needs an explicit offset.")
    fraction = match["fraction"] or ""
    offset = "+00:00" if match["offset"] in ("Z", "z") else match["offset"]
    normalized = f"{match['date']}T{match['clock']}"
    if fraction:
        normalized += f".{fraction[:6]}"
    instant = datetime.fromisoformat(normalized + offset).astimezone(timezone.utc)
    return instant, bool(fraction[6:].strip("0"))


def _timestamp(record, path, warnings):
    dt_value = _get(record, path + "_dt")
    ms_value = _get(record, path)
    explicit = epoch = None
    truncated = False
    if dt_value is not None:
        try:
            explicit, truncated = _date(dt_value)
        except (ValueError, OverflowError):
            warnings[f"Invalid {path}_dt retained in source JSON"] += 1
    if ms_value is not None:
        try:
            millis = _number(ms_value, signed=True)
            if millis is None:
                raise ValueError("Expected milliseconds.")
            epoch = EPOCH + timedelta(milliseconds=millis)
        except (ValueError, OverflowError):
            warnings[f"Invalid {path} retained in source JSON"] += 1
    if explicit:
        comment = f"Reported in {path}_dt"
        if truncated:
            warnings[f"Sub-microsecond precision in {path}_dt retained in source JSON"] += 1
            comment += ". Truncated to microseconds"
        if epoch:
            delta = explicit - epoch
            # A discarded fraction places the original instant after the normalized one.
            if abs(delta) >= MILLISECOND and not (truncated and delta == -MILLISECOND):
                warnings[f"{path}_dt disagrees with {path} in epoch milliseconds. Used {path}_dt"] += 1
                comment += f". {path} disagreed when interpreted as UTC epoch milliseconds"
        return explicit.isoformat(), comment
    if epoch:
        return epoch.isoformat(), f"Reported in {path} as UTC epoch milliseconds"
    return None


def _host(value):
    value = value.removesuffix(".")
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if (
        len(value) <= 253
        and not value.replace(".", "").isdigit()
        and all(HOST_LABEL.fullmatch(label) for label in value.split("."))
    ):
        return value
    return None


def _ip(value):
    if "%" not in value:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    return None


def _validated(relation, value):
    value = _text(value, 2048)
    if value is None:
        return None
    if relation in {"source-ip", "destination-ip", "ip-address"}:
        return _ip(value)
    if relation in {"hostname", "domain"}:
        host = _host(value)
        return host if host and (relation != "domain" or "." in host) else None
    if relation == "url":
        if any(c.isspace() for c in value):
            return None
        try:
            url = urlsplit(value)
            if (
                url.scheme in {"http", "https"}
                and url.hostname
                and (_host(url.hostname) or _ip(url.hostname))
                and url.username is None
                and (url.port is None or url.port > 0)
            ):
                return value
        except ValueError:
            pass
        return None
    if relation == "email-address":
        local, sep, domain = value.rpartition("@")
        return value if sep and re.fullmatch(r"[^@\s]+", local) and _host(domain) else None
    if relation == "mac-address":
        if re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", value):
            return value.replace("-", ":").lower()
        return None
    return value


def _entries(value, warnings):
    if not isinstance(value, list):
        return ()
    if len(value) > MAX_PIVOT_ITEMS:
        warnings["Source array exceeded the 128-entry pivot scan limit; full array retained"] += 1
    return enumerate(value[:MAX_PIVOT_ITEMS])


def _contexts(record, warnings):
    yield "", record
    for field in ("evidence", "evidences"):
        for index, context in _entries(record.get(field), warnings):
            if isinstance(context, dict):
                yield f"{field}[{index}].", context


def _pivot_fields(record, warnings):
    for prefix, context in _contexts(record, warnings):
        for endpoint, ip_relation in ENDPOINTS.items():
            for name, relation in (("ip", ip_relation), ("hostname", "hostname"), ("mac", "mac-address")):
                path = f"{endpoint}.{name}"
                yield relation, _get(context, path), prefix + path
        for user in USER_PATHS:
            for name, relation in (("name", "user-name"), ("uid", "user-id"), ("email_addr", "email-address")):
                path = f"{user}.{name}"
                yield relation, _get(context, path), prefix + path
        for process in PROCESS_PATHS:
            for name, relation in (("name", "process-name"), ("cmd_line", "command-line")):
                path = f"{process}.{name}"
                yield relation, _get(context, path), prefix + path
        for file in FILE_PATHS:
            for name, relation in (("name", "file-name"), ("path", "file-path")):
                path = f"{file}.{name}"
                yield relation, _get(context, path), prefix + path
            for index, fingerprint in _entries(_get(context, f"{file}.hashes"), warnings):
                algo = HASH_TYPES.get(_number(_get(fingerprint, "algorithm_id")))
                value = _get(fingerprint, "value")
                if algo and isinstance(value, str) and len(value) == algo[1] and re.fullmatch(r"[0-9a-fA-F]+", value):
                    yield algo[0], value.lower(), f"{prefix}{file}.hashes[{index}].value"
        for url in ("url", "http_request.url"):
            for name, relation in (("url_string", "url"), ("domain", "domain"), ("hostname", "hostname")):
                path = f"{url}.{name}"
                yield relation, _get(context, path), prefix + path
        yield "hostname", _get(context, "query.hostname"), prefix + "query.hostname"
    for index, item in _entries(record.get("observables"), warnings):
        relation = OBSERVABLES.get(_number(_get(item, "type_id")))
        if relation:
            path = f"observables[{index}].value"
            name = _get(item, "name")
            if isinstance(name, str) and OBSERVABLE_NAME.fullmatch(name):
                if relation == "ip-address" and name.endswith(".ip"):
                    relation = ENDPOINTS.get(name.rsplit(".", 2)[-2], relation)
                path = f"{path} ({name})"
            yield relation, _get(item, "value"), path


def _pivots(record, obj, warnings):
    pivots = {}
    limited = False
    for relation, value, path in _pivot_fields(record, warnings):
        if value is None:
            continue
        normalized = _validated(relation, value)
        if normalized is None:
            warnings[f"Invalid {relation} value retained in source JSON"] += 1
            continue
        key = (relation, normalized)
        if key not in pivots and len(pivots) >= MAX_PIVOTS:
            limited = True
            continue
        paths = pivots.setdefault(key, [])
        if len(paths) < 5 and path not in paths:
            paths.append(path)
    for (relation, value), paths in pivots.items():
        _add(obj, relation, value, key=value, comment="Reported in " + ", ".join(paths))
    if limited:
        warnings["Record exceeds the limit of 64 distinct projected values"] += 1
    return len(pivots)


def _raw_record(obj, text):
    if text.isascii() and len(text) <= RAW_TEXT_LIMIT:
        _add(obj, "raw-event", text)
        return
    parts = [text[start : start + RAW_PART_SIZE] for start in range(0, len(text), RAW_PART_SIZE)]
    for index, part in enumerate(parts, 1):
        _add(obj, "raw-event-part", _json({"part": index, "parts": len(parts), "text": part}), key=index)


def _event(record, text, index, source, digest, warnings):
    if not isinstance(record, dict) or (class_id := _number(record.get("class_uid"))) is None:
        raise ValueError(f"Record {index} must be an OCSF object with a nonnegative integer class_uid.")
    data = text.encode("utf-8")
    if len(data) > MAX_RECORD_BYTES:
        raise ValueError(f"Record {index} exceeds 512 KiB.")
    event = MISPObject("ocsf-event", strict=True, standalone=False, misp_objects_template_custom=_template())
    event.uuid = _uuid(NAMESPACE, "ocsf-event", source.uuid, index)
    _add(event, "class-id", class_id)
    _add(event, "record-index", index)
    _add(event, "source-sha256", digest)
    _add(event, "event-sha256", hashlib.sha256(data).hexdigest())
    _raw_record(event, text)
    for path, relation in NUMBER_FIELDS.items():
        if (value := _number(record.get(path))) is not None:
            _add(event, relation, value)
    for path, relation in TEXT_FIELDS.items():
        if (value := _text(_get(record, path))) is not None:
            _add(event, relation, value)
    for field, relation in (("uid", "finding-id"), ("title", "finding-title")):
        value = _text(_get(record, f"finding_info.{field}")) or _text(_get(record, f"finding.{field}"))
        if value is not None:
            _add(event, relation, value)
    for path, relation in TIME_FIELDS.items():
        if (selected := _timestamp(record, path, warnings)) is not None:
            value, comment = selected
            _add(event, relation, value, comment=comment)
    count = _pivots(record, event, warnings)
    ref = event.add_reference(source.uuid, "extracted-from")
    ref.uuid = _uuid(UUID(event.uuid), "extracted-from", source.uuid)
    return event, count


def _import(request):
    if not isinstance(request, dict):
        raise ValueError("Expected a request object.")
    raw, text, filename, compressed, attach = _upload(request)
    digest = hashlib.sha256(raw).hexdigest()
    source = MISPObject("file", strict=True, standalone=False)
    source.uuid = _uuid(NAMESPACE, "file", digest, filename)
    _add(source, "filename", filename)
    _add(source, "sha256", digest)
    _add(source, "size-in-bytes", len(raw))
    _add(source, "mimetype", "application/gzip" if compressed else "application/json")
    if attach:
        _add(source, "attachment", filename, data=BytesIO(raw))
    warnings = Counter()
    serialized = [json.loads(source.to_json(strict=True))]
    pivot_count = 0
    source_format = None
    for index, (record, original, format_) in enumerate(_records(text), 1):
        if source_format is None or format_ == "json-stream":
            source_format = format_
        event, count = _event(record, original, index, source, digest, warnings)
        pivot_count += count
        serialized.append(json.loads(event.to_json(strict=True)))
    if len(serialized) == 1:
        raise ValueError("The upload contains no OCSF events.")
    return {
        "results": {"Object": serialized},
        "summary": {
            "format": source_format,
            "gzip": compressed,
            "records": len(serialized) - 1,
            "projected_values": pivot_count,
            "source_sha256": digest,
            "source_attached": attach,
        },
        "warnings": [f"{message} ({count})" for message, count in sorted(warnings.items())],
    }


def handler(q=False):
    if q is False:
        return False
    try:
        return _import(json.loads(q))
    except (binascii.Error, UnicodeError, json.JSONDecodeError, OSError, EOFError, zlib.error, RecursionError):
        return {"error": "Unable to decode OCSF upload. Supply UTF-8 JSON or JSON Lines, optionally gzip-compressed."}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import OCSF events. Check the request and object templates."}
    except ValueError as error:
        return {"error": f"Unable to import OCSF events: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {"include_source": {"type": "Boolean", "message": "Attach the exact source upload"}},
    }


def version():
    return dict(moduleinfo, config=[])
