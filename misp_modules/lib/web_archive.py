"""Read capture metadata from local WARC and WACZ bytes without replay."""

import gzip
import hashlib
import json
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from io import BufferedReader, BytesIO
from urllib.parse import urlsplit
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

MIB = 1024 * 1024
MAX_UPLOAD = 25 * MIB
MAX_ZIP_BYTES = 128 * MIB
MAX_WARC_BYTES = 128 * MIB
MAX_ZIP_MEMBERS = 512
MAX_RECORDS = 10000
MAX_CAPTURES = 1000
MAX_CAPTURE_HEADERS = 64
MAX_METADATA_BYTES = 8 * MIB
MAX_MANIFEST = MIB
MAX_HEADER = 64 * 1024
MAX_LINE = 8192
CHUNK = 64 * 1024
MANIFEST = "datapackage.json"
DIGEST = "datapackage-digest.json"
CAPTURE_TYPES = {"response", "revisit", "resource"}
RESPONSE_HEADERS = {
    "cache-control",
    "content-encoding",
    "content-language",
    "content-length",
    "content-type",
    "date",
    "etag",
    "last-modified",
    "location",
    "transfer-encoding",
    "vary",
}
WARC_FIELDS = {
    "warc-block-digest": "declared-block-digest",
    "warc-payload-digest": "declared-payload-digest",
    "warc-refers-to": "refers-to",
    "warc-refers-to-target-uri": "refers-to-target-uri",
    "warc-truncated": "truncated",
    "content-type": "block-content-type",
}
FIELD_NAME = re.compile(rb"[!#$%&'*+.^_\x60|~0-9A-Za-z-]+")
HTTP_STATUS = re.compile(rb"HTTP/([0-9]{1,2}(?:\.[0-9]{1,2})?) ([1-5][0-9]{2})(?:[ \t].*)?")
ISO_UTC = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z")


@dataclass
class WarcBudget:
    warc_bytes: int = 0
    records: int = 0
    metadata_bytes: int = 0


class WarcReader:
    def __init__(self, stream, budget):
        self.stream = stream
        self.budget = budget
        self.offset = 0

    def _bounded(self, method, size):
        remaining = MAX_WARC_BYTES - self.budget.warc_bytes
        chunk = method(min(size, remaining + 1))
        self.budget.warc_bytes += len(chunk)
        self.offset += len(chunk)
        if len(chunk) > remaining:
            raise ValueError("Inflated WARC data exceed the 128 MiB limit.")
        return chunk

    def read(self, size):
        return self._bounded(self.stream.read, size)

    def readline(self, size):
        return self._bounded(self.stream.readline, size)


def _line(reader, end=None, eof=False):
    limit = MAX_LINE + 1
    if end is not None:
        limit = min(limit, end - reader.offset)
    line = reader.readline(limit) if limit > 0 else b""
    if not line and eof:
        return None
    if not line.endswith(b"\n") or len(line) > MAX_LINE:
        raise ValueError("Truncated or oversized WARC or HTTP header line.")
    return line.removesuffix(b"\n").removesuffix(b"\r")


def _headers(reader, encoding, end=None):
    fields = []
    start = reader.offset
    while True:
        line = _line(reader, end)
        if reader.offset - start > MAX_HEADER:
            raise ValueError("WARC or HTTP headers exceed 64 KiB.")
        if not line:
            return [(name, value.decode(encoding)) for name, value in fields]
        if line.startswith((b" ", b"\t")) and fields:
            name, value = fields[-1]
            fields[-1] = name, value + b" " + line.strip(b" \t")
            continue
        name, sep, value = line.partition(b":")
        if not sep or not FIELD_NAME.fullmatch(name):
            raise ValueError("Invalid WARC or HTTP header name.")
        fields.append((name.decode("ascii").lower(), value.strip(b" \t")))


def _warc_fields(reader):
    fields = {}
    unique = WARC_FIELDS.keys() | {"content-length", "warc-date", "warc-record-id", "warc-target-uri", "warc-type"}
    for name, value in _headers(reader, "utf-8"):
        if name not in unique:
            continue
        if name in fields:
            raise ValueError("Duplicate WARC metadata field.")
        if any(not character.isprintable() and character != "\t" for character in value):
            raise ValueError("WARC metadata contains a control character.")
        fields[name] = value
    return fields


def _uri(value):
    return value[1:-1] if value.startswith("<") and value.endswith(">") else value


def _target(value):
    raw = _uri(value)
    if not raw:
        raise ValueError("Capture record is missing WARC-Target-URI.")
    if any(character.isspace() for character in raw):
        raise ValueError("Invalid whitespace in WARC-Target-URI.")
    url = urlsplit(raw)
    if url.scheme not in {"http", "https"}:
        return None
    if not url.hostname:
        raise ValueError("An HTTP WARC-Target-URI needs a hostname.")
    return raw


def _metadata(fields, reader, end):
    record_id = _uri(fields.get("warc-record-id", ""))
    if not record_id or not urlsplit(record_id).scheme or any(char.isspace() for char in record_id):
        raise ValueError("Capture record needs a WARC-Record-ID URI.")
    date = fields.get("warc-date", "")
    match = ISO_UTC.fullmatch(date)
    if not match:
        raise ValueError("Capture record needs a UTC WARC-Date.")
    fraction = (match[2] or "").ljust(6, "0")[:6]
    values = {
        "record-id": record_id,
        "capture-date": datetime.fromisoformat(f"{match[1]}.{fraction}+00:00").isoformat(),
        "warc-date-raw": date,
    }
    values.update({relation: fields[key] for key, relation in WARC_FIELDS.items() if fields.get(key)})
    http_headers = []
    block_type = fields.get("content-type", "").partition(";")[0].strip().lower()
    if fields["warc-type"] != "resource" and reader.offset < end and block_type in {"application/http", "message/http"}:
        status = HTTP_STATUS.fullmatch(_line(reader, end))
        if not status:
            raise ValueError("Invalid archived HTTP response status line.")
        values.update({"http-version": status[1].decode("ascii"), "http-status": status[2].decode("ascii")})
        for name, value in _headers(reader, "latin-1", end):
            if name in RESPONSE_HEADERS:
                if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
                    raise ValueError("Archived HTTP metadata contains a control character.")
                http_headers.append((name, value))
        if len(http_headers) > MAX_CAPTURE_HEADERS:
            raise ValueError("A capture exceeds 64 supported HTTP response headers.")
    return values, http_headers


def _skip_block(reader, end):
    while reader.offset < end:
        if not reader.read(min(CHUNK, end - reader.offset)):
            raise ValueError("Truncated WARC record content block.")
    if _line(reader) or _line(reader):
        raise ValueError("Expected a WARC record separator.")


def _collect(stream, path, captures, budget):
    reader = WarcReader(stream, budget)
    start_count = budget.records
    offset = 0
    while (version := _line(reader, eof=True)) is not None:
        if version not in {b"WARC/1.0", b"WARC/1.1"}:
            raise ValueError("Expected WARC 1.0 or 1.1 record.")
        budget.records += 1
        if budget.records > MAX_RECORDS:
            raise ValueError("Archive exceeds 10,000 WARC records.")
        fields = _warc_fields(reader)
        length = fields.get("content-length", "")
        if not re.fullmatch(r"[0-9]{1,10}", length) or not fields.get("warc-type"):
            raise ValueError("WARC record needs a type and a valid Content-Length.")
        length = int(length)
        if length > MAX_WARC_BYTES - budget.warc_bytes:
            raise ValueError("Inflated WARC data exceed the 128 MiB limit.")
        end = reader.offset + length
        kind = fields["warc-type"]
        if kind in CAPTURE_TYPES and (url := _target(fields.get("warc-target-uri", ""))):
            if len(captures) >= MAX_CAPTURES:
                raise ValueError("Archive exceeds 1,000 HTTP(S) captures.")
            values, headers = _metadata(fields, reader, end)
            values.update(
                {
                    "record-type": kind,
                    "target-uri": url,
                    "warc-version": version.decode("ascii")[5:],
                    "record-offset": offset,
                    "block-length": length,
                }
            )
            if path:
                values["member-path"] = path
            budget.metadata_bytes += sum(len(str(value).encode("utf-8")) for value in values.values())
            budget.metadata_bytes += sum(len(name) + len(value.encode("utf-8")) for name, value in headers)
            if budget.metadata_bytes > MAX_METADATA_BYTES:
                raise ValueError("Captured response metadata exceeds 8 MiB.")
            captures.append((values, headers))
        _skip_block(reader, end)
        offset = reader.offset
    if budget.records == start_count:
        raise ValueError("Empty WARC member.")


def _collect_warc(stream, path, captures, budget):
    with BufferedReader(stream) as buffered:
        if buffered.peek(2).startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=buffered) as inflated:
                _collect(inflated, path, captures, budget)
        else:
            _collect(buffered, path, captures, budget)


def _path(value):
    if (
        not isinstance(value, str)
        or len(value) > 1024
        or not value.isprintable()
        or ":" in value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("WACZ member path must be a safe relative ZIP path.")
    return value


def _zip_members(zipped):
    infos = zipped.infolist()
    if len(infos) > MAX_ZIP_MEMBERS or sum(info.file_size for info in infos) > MAX_ZIP_BYTES:
        raise ValueError("WACZ exceeds the ZIP member count or 128 MiB of inflated ZIP data.")
    members, names = {}, set()
    for info in infos:
        name = _path(info.filename.removesuffix("/") if info.is_dir() else info.filename)
        mode = stat.S_IFMT(info.external_attr >> 16) if info.create_system == 3 else 0
        if (
            name in names
            or info.orig_filename != info.filename
            or mode not in {0, stat.S_IFDIR if info.is_dir() else stat.S_IFREG}
            or info.flag_bits & 1
            or info.compress_type not in {ZIP_STORED, ZIP_DEFLATED}
            or (info.is_dir() and info.file_size)
        ):
            raise ValueError("WACZ contains a duplicate, unsafe, encrypted or unsupported ZIP member.")
        names.add(name)
        if not info.is_dir():
            members[name] = info
    return members


def _unique_json(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("WACZ metadata contains a duplicate JSON key.")
    return obj


def _read_json(zipped, info):
    with zipped.open(info) as stream:
        raw = stream.read(MAX_MANIFEST + 1)
    if len(raw) > MAX_MANIFEST:
        raise ValueError("WACZ manifest or digest file exceeds 1 MiB.")
    if len(raw) != info.file_size:
        raise ValueError("WACZ metadata byte count does not match its ZIP entry.")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json)
    if not isinstance(data, dict):
        raise ValueError("Expected a WACZ metadata JSON object.")
    return raw, data


def _verify_digest(declared, actual, description):
    if not isinstance(declared, str) or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", declared, re.IGNORECASE):
        raise ValueError(f"{description} must declare a SHA-256 digest.")
    if declared.lower().split(":")[-1] != actual:
        raise ValueError(f"{description} SHA-256 does not match the uploaded bytes.")


def _resource_info(manifest, members):
    resources = manifest.get("resources")
    if not isinstance(resources, list) or not resources or len(resources) > MAX_ZIP_MEMBERS:
        raise ValueError("WACZ manifest requires a bounded resources list.")
    listed = {}
    for resource in resources:
        if not isinstance(resource, dict):
            raise ValueError("Each WACZ resource must be an object.")
        path = _path(resource.get("path"))
        if path in listed:
            raise ValueError("Duplicate WACZ manifest resource path.")
        listed[path] = resource
    if listed.keys() != members.keys() - {MANIFEST, DIGEST}:
        raise ValueError("WACZ manifest resources must match the ZIP file members.")
    return listed


def _verify_resources(zipped, members, listed):
    verified = 0
    for path, resource in listed.items():
        info = members[path]
        legacy = resource.get("stats", {})
        if not isinstance(legacy, dict):
            raise ValueError("WACZ resource stats must be an object.")
        if "hash" in legacy and resource.get("hashing") not in (None, "sha256"):
            raise ValueError("Legacy WACZ resource digest must use SHA-256.")
        digest = hashlib.sha256()
        actual_size = 0
        with zipped.open(info) as stream:
            while chunk := stream.read(CHUNK):
                digest.update(chunk)
                actual_size += len(chunk)
        if actual_size != info.file_size:
            raise ValueError("Inflated WACZ resource byte count differs from its ZIP entry.")
        for attributes in (resource, legacy):
            if "bytes" in attributes and (type(attributes["bytes"]) is not int or attributes["bytes"] != actual_size):
                raise ValueError("WACZ resource byte count does not match its ZIP member.")
            if "hash" in attributes:
                _verify_digest(attributes["hash"], digest.hexdigest(), "WACZ resource")
        if "hash" in resource or "hash" in legacy:
            verified += 1
    return verified


def _manifest_digest(zipped, members, raw_manifest):
    if DIGEST not in members:
        return False, False
    _, details = _read_json(zipped, members[DIGEST])
    if details.get("path") != MANIFEST:
        raise ValueError("WACZ package digest must refer to datapackage.json.")
    actual = hashlib.sha256(raw_manifest).hexdigest()
    _verify_digest(details.get("hash"), actual, "WACZ manifest")
    signed = details.get("signedData")
    if signed is not None:
        if not isinstance(signed, dict):
            raise ValueError("WACZ signedData must be an object.")
        if "hash" in signed:
            _verify_digest(signed["hash"], actual, "WACZ signed metadata")
    return True, signed is not None


def _collect_wacz(raw, captures, budget):
    with ZipFile(BytesIO(raw)) as zipped:
        members = _zip_members(zipped)
        if MANIFEST not in members:
            raise ValueError("Expected a WACZ with root datapackage.json.")
        manifest_raw, manifest = _read_json(zipped, members[MANIFEST])
        if manifest.get("profile") not in (None, "data-package", "wacz"):
            raise ValueError("Unsupported WACZ manifest profile.")
        listed = _resource_info(manifest, members)
        warcs = sorted(
            path for path in listed if path.startswith("archive/") and path.lower().endswith((".warc", ".warc.gz"))
        )
        if not warcs:
            raise ValueError("WACZ must contain at least one WARC member under archive/.")
        manifest_verified, signed = _manifest_digest(zipped, members, manifest_raw)
        verified = _verify_resources(zipped, members, listed)
        for path in warcs:
            with zipped.open(members[path]) as stream:
                _collect_warc(stream, path, captures, budget)
    return {
        "manifest_digest": "verified" if manifest_verified else "not-present",
        "resources_verified": verified,
        "resources_total": len(listed),
        "signature": "not-verified" if signed else "not-present",
    }


def read_archive(raw, format_):
    """Return capture records, scanned record count and optional WACZ digest results."""
    captures, budget = [], WarcBudget()
    if format_ == "wacz":
        report = _collect_wacz(raw, captures, budget)
    else:
        _collect_warc(BytesIO(raw), None, captures, budget)
        report = None
    if not captures:
        raise ValueError("Archive contains no HTTP(S) response, revisit or resource captures.")
    return captures, budget.records, report
