"""Import portable web archive evidence into MISP."""

import base64
import binascii
import hashlib
import json
import zlib
from functools import lru_cache
from importlib import resources
from io import BytesIO
from uuid import UUID, uuid5
from zipfile import BadZipFile

from pymisp import MISPObject
from pymisp.exceptions import PyMISPError

from misp_modules.lib import web_archive

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Portable Web Archive Evidence Import",
    "description": "Import local WARC and WACZ captures with response metadata and package digest verification.",
    "module-type": ["import"],
    "requirements": ["PyMISP"],
    "features": (
        "Reads WARC 1.0/1.1, gzip-compressed WARC and WACZ. Links HTTP(S) capture records and selected archived"
        " response metadata to page-capture objects and the SHA-256 of the original upload. Verifies declared"
        " WACZ manifest and resource digests. Original archive attachment is optional. No replay or network access."
    ),
    "references": [
        "https://specs.webrecorder.net/wacz/1.2.0/",
        "https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/",
        "https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/web_archive_import.md",
    ],
    "input": "Base64-encoded WARC, WARC.GZ or WACZ file.",
    "output": "A source file, WARC record metadata and linked page-capture objects.",
}
NAMESPACE = UUID("f2cf075f-d1be-4cc1-b0b7-f1162acd7723")
FORMATS = {"wacz": "application/wacz+zip", "warc.gz": "application/gzip", "warc": "application/warc"}


@lru_cache(maxsize=2)
def _template(name):
    path = resources.files("misp_modules").joinpath("data", name, "definition.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _json(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _uuid(namespace, *parts):
    return str(uuid5(namespace, _json(parts)))


def _add(obj, relation, value, *, index=None, **kwargs):
    attr = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
    attr.uuid = _uuid(UUID(str(obj.uuid)), relation, index)


def _object(name, identity, values):
    options = {} if name == "file" else {"misp_objects_template_custom": _template(name)}
    obj = MISPObject(name, strict=True, standalone=False, **options)
    obj.uuid = _uuid(NAMESPACE, name, *identity)
    for relation, value in values.items():
        _add(obj, relation, value)
    return obj


def _source_reference(obj, source):
    ref = obj.add_reference(source.uuid, "extracted-from")
    ref.uuid = _uuid(UUID(str(obj.uuid)), "extracted-from", str(source.uuid))


def _upload(request):
    data = request.get("data")
    max_bytes = web_archive.MAX_UPLOAD
    if not isinstance(data, str) or len(data) > 4 * ((max_bytes + 2) // 3):
        raise ValueError("data requires a base64 archive upload of at most 25 MiB.")
    raw = base64.b64decode(data, validate=True)
    if not raw or len(raw) > max_bytes:
        raise ValueError("Archive upload must be nonempty and at most 25 MiB.")
    if raw.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return raw, "wacz"
    if raw.startswith(b"\x1f\x8b"):
        return raw, "warc.gz"
    if raw.startswith((b"WARC/1.0", b"WARC/1.1")):
        return raw, "warc"
    raise ValueError("Expected a WARC, gzip-compressed WARC or WACZ file.")


def _filename(request, format_):
    filename = request.get("filename")
    if filename in (None, ""):
        filename = f"capture.{format_}"
    if not isinstance(filename, str):
        raise ValueError("filename must be text.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255 or not filename.isprintable():
        raise ValueError("filename requires a printable basename of at most 255 characters.")
    return filename


def _attach(request):
    config = request.get("config")
    if config is None:
        return False
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    attach = config.get("include_archive")
    if isinstance(attach, str):
        attach = attach.strip().lower()
        if attach in ("true", "yes", "1"):
            return True
        if attach in ("", "false", "no", "0"):
            return False
    if attach is None or isinstance(attach, bool):
        return bool(attach)
    raise ValueError("include_archive must be a boolean.")


def _import(request):
    if not isinstance(request, dict):
        raise ValueError("Expected an import request object.")
    raw, format_ = _upload(request)
    filename = _filename(request, format_)
    attach = _attach(request)
    captures, scanned, report = web_archive.read_archive(raw, format_)
    digest = hashlib.sha256(raw).hexdigest()
    source = _object(
        "file",
        (digest,),
        {"filename": filename, "sha256": digest, "size-in-bytes": len(raw), "mimetype": FORMATS[format_]},
    )
    if attach:
        _add(source, "attachment", filename, data=BytesIO(raw))
    warnings = []
    if report is not None:
        _add(source, "text", _json(report), comment="WACZ package digest verification")
        if report["manifest_digest"] == "not-present" or report["resources_verified"] < report["resources_total"]:
            warnings.append("WACZ is missing the manifest digest or one or more resource digests.")
        if report["signature"] == "not-verified":
            warnings.append("WACZ signature metadata is present. Only digests were verified.")

    objects = [source]
    for values, headers in captures:
        identity = (digest, values.get("member-path"), values["record-offset"])
        record = _object("warc-record", identity, values)
        for index, (name, value) in enumerate(headers):
            _add(record, "http-response-header", _json({"name": name, "value": value}), index=index)
        capture = _object(
            "page-capture",
            identity,
            {
                "url": values["target-uri"],
                "capture-date": values["capture-date"],
                "archive-record-id": values["record-id"],
            },
        )
        _source_reference(record, source)
        _source_reference(capture, record)
        objects.extend((record, capture))

    summary = {
        "format": format_,
        "records_scanned": scanned,
        "captures": len(captures),
        "source_sha256": digest,
        "archive_attached": attach,
    }
    if report is not None:
        summary["wacz_integrity"] = report
    return {
        "results": {"Object": [json.loads(obj.to_json()) for obj in objects]},
        "summary": summary,
        "warnings": warnings,
    }


def handler(q=False):
    if q is False:
        return False
    try:
        return _import(json.loads(q))
    except (
        binascii.Error,
        UnicodeError,
        json.JSONDecodeError,
        BadZipFile,
        EOFError,
        OSError,
        zlib.error,
        RecursionError,
    ):
        return {"error": "Unable to decode web archive. Supply a valid WARC, gzip-compressed WARC or WACZ file."}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import web archive. Check the request and object templates."}
    except ValueError as error:
        return {"error": f"Unable to import web archive: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "include_archive": {
                "type": "Boolean",
                "message": "Attach the original archive (may contain sensitive content)",
            },
        },
    }


def version():
    return dict(moduleinfo, config=[])
