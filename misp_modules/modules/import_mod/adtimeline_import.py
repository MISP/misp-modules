"""Import native ADTimeline replication-metadata CSV without contacting Active Directory."""

import base64
import binascii
import csv
import hashlib
import io
import json
import re
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from uuid import UUID, uuid5

from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "ADTimeline Import",
    "description": (
        "Import ADTimeline CSV replication metadata with linked-value times, server-scoped counters and source"
        " provenance."
    ),
    "module-type": ["import"],
    "requirements": ["PyMISP"],
    "features": (
        "Imports native semicolon-delimited timeline CSV as unreviewed ad-replication-metadata objects with an exact"
        " source attachment. Preserves all columns and raw timestamps. Replication metadata is partial last-change"
        " evidence, not actor attribution or confirmed malicious activity. No LDAP access or code execution. Includes"
        " its object template. See the usage guide for supported inputs and limits."
    ),
    "references": [
        "https://github.com/ANSSI-FR/ADTimeline",
        "https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/adtimeline_import.md",
    ],
    "input": "Base64-encoded native timeline_*.csv (UTF-8, or BOM-marked UTF-16).",
    "output": "Source file and unreviewed AD replication metadata objects.",
}
MAX_INPUT = 10 * 1024 * 1024
MAX_ROWS = 1000
MAX_FIELD = 65536
NAMESPACE = UUID("3c741064-5152-4f32-a2f5-c52e9fa4c548")
FIELDS = {
    "DN": "object-dn",
    "pszAttributeName": "attribute-name",
    "Name": "object-name",
    "ObjectClass": "object-class",
    "ObjectCategory": "object-category",
    "SamAccountName": "account-name",
    "SID": "sid",
    "dwVersion": "version",
    "pszLastOriginatingDsaDN": "originating-dsa-dn",
    "uuidLastOriginatingDsaInvocationID": "originating-invocation-id",
    "usnOriginatingChange": "originating-usn",
    "usnLocalChange": "local-usn",
    "Member": "linked-value-dn",
}
TIMES = {
    "ftimeLastOriginatingChange": "change-time",
    "WhenCreated": "object-created",
    "ftimeCreated": "link-created",
    "ftimeDeleted": "link-deleted",
}


@lru_cache(maxsize=1)
def _template():
    return json.loads(
        resources.files("misp_modules").joinpath("data", "ad-replication-metadata", "definition.json").read_text()
    )


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _text(value, name):
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_FIELD or "\x00" in value:
        raise ValueError(f"{name} must be nonempty text without NUL, at most 65536 characters.")
    return value


def _time(value):
    # ADTimeline documents UTC; never guess locale-dependent or timezone-free dates.
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T"
        r" ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
        value,
    ) or value.endswith("-00:00"):
        raise ValueError("Timestamp needs ISO seconds and a known timezone.")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    return None if parsed == datetime(1601, 1, 1, tzinfo=timezone.utc) else parsed.isoformat()


def _rows(raw):
    text = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
    if "\x00" in text:
        raise ValueError("CSV contains NUL characters.")
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=";", strict=True)
    header = next(reader, None)
    if (
        not header
        or len(header) > 128
        or any(not name.strip() or len(name) > 256 for name in header)
        or len(set(header)) != len(header)
    ):
        raise ValueError("CSV requires unique, nonempty column names.")
    required = {"DN", "pszAttributeName", "ftimeLastOriginatingChange"}
    if not required.issubset(header):
        raise ValueError("Expected native ADTimeline CSV columns: DN, pszAttributeName, ftimeLastOriginatingChange.")
    result = []
    for cells in reader:
        if not cells:
            continue
        if len(cells) != len(header) or any(len(value) > MAX_FIELD for value in cells):
            raise ValueError("CSV record has the wrong column count or an oversized field.")
        row = dict(zip(header, cells))
        for name in required:
            _text(row[name], name)
        result.append(row)
        if len(result) > MAX_ROWS:
            raise ValueError("At most 1000 timeline records are supported; select a smaller export.")
    if not result:
        raise ValueError("CSV contains no timeline records.")
    return result


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an import request object.")
        config = request.get("config")
        config = {} if config is None else config
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        context = {
            key: _text(config[key], key)
            for key in ("domain_scope", "collection_server")
            if config.get(key) not in (None, "")
        }
        encoded = request.get("data")
        if not isinstance(encoded, str) or not encoded or len(encoded) > 4 * ((MAX_INPUT + 2) // 3):
            raise ValueError("data requires a base64 export of at most 10 MiB.")
        raw = base64.b64decode(encoded, validate=True)
        if not raw or len(raw) > MAX_INPUT:
            raise ValueError("Export must be nonempty and at most 10 MiB.")
        rows = _rows(raw)
        filename = request.get("filename")
        filename = "adtimeline.csv" if filename in (None, "") else _text(filename, "filename")
        filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
        if filename in ("", ".", "..") or len(filename) > 255 or any(ord(c) < 32 for c in filename):
            raise ValueError("filename requires a basename of at most 255 characters without controls.")
        digest = hashlib.sha256(raw).hexdigest()
        event, warnings = MISPEvent(), Counter()
        source = MISPObject("file", strict=True, standalone=False)
        source.uuid = str(uuid5(NAMESPACE, _json([digest, filename])))

        def add(obj, relation, value, **kwargs):
            a = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
            a.uuid = str(uuid5(UUID(str(obj.uuid)), _json([relation, str(value)])))

        for relation, value in {"filename": filename, "sha256": digest, "size-in-bytes": len(raw)}.items():
            add(source, relation, value)
        add(source, "attachment", filename, data=io.BytesIO(raw))
        event.add_object(source)
        for number, row in enumerate(rows, 1):
            obj = MISPObject(
                "ad-replication-metadata", strict=True, standalone=False, misp_objects_template_custom=_template()
            )
            obj.uuid = str(uuid5(NAMESPACE, _json([source.uuid, number, context])))
            values = {
                "record-index": number,
                "source-sha256": digest,
                "raw-record": _json(row),
                "review-status": "unreviewed",
            }
            values.update({relation: row[key] for key, relation in FIELDS.items() if row.get(key)})
            values.update({key.replace("_", "-"): value for key, value in context.items()})
            for field, relation in TIMES.items():
                if not row.get(field):
                    continue
                values[relation + "-raw"] = row[field]
                try:
                    normalized = _time(row[field])
                except (ValueError, OverflowError):
                    warnings[f"Unsupported {field}; raw value retained without normalization"] += 1
                else:
                    if normalized:
                        values[relation] = normalized
            for relation, value in values.items():
                add(obj, relation, value)
            reference = obj.add_reference(source.uuid, "derived-from")
            reference.uuid = str(uuid5(UUID(str(obj.uuid)), str(source.uuid)))
            event.add_object(obj)
        return {
            "results": {"Object": json.loads(event.to_json())["Object"]},
            "summary": {"records": len(rows), "source_sha256": digest},
            "warnings": [f"{key}: {value}" for key, value in sorted(warnings.items())],
        }
    except (
        ValueError,
        TypeError,
        UnicodeError,
        binascii.Error,
        csv.Error,
        PyMISPError,
        OverflowError,
        RecursionError,
    ) as error:
        return {"error": f"Unable to import ADTimeline: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "domain_scope": {"type": "String", "message": "Optional collected domain context"},
            "collection_server": {"type": "String", "message": "Optional LDAP collection server; scopes local USNs"},
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
