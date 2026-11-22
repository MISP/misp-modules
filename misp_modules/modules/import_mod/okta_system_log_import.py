"""Import saved native Okta System Log API responses."""

import base64
import binascii
import gzip
import hashlib
import ipaddress
import json
import re
import zlib
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO
from uuid import UUID, uuid5

from pymisp import MISPObject
from pymisp.exceptions import PyMISPError

from misp_modules.lib.network_observation import dumps, loads

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Okta System Log Import",
    "description": "Import saved Okta System Log events with typed targets and investigation links.",
    "module-type": ["import"],
    "data-source": "internal",
    "requirements": ["PyMISP"],
    "features": (
        "Reads native Okta System Log API JSON arrays or individual events. Captures actor, client IP, authentication"
        " context, outcome, targets, and distinct transaction, session and root session IDs. Connects events with"
        " shared reported identifiers and links them to the original upload. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/okta_system_log_import.md)."
    ),
    "references": [
        "https://developer.okta.com/docs/reference/system-log-query/",
        "https://developer.okta.com/docs/api/openapi/okta-management/management/tags/systemlog",
    ],
    "input": "Saved native Okta System Log API JSON, optionally gzip-compressed.",
    "output": "A source file and linked Okta System Log event and target objects.",
}

MAX_UPLOAD = 10 * 1024 * 1024
MAX_JSON = 20 * 1024 * 1024
MAX_RECORDS = 1000
MAX_TARGETS = 2000
MAX_TEXT = 4096
NAMESPACE = UUID("251eaa5e-b92d-4b63-bab6-705bf2c91aca")
EVENT = "okta-system-log-event"
TARGET = "okta-system-log-target"
TIMESTAMP = re.compile(
    r"(?P<seconds>[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<offset>[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
UNUSABLE_IDS = {
    "0",
    "-",
    "none",
    "null",
    "unknown",
    "undefined",
    "n/a",
    "system",
    "okta#system",
    "00000000-0000-0000-0000-000000000000",
}
PIVOT_FIELDS = {
    "actor-id": "actor or target ID",
    "target-id": "actor or target ID",
    "client-ip": "client IP",
    "external-session-id": "external session ID",
    "root-session-id": "root session ID",
    "transaction-id": "transaction ID",
}
EVENT_FIELDS = {
    "severity": "severity",
    "legacyEventType": "legacy-event-type",
}
ACTOR_FIELDS = {
    "id": "actor-id",
    "type": "actor-type",
    "alternateId": "actor-alternate-id",
    "displayName": "actor-display-name",
}
TARGET_FIELDS = {
    "id": "target-id",
    "type": "target-type",
    "alternateId": "target-alternate-id",
    "displayName": "target-display-name",
}
AUTH_FIELDS = {
    "authenticationProvider": "authentication-provider",
    "credentialProvider": "credential-provider",
    "credentialType": "credential-type",
    "externalSessionId": "external-session-id",
    "rootSessionId": "root-session-id",
    "interface": "authentication-interface",
}


@lru_cache(maxsize=2)
def _template(name):
    definition = resources.files("misp_modules").joinpath("data", "okta-system-log", name, "definition.json")
    return json.loads(definition.read_text(encoding="utf-8"))


def _uuid(namespace, *parts):
    return str(uuid5(namespace, json.dumps(parts, ensure_ascii=True, separators=(",", ":"))))


def _pivot(relation, value):
    kind = PIVOT_FIELDS.get(relation)
    if kind and len(value) <= 191 and not any(c.isspace() for c in value) and value.casefold() not in UNUSABLE_IDS:
        if relation == "client-ip" and ipaddress.ip_address(value).is_unspecified:
            return None
        return kind, value
    return None


def _object(name, identity, fields):
    options = {} if name == "file" else {"misp_objects_template_custom": _template(name)}
    obj = MISPObject(name, strict=True, standalone=False, **options)
    obj.uuid = _uuid(NAMESPACE, name, *identity)
    for relation, value in fields.items():
        _add(obj, relation, value)
    return obj


def _add(obj, relation, value, **kwargs):
    attr = obj.add_attribute(
        relation, value=value, to_ids=False, disable_correlation=_pivot(relation, value) is None, **kwargs
    )
    attr.uuid = _uuid(UUID(obj.uuid), relation)


def _reference(obj, other, relationship, comment):
    ref = obj.add_reference(other.uuid, relationship, comment)
    ref.uuid = _uuid(UUID(obj.uuid), relationship, other.uuid)


def _text(value, field, *, multiline=False):
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise ValueError(f"{field} must be nonempty text of at most 4,096 characters.")
    if any(not c.isprintable() and not (multiline and c in "\r\n\t") for c in value):
        raise ValueError(f"{field} contains unsupported characters.")
    return value


def _fields(record, mapping):
    result = {}
    for field, relation in mapping.items():
        value = record.get(field)
        if value not in (None, ""):
            result[relation] = _text(value, field)
    return result


def _mapping(record, field):
    value = record.get(field)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object.")
    return value


def _include_source(request):
    config = request.get("config")
    if config is None:
        return False
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    value = config.get("include_source")
    if isinstance(value, str):
        value = value.strip().lower()
        if value in ("yes", "true", "1"):
            return True
        if value in ("", "no", "false", "0"):
            return False
    if value is None or isinstance(value, bool):
        return bool(value)
    raise ValueError("include_source must be a boolean.")


def _upload(request):
    encoded = request.get("data")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_UPLOAD + 2) // 3):
        raise ValueError("Provide a base64 upload of at most 10 MiB.")
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > MAX_UPLOAD:
        raise ValueError("Upload must contain between 1 byte and 10 MiB.")
    compressed = raw.startswith(b"\x1f\x8b")
    if compressed:
        with gzip.GzipFile(fileobj=BytesIO(raw)) as stream:
            payload = stream.read(MAX_JSON + 1)
    else:
        payload = raw
    if len(payload) > MAX_JSON:
        raise ValueError("Decoded System Log upload exceeds 20 MiB.")
    filename = request.get("filename")
    if filename in (None, ""):
        filename = "okta-system-log.json.gz" if compressed else "okta-system-log.json"
    filename = _text(filename, "filename").replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255:
        raise ValueError("Provide a printable basename of at most 255 characters.")
    return raw, filename, loads(payload.decode("utf-8-sig"))


def _records(document):
    if isinstance(document, list):
        records, format_ = document, "system-log-array"
    elif isinstance(document, dict) and "uuid" in document:
        records, format_ = [document], "system-log-event"
    else:
        raise ValueError("Expected a native System Log event or API response array.")
    if not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError("The upload must contain between 1 and 1,000 System Log records.")
    return records, format_


def _timestamp(value):
    raw = _text(value, "published")
    match = TIMESTAMP.fullmatch(raw)
    if not match or match["offset"] == "-00:00":
        raise ValueError("published needs an offset-aware ISO 8601 timestamp with at most nine fractional digits.")
    offset = "+00:00" if match["offset"].upper() == "Z" else match["offset"]
    try:
        instant = datetime.fromisoformat(match["seconds"].upper() + offset).astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise ValueError("published is outside the supported calendar or UTC offset.") from error
    microseconds = int((match["fraction"] or "").ljust(6, "0")[:6])
    return instant.replace(microsecond=microseconds)


def _targets(record):
    values = record.get("target")
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > MAX_TARGETS:
        raise ValueError("target must be an array of at most 2,000 entries.")
    result = []
    for index, item in enumerate(values, 1):
        if not isinstance(item, dict):
            raise ValueError(f"target[{index - 1}] must be an object.")
        result.append({"target-index": index, **_fields(item, TARGET_FIELDS)})
    return result


def _event(record, identifier):
    values = {"event-id": identifier, "event-type": _text(record.get("eventType"), "eventType")}
    values.update(_fields(record, EVENT_FIELDS))
    version = record.get("version")
    if version not in (None, ""):
        values["schema-version"] = _text(str(version) if type(version) is int else version, "version")
    values.update(_fields(_mapping(record, "actor"), ACTOR_FIELDS))
    values.update(_fields(_mapping(record, "transaction"), {"id": "transaction-id", "type": "transaction-type"}))
    auth = _mapping(record, "authenticationContext")
    values.update(_fields(auth, AUTH_FIELDS))
    values.update(_fields(_mapping(auth, "issuer"), {"id": "issuer-id", "type": "issuer-type"}))
    if (step := auth.get("authenticationStep")) is not None:
        if type(step) is not int or not 0 <= step <= 2**31 - 1:
            raise ValueError("authenticationContext.authenticationStep must be a nonnegative int32.")
        values["authentication-step"] = step

    client = _mapping(record, "client")
    values.update(_fields(client, {"ipAddress": "client-address", "device": "client-device", "zone": "client-zone"}))
    values.update(_fields(_mapping(client, "userAgent"), {"rawUserAgent": "user-agent"}))
    if (address := values.get("client-address")) and "%" not in address:
        try:
            values["client-ip"] = str(ipaddress.ip_address(address))
        except ValueError:
            pass

    outcome = _mapping(record, "outcome")
    values.update(_fields(outcome, {"result": "outcome"}))
    for parent, field, relation in ((record, "displayMessage", "message"), (outcome, "reason", "outcome-reason")):
        if parent.get(field) not in (None, ""):
            values[relation] = _text(parent[field], field, multiline=True)
    debug = _mapping(_mapping(record, "debugContext"), "debugData")
    values.update(
        _fields(debug, {"requestId": "request-id", "factor": "reported-factor", "factorType": "reported-factor-type"})
    )

    observed = None
    if record.get("published") is not None:
        observed = _timestamp(record["published"])
        values.update({"published": observed.isoformat(), "published-raw": record["published"]})
    return values, observed


def _link_related(event, fields, targets, anchors):
    groups = defaultdict(set)
    keys = {
        pivot
        for mapping in (fields, *targets)
        for relation, value in mapping.items()
        if (pivot := _pivot(relation, value)) is not None
    }
    for key in sorted(keys):
        first = anchors.setdefault(key, event)
        if first is not event:
            groups[first.uuid].add(key[0])
    for anchor, shared in groups.items():
        ref = event.add_reference(anchor, "related-to", "Shared reported Okta " + ", ".join(sorted(shared)))
        ref.uuid = _uuid(UUID(event.uuid), "related-to", anchor)
    return len(groups)


def _import(request):
    if not isinstance(request, dict):
        raise ValueError("Expected an import request object.")
    attach = _include_source(request)
    raw, filename, document = _upload(request)
    records, format_ = _records(document)
    digest = hashlib.sha256(raw).hexdigest()
    source = _object("file", (digest, filename), {"filename": filename, "sha256": digest, "size-in-bytes": len(raw)})
    if attach:
        _add(source, "attachment", filename, data=BytesIO(raw))

    events, targets, fingerprints, anchors = [], [], {}, {}
    missing_timestamps = 0
    related_links = 0
    for index, record in enumerate(records, 1):
        try:
            if not isinstance(record, dict):
                raise ValueError("Every System Log record must be an object.")
            identifier = _text(record.get("uuid"), "uuid")
            fingerprint = hashlib.sha256(dumps(record).encode("ascii")).digest()
            if identifier in fingerprints:
                if fingerprints[identifier] != fingerprint:
                    raise ValueError("Conflicting records share the same System Log UUID.")
                continue
            fingerprints[identifier] = fingerprint
            values, observed = _event(record, identifier)
            event_targets = _targets(record)
            if len(targets) + len(event_targets) > MAX_TARGETS:
                raise ValueError("The upload exceeds 2,000 targets.")
            event = _object(EVENT, (identifier,), values)
            if observed is not None:
                event.first_seen = event.last_seen = observed
            else:
                missing_timestamps += 1
            _reference(event, source, "extracted-from", f"Okta System Log record {index}")
            for target in event_targets:
                child = _object(TARGET, (event.uuid, target["target-index"]), target)
                _reference(event, child, "contains", f"target[{target['target-index'] - 1}]")
                targets.append(child)
            related_links += _link_related(event, values, event_targets, anchors)
            events.append(event)
        except (ValueError, OverflowError) as error:
            raise ValueError(f"Record {index}: {error}") from error

    warnings = []
    if missing_timestamps:
        warnings.append(f"{missing_timestamps} records did not report a published timestamp.")
    return {
        "results": {"Object": [json.loads(obj.to_json(strict=True)) for obj in [source, *events, *targets]]},
        "summary": {
            "format": format_,
            "records": len(records),
            "events": len(events),
            "duplicate_records": len(records) - len(events),
            "targets": len(targets),
            "related_event_links": related_links,
            "source_sha256": digest,
            "source_attached": attach,
        },
        "warnings": warnings,
    }


def handler(q=False):
    if q is False:
        return False
    try:
        return _import(json.loads(q))
    except (binascii.Error, UnicodeError, json.JSONDecodeError, OSError, EOFError, zlib.error, RecursionError):
        return {"error": "Unable to decode the upload. Supply Okta System Log UTF-8 JSON or gzip."}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import Okta System Log events. Check the request and object templates."}
    except ValueError as error:
        return {"error": f"Unable to import Okta System Log events: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {"include_source": {"type": "Boolean", "message": "Attach the exact source audit log"}},
    }


def version():
    return dict(moduleinfo, config=[])
