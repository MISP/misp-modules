"""Import operator-supplied native Google Cloud Audit Logs."""

import base64
import binascii
import gzip
import hashlib
import ipaddress
import json
import re
import zlib
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO
from urllib.parse import unquote
from uuid import UUID, uuid5

from pymisp import MISPObject
from pymisp.exceptions import PyMISPError

from misp_modules.lib.network_observation import dumps, loads

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Google Cloud Audit Logs Import",
    "description": "Import native Google Cloud Audit Logs with authorization decisions and IAM binding changes.",
    "module-type": ["import"],
    "data-source": "internal",
    "requirements": ["PyMISP"],
    "features": (
        "Reads saved Cloud Logging LogEntry JSON, including gcloud arrays and Logging API pages. Maps principals,"
        " services, methods, resources, status codes, permission checks and IAM binding changes. Links each imported"
        " event to the source file and optionally attaches the exact upload. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/google_cloud_audit_import.md)."
    ),
    "references": [
        "https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs",
        "https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog",
        "https://docs.cloud.google.com/iam/docs/review-iam-policy-history",
    ],
    "input": "A Google Cloud Logging LogEntry, JSON array or entries.list response, optionally gzip-compressed.",
    "output": "A source file and linked Google Cloud audit events, permission checks and IAM binding changes.",
}

MAX_UPLOAD = 10 * 1024 * 1024
MAX_JSON = 20 * 1024 * 1024
MAX_RECORDS = 1000
MAX_DETAILS = 2000
MAX_TEXT = 4096
NAMESPACE = UUID("7b9a248e-aa1a-4521-8e4c-aac4166eae62")
AUDIT_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"
LOG_PREFIX = "cloudaudit.googleapis.com/"
LOG_CATEGORIES = {"activity", "data_access", "system_event", "policy"}
LOG_SCOPE = re.compile(r"(?P<kind>projects|folders|organizations|billingAccounts)/(?P<uid>[^/\s]+)")
TIMESTAMP = re.compile(
    r"(?P<seconds>[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<offset>[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
PAYLOAD_FIELDS = {"serviceName": "service-name", "methodName": "method-name", "resourceName": "resource-name"}
AUTHENTICATION_FIELDS = {"principalEmail": "principal-email", "principalSubject": "principal-subject"}
REQUEST_FIELDS = {
    "callerIp": "caller-address",
    "callerSuppliedUserAgent": "user-agent",
    "callerNetwork": "caller-network",
}
RESOURCE_LABEL_FIELDS = {"project_id": "monitored-project-id", "location": "location", "zone": "zone"}


@lru_cache(maxsize=3)
def _template(name):
    return json.loads(
        resources.files("misp_modules").joinpath("data", "google-cloud-audit", name, "definition.json").read_text()
    )


def _uuid(namespace, *parts):
    encoded = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    return str(uuid5(namespace, encoded))


def _add(obj, relation, value, *, key=None, **kwargs):
    attr = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
    attr.uuid = _uuid(UUID(obj.uuid), relation, key)


def _object(name, identity, values):
    options = {} if name == "file" else {"misp_objects_template_custom": _template(name)}
    obj = MISPObject(name, strict=True, standalone=False, **options)
    obj.uuid = _uuid(NAMESPACE, name, *identity)
    for relation, value in values.items():
        _add(obj, relation, value)
    return obj


def _reference(obj, target, relationship, comment):
    ref = obj.add_reference(target.uuid, relationship, comment)
    ref.uuid = _uuid(UUID(obj.uuid), relationship, target.uuid)


def _text(value, field, *, multiline=False):
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise ValueError(f"{field} must be nonempty text of at most 4,096 characters.")
    if any((not c.isprintable() and not (multiline and c in "\r\n\t")) or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError(f"{field} contains unsupported characters.")
    return value


def _fields(record, fields):
    values = {}
    for field, relation in fields.items():
        value = record.get(field)
        if value not in (None, ""):
            values[relation] = _text(value, field)
    return values


def _mapping(record, field):
    value = record.get(field)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object.")
    return value


def _array(record, field):
    value = record.get(field)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array.")
    if len(value) > MAX_DETAILS:
        raise ValueError(f"{field} exceeds 2,000 entries.")
    if any(not isinstance(item, dict) for item in value):
        raise ValueError(f"Every {field} entry must be an object.")
    return value


def _include_source(request):
    config = request.get("config")
    if config is None:
        return False
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    setting = config.get("include_source")
    if isinstance(setting, str):
        setting = setting.strip().lower()
        if setting in ("", "no", "false", "0"):
            return False
        if setting in ("yes", "true", "1"):
            return True
    if setting is None or isinstance(setting, bool):
        return bool(setting)
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
        raise ValueError("Decoded audit log exceeds 20 MiB.")

    filename = request.get("filename")
    if filename in (None, ""):
        filename = "google-cloud-audit.json.gz" if compressed else "google-cloud-audit.json"
    if not isinstance(filename, str):
        raise ValueError("filename must be text.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255 or not filename.isprintable():
        raise ValueError("Provide a printable basename of at most 255 characters.")
    return raw, filename, payload


def _records(payload):
    document = loads(payload.decode("utf-8-sig"))
    if isinstance(document, list):
        entries, format_, next_page = document, "gcloud-array", False
    elif isinstance(document, dict) and "logName" in document:
        entries, format_, next_page = [document], "log-entry", False
    elif isinstance(document, dict) and ("entries" in document or "nextPageToken" in document):
        entries = document.get("entries", [])
        token = document.get("nextPageToken")
        if token is not None and not isinstance(token, str):
            raise ValueError("nextPageToken must be a string.")
        format_, next_page = "logging-api", bool(token)
    else:
        raise ValueError("Expected a LogEntry, gcloud JSON array, or Logging API entries.list response.")
    if not isinstance(entries, list) or len(entries) > MAX_RECORDS:
        raise ValueError("The upload must contain a JSON array of at most 1,000 events.")
    if not entries:
        if next_page:
            raise ValueError("This response has no entries and reports another page. Import the saved next page.")
        raise ValueError("The upload contains no audit entries.")
    return entries, format_, next_page


def _timestamp(value, field):
    raw = _text(value, field)
    match = TIMESTAMP.fullmatch(raw)
    if not match or match["offset"] == "-00:00":
        raise ValueError(f"{field} needs RFC 3339 seconds, at most nine fractional digits, and a known UTC offset.")
    seconds = match["seconds"].upper()
    offset = "+00:00" if match["offset"].upper() == "Z" else match["offset"]
    try:
        instant = datetime.fromisoformat(seconds + offset).astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise ValueError(f"{field} is outside the supported calendar or UTC offset.") from error
    fractions = (match["fraction"] or "").ljust(9, "0")
    return instant.replace(microsecond=int(fractions[:6])), fractions


def _log_name(entry):
    name = _text(entry.get("logName"), "logName")
    parent, separator, encoded = name.partition("/logs/")
    scope = LOG_SCOPE.fullmatch(parent)
    if not separator or scope is None:
        raise ValueError("logName must identify the Google Cloud scope and native audit log.")
    log_id = unquote(encoded, errors="strict")
    category = log_id.removeprefix(LOG_PREFIX)
    if not log_id.startswith(LOG_PREFIX) or category not in LOG_CATEGORIES:
        raise ValueError("logName does not identify a Google Cloud Audit Logs category.")
    return {
        "log-name": name,
        "log-category": category,
        "scope-type": scope["kind"],
        "scope-id": scope["uid"],
    }


def _principal_chain(auth):
    values = []
    for item in _array(auth, "serviceAccountDelegationInfo"):
        delegated = _fields(item, {"principalSubject": "principalSubject"})
        first_party = _mapping(item, "firstPartyPrincipal")
        delegated.update(_fields(first_party, {"principalEmail": "principalEmail"}))
        values.append(delegated)
    return values


def _source_ip(value):
    if value and "%" not in value:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    return None


def _event_values(entry):
    if not isinstance(entry, dict):
        raise ValueError("Every LogEntry must be an object.")
    values = _log_name(entry)
    payload = _mapping(entry, "protoPayload")
    if payload.get("@type") != AUDIT_TYPE:
        raise ValueError("protoPayload must be a google.cloud.audit.AuditLog.")

    observed = instant_key = None
    if entry.get("timestamp") is not None:
        observed, fraction = _timestamp(entry["timestamp"], "timestamp")
        values["event-time"] = observed.isoformat()
        values["event-time-raw"] = entry["timestamp"]
        instant_key = observed.replace(microsecond=0).isoformat() + "/" + fraction
    if entry.get("receiveTimestamp") is not None:
        received, _ = _timestamp(entry["receiveTimestamp"], "receiveTimestamp")
        values["received-time"] = received.isoformat()
        values["received-time-raw"] = entry["receiveTimestamp"]

    values.update(_fields(entry, {"insertId": "insert-id", "severity": "severity"}))
    values.update(_fields(payload, PAYLOAD_FIELDS))
    auth = _mapping(payload, "authenticationInfo")
    values.update(_fields(auth, AUTHENTICATION_FIELDS))
    values.update(_fields(_mapping(payload, "requestMetadata"), REQUEST_FIELDS))
    if ip := _source_ip(values.get("caller-address")):
        values["source-ip"] = ip
    resource = _mapping(entry, "resource")
    values.update(_fields(resource, {"type": "monitored-resource-type"}))
    values.update(_fields(_mapping(resource, "labels"), RESOURCE_LABEL_FIELDS))
    values.update(_fields(_mapping(entry, "operation"), {"id": "operation-id", "producer": "operation-producer"}))
    status = _mapping(payload, "status")
    if (code := status.get("code")) is not None:
        if type(code) is not int or not 0 <= code <= 2**31 - 1:
            raise ValueError("status.code must be a nonnegative int32.")
        values["status-code"] = code

    entry_id = values.get("insert-id")
    key = None
    if entry_id and instant_key:
        key = (values["scope-type"], values["scope-id"], values["log-category"], instant_key, entry_id)
    return values, observed, key, payload, _principal_chain(auth)


def _permission_values(check):
    granted = check.get("granted")
    if granted is not None and not isinstance(granted, bool):
        raise ValueError("authorizationInfo.granted must be a boolean.")
    decision = {True: "granted", False: "denied", None: "unknown"}[granted]
    values = {"decision": decision}
    values.update(
        _fields(check, {"permission": "permission", "resource": "resource-name", "permissionType": "permission-type"})
    )
    values.update(
        _fields(
            _mapping(check, "resourceAttributes"),
            {"name": "resource-attribute-name", "service": "resource-service", "type": "resource-type"},
        )
    )
    return values


def _binding_changes(payload):
    for branch in ("metadata", "serviceData"):
        policy = _mapping(_mapping(payload, branch), "policyDelta")
        for index, delta in enumerate(_array(policy, "bindingDeltas")):
            values = _fields(delta, {"action": "action", "role": "role", "member": "member"})
            if not values:
                raise ValueError("IAM binding delta needs an action, role or member.")
            condition = _mapping(delta, "condition")
            if condition:
                selected = {
                    field: _text(condition[field], f"condition.{field}", multiline=True)
                    for field in ("expression", "title", "description", "location")
                    if condition.get(field) not in (None, "")
                }
                if selected:
                    values["condition"] = dumps(selected)
            yield f"protoPayload.{branch}.policyDelta.bindingDeltas[{index}]", values


def _details(event, payload, chains):
    for index, principal in enumerate(chains):
        if principal:
            path = f"protoPayload.authenticationInfo.serviceAccountDelegationInfo[{index}]"
            _add(event, "delegation-principal", dumps(principal), key=index, comment=path)
    for index, check in enumerate(_array(payload, "authorizationInfo")):
        path = f"protoPayload.authorizationInfo[{index}]"
        yield "google-cloud-authorization-check", path, _permission_values(check)
    for path, values in _binding_changes(payload):
        yield "google-cloud-iam-binding-change", path, values


def _import(request):
    if not isinstance(request, dict):
        raise ValueError("Expected an import request object.")
    attach = _include_source(request)
    raw, filename, payload = _upload(request)
    entries, format_, next_page = _records(payload)
    digest = hashlib.sha256(raw).hexdigest()
    source = _object("file", (digest, filename), {"filename": filename, "sha256": digest, "size-in-bytes": len(raw)})
    if attach:
        _add(source, "attachment", filename, data=BytesIO(raw))

    events, details, seen = [], [], {}
    categories = Counter()
    counts = Counter()
    budget = MAX_DETAILS
    missing_timestamps = 0
    for index, entry in enumerate(entries, 1):
        try:
            values, observed, key, audit, chains = _event_values(entry)
            if key is not None:
                fingerprint = hashlib.sha256(dumps(entry).encode("ascii")).digest()
                if key in seen:
                    if seen[key] != fingerprint:
                        raise ValueError("Conflicting entries share the same scope, audit log, timestamp and insertId.")
                    continue
                seen[key] = fingerprint
            identity = key if key is not None else (source.uuid, index)
            event = _object("google-cloud-audit-event", identity, values)
            if observed is None:
                missing_timestamps += 1
            else:
                event.first_seen = event.last_seen = observed
            _reference(event, source, "extracted-from", f"Google Cloud LogEntry {index}")
            budget -= len(chains)
            if budget < 0:
                raise ValueError("Upload exceeds 2,000 detail records.")
            for name, path, fields in _details(event, audit, chains):
                if budget == 0:
                    raise ValueError("Upload exceeds 2,000 detail records.")
                budget -= 1
                child = _object(name, (event.uuid, path), fields)
                _reference(event, child, "contains", path)
                details.append(child)
                counts[name] += 1
            events.append(event)
            categories[values["log-category"]] += 1
        except (ValueError, OverflowError) as error:
            raise ValueError(f"Record {index}: {error}") from error

    warnings = ["The response reports another page. Import the remaining saved pages separately."] if next_page else []
    if missing_timestamps:
        warnings.append(f"{missing_timestamps} entries did not report an event timestamp.")
    return {
        "results": {"Object": [json.loads(obj.to_json(strict=True)) for obj in [source, *events, *details]]},
        "summary": {
            "format": format_,
            "records": len(entries),
            "events": len(events),
            "duplicate_records": len(entries) - len(events),
            "categories": dict(categories),
            "authorization_checks": counts["google-cloud-authorization-check"],
            "iam_binding_changes": counts["google-cloud-iam-binding-change"],
            "source_sha256": digest,
            "source_attached": attach,
            "has_next_page": next_page,
        },
        "warnings": warnings,
    }


def handler(q=False):
    if q is False:
        return False
    try:
        return _import(json.loads(q))
    except (binascii.Error, UnicodeError, json.JSONDecodeError, OSError, EOFError, zlib.error, RecursionError):
        return {"error": "Unable to decode the upload. Supply Google Cloud Audit Logs as UTF-8 JSON or gzip."}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import Google Cloud Audit Logs. Check the request and object templates."}
    except ValueError as error:
        return {"error": f"Unable to import Google Cloud Audit Logs: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {"include_source": {"type": "Boolean", "message": "Attach the exact source audit log"}},
    }


def version():
    return dict(moduleinfo, config=[])
