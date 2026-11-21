"""Import Microsoft Entra and Purview audit records from local exports."""

import base64
import binascii
import csv
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO, StringIO
from uuid import UUID, uuid5

from pymisp import MISPObject
from pymisp.exceptions import PyMISPError

moduleinfo = {
    "name": "Microsoft Identity and Audit Logs Import",
    "description": "Import Entra sign-in and directory audit logs and Microsoft Purview Unified Audit Log exports.",
    "version": "1.0",
    "author": "MISP Project",
    "module-type": ["import"],
    "requirements": ["PyMISP"],
    "features": (
        "Imports Entra sign-in and directory audit JSON and Purview Unified Audit Log JSON or AuditData CSV offline."
        " Maps actions, actors, tenant and session context, results and times to unreviewed MISP objects. Links"
        " observations to a SHA-256 source file descriptor and supports attaching the exact upload by request."
    ),
    "references": [
        "https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0",
        "https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0",
        "https://learn.microsoft.com/en-us/purview/audit-log-export-records",
        "https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/microsoft_audit_import.md",
    ],
    "input": "Base64-encoded UTF-8 Entra or Purview JSON, or a Purview CSV containing AuditData.",
    "output": "Microsoft audit event, source file and optional linked cloud account objects.",
}
MAX_UPLOAD = 10 * 1024 * 1024
MAX_RECORDS = 1000
MAX_TARGETS = 1000
NAMESPACE = UUID("5408461f-8355-4a73-813f-800de4f023b5")
TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(Z|[+-][0-9]{2}:[0-9]{2})?"
)
KINDS = {
    "createdDateTime": "entra-sign-in",
    "activityDateTime": "entra-directory-audit",
    "CreationTime": "purview-unified-audit",
}
SIGN_IN_FIELDS = {
    "userId": "actor-id",
    "userPrincipalName": "actor-upn",
    "appId": "application-id",
    "appDisplayName": "application-name",
    "servicePrincipalId": "service-principal-id",
    "resourceId": "resource-id",
    "resourceDisplayName": "resource-name",
    "sessionId": "session-id",
    "correlationId": "correlation-id",
    "homeTenantId": "home-tenant-id",
    "resourceTenantId": "resource-tenant-id",
    "conditionalAccessStatus": "conditional-access-status",
    "ipAddress": "source-address",
}
AUDIT_FIELDS = {
    "operationType": "operation-type",
    "category": "category",
    "loggedByService": "workload",
    "correlationId": "correlation-id",
    "result": "result-status",
}
PURVIEW_FIELDS = {
    "Workload": "workload",
    "UserId": "actor-id",
    "ObjectId": "resource-id",
    "SessionId": "session-id",
    "CorrelationId": "correlation-id",
    "ClientIP": "source-address",
    "ResultStatus": "result-status",
}
OUTCOMES = {
    "success": "success",
    "succeeded": "success",
    "true": "success",
    "failure": "failure",
    "failed": "failure",
    "false": "failure",
    "timeout": "timeout",
    "partiallysucceeded": "partial-success",
    "partially succeeded": "partial-success",
}


@lru_cache(maxsize=2)
def _template(name):
    path = resources.files("misp_modules").joinpath("data", "microsoft-audit", name, "definition.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _uuid(namespace, *parts):
    return str(uuid5(namespace, _json(parts)))


def _add(obj, relation, value, identity=None, **kwargs):
    attribute = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
    attribute.uuid = _uuid(UUID(str(obj.uuid)), relation, identity)


def _object(name, key, values):
    options = {} if name == "file" else {"misp_objects_template_custom": _template(name)}
    obj = MISPObject(name, strict=True, standalone=False, **options)
    obj.uuid = _uuid(NAMESPACE, name, *key)
    for relation, value in values.items():
        _add(obj, relation, value)
    return obj


def _reference(obj, target, relationship, comment):
    ref = obj.add_reference(target.uuid, relationship, comment)
    ref.uuid = _uuid(UUID(str(obj.uuid)), relationship, str(target.uuid))


def _json_pairs(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("Export JSON contains a duplicate key.")
    return value


def _invalid_constant(_):
    raise ValueError("Export JSON contains a non-finite number.")


def _loads(payload):
    return json.loads(payload, object_pairs_hook=_json_pairs, parse_constant=_invalid_constant)


def _text(value, field):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096 or not value.isprintable():
        raise ValueError(f"{field} must be nonempty printable text of at most 4,096 characters.")
    return value


def _fields(record, mapping):
    return {
        relation: _text(record[field], field)
        for field, relation in mapping.items()
        if record.get(field) not in ("", None)
    }


def _mapping(record, field):
    value = record.get(field)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object.")
    return value


def _guid(value, field):
    text = _text(value, field)
    try:
        identifier = str(UUID(text))
    except ValueError:
        raise ValueError(f"{field} must be a hyphenated UUID.") from None
    if identifier != text.lower():
        raise ValueError(f"{field} must be a hyphenated UUID.")
    return identifier


def _tenant(record, supplied, field):
    value = record.get(field)
    recorded = _guid(value, field) if value not in ("", None) else None
    if supplied and recorded and supplied != recorded:
        raise ValueError("The source tenant differs from the configured tenant_id.")
    return recorded or supplied


def _time(value, name, implicit_utc=False):
    raw = _text(value, name)
    match = TIMESTAMP.fullmatch(raw)
    if not match or raw.endswith("-00:00") or (not match[1] and not implicit_utc):
        raise ValueError(f"{name} requires ISO 8601 seconds and a known timezone.")
    zone = match[1]
    if zone and zone != "Z" and (int(zone[1:3]) > 23 or int(zone[4:]) > 59):
        raise ValueError(f"{name} has an invalid UTC offset.")
    if not zone:
        raw += "+00:00"
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)


def _normalize_ip(address):
    if not address or "%" in address:
        return None
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        pass
    match = re.fullmatch(r"(?:\[([0-9a-fA-F.:]+)\]|([0-9.]+)):([0-9]{1,5})", address)
    if not match or int(match[3]) > 65535:
        return None
    try:
        return str(ipaddress.ip_address(match[1] or match[2]))
    except ValueError:
        return None


def _options(request):
    config = request.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    tenant = config.get("tenant_id")
    tenant = None if tenant in (None, "") else _guid(tenant, "tenant_id")
    attach = config.get("include_source")
    if isinstance(attach, str):
        attach = attach.strip().lower()
        if attach in ("true", "yes", "1"):
            return tenant, True
        if attach in ("", "false", "no", "0"):
            return tenant, False
    if attach is None or isinstance(attach, bool):
        return tenant, bool(attach)
    raise ValueError("include_source must be a boolean.")


def _upload(request):
    encoded = request.get("data")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_UPLOAD + 2) // 3):
        raise ValueError("data requires a base64 upload of at most 10 MiB.")
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > MAX_UPLOAD:
        raise ValueError("Upload must be nonempty and at most 10 MiB.")
    return raw


def _filename(filename, format_):
    if filename in (None, ""):
        filename = f"microsoft-audit.{format_}"
    if not isinstance(filename, str):
        raise ValueError("filename must be text.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255 or not filename.isprintable():
        raise ValueError("filename requires a printable basename of at most 255 characters.")
    return filename


def _read_csv(payload):
    rows = csv.reader(StringIO(payload, newline=""), strict=True)
    header = next(rows, [])
    if "AuditData" not in header or len(header) > 128 or len(header) != len(set(header)):
        raise ValueError("Expected a Purview CSV with a unique AuditData column and at most 128 columns.")
    index = header.index("AuditData")
    records = []
    for row in rows:
        if not row:
            continue
        if len(row) != len(header):
            raise ValueError("Purview CSV row has the wrong number of columns.")
        if len(records) >= MAX_RECORDS:
            raise ValueError("Export exceeds 1,000 audit records.")
        records.append(_loads(row[index]))
    return records


def _read(raw):
    payload = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
    if not payload.lstrip().startswith(("{", "[")):
        return _read_csv(payload), "csv", False
    doc = _loads(payload)
    if isinstance(doc, list):
        return doc, "json", False
    if isinstance(doc, dict) and "value" in doc:
        return doc["value"], "json", bool(doc.get("@odata.nextLink"))
    return [doc], "json", False


def _classify(record, format_):
    if not isinstance(record, dict):
        raise ValueError("Each audit record must be a JSON object.")
    matches = [field for field in KINDS if field in record]
    if len(matches) != 1 or (format_ == "csv" and matches[0] != "CreationTime"):
        raise ValueError("Expected an Entra sign-in, Entra directory audit, or Purview audit record.")
    field = matches[0]
    if field == "createdDateTime":
        markers = (
            "status",
            "appId",
            "ipAddress",
            "isInteractive",
            "signInEventTypes",
            "sessionId",
            "servicePrincipalId",
        )
        known_type = record.get("@odata.type") == "#microsoft.graph.signIn"
        if (not known_type and not any(key in record for key in markers)) or "auditData" in record:
            raise ValueError("Expected native Entra sign-in fields.")
    return field, KINDS[field]


def _sign_in(record):
    values = _fields(record, SIGN_IN_FIELDS)
    if "actor-id" not in values and "actor-upn" not in values and "service-principal-id" in values:
        values["actor-id"] = values["service-principal-id"]
    status = _mapping(record, "status")
    code = status.get("errorCode")
    values["outcome"] = "unknown"
    if code is not None:
        if not isinstance(code, int) or isinstance(code, bool):
            raise ValueError("status.errorCode must be an integer.")
        values["result-code"] = str(code)
        values["outcome"] = "success" if code == 0 else "failure"
    if record.get("TimeGenerated") not in (None, ""):
        raw = _text(record["TimeGenerated"], "TimeGenerated")
        values["ingestion-time-raw"] = raw
        values["ingestion-time"] = _time(raw, "TimeGenerated").isoformat()
    if record.get("isInteractive") is not None:
        if not isinstance(record["isInteractive"], bool):
            raise ValueError("isInteractive must be a JSON boolean.")
        values["interactive"] = record["isInteractive"]
    return values


def _directory_audit(record):
    values = _fields(record, AUDIT_FIELDS)
    values["outcome"] = OUTCOMES.get(values.get("result-status", "").casefold(), "unknown")
    initiated = _mapping(record, "initiatedBy")
    user = _fields(
        _mapping(initiated, "user"), {"id": "actor-id", "userPrincipalName": "actor-upn", "ipAddress": "source-address"}
    )
    app = _fields(
        _mapping(initiated, "app"),
        {"appId": "application-id", "displayName": "application-name", "servicePrincipalId": "service-principal-id"},
    )
    values.update(user)
    values.update(app)
    if "actor-id" not in values and "service-principal-id" in values:
        values["actor-id"] = values["service-principal-id"]
    return values


def _purview(record, operation):
    values = _fields(record, PURVIEW_FIELDS)
    record_type = record.get("RecordType")
    if isinstance(record_type, int) and not isinstance(record_type, bool):
        values["record-type"] = str(record_type)
    elif record_type not in (None, ""):
        values["record-type"] = _text(record_type, "RecordType")
    sts = values.get("record-type", "").casefold() in {"15", "azureactivedirectorystslogon"} or (
        values.get("workload", "").casefold() == "azureactivedirectory"
        and operation.casefold() in {"userloggedin", "userloginfailed"}
    )
    if sts:
        error = record.get("LogonError")
        fails = isinstance(error, str) and error.strip().casefold() not in {"", "0", "none"}
        values["outcome"] = "failure" if fails else "unknown"
    else:
        values["outcome"] = OUTCOMES.get(values.get("result-status", "").casefold(), "unknown")
    return values


def _targets(record):
    targets = record.get("targetResources")
    if targets is None:
        return []
    if not isinstance(targets, list) or len(targets) > MAX_TARGETS:
        raise ValueError("targetResources must be an array of at most 1,000 objects.")
    return targets


def _audit_event(record, supplied_tenant, format_):
    timestamp_field, kind = _classify(record, format_)
    purview = kind == "purview-unified-audit"
    record_id = _text(record.get("Id" if purview else "id"), "audit record ID")
    raw_time = _text(record[timestamp_field], timestamp_field)
    event_time = _time(raw_time, timestamp_field, implicit_utc=purview)
    tenant = _tenant(record, supplied_tenant, "OrganizationId" if purview else "tenantId")
    if purview:
        operation = _text(record.get("Operation"), "Operation")
        values = _purview(record, operation)
    elif kind == "entra-directory-audit":
        operation = _text(record.get("activityDisplayName"), "activityDisplayName")
        values = _directory_audit(record)
    else:
        operation, values = "Sign-in", _sign_in(record)
    values.update(
        {
            "record-id": record_id,
            "log-type": kind,
            "operation": operation,
            "event-time": event_time.isoformat(),
            "event-time-raw": raw_time,
            "review-status": "unreviewed",
        }
    )
    if tenant:
        values["tenant-id"] = tenant
    ip = _normalize_ip(values.get("source-address"))
    if ip:
        values["source-ip"] = ip
    key = (kind, tenant, record_id)
    obj = _object("microsoft-audit-event", key, values)
    obj.first_seen = event_time
    obj.last_seen = event_time
    return key, obj


def _add_targets(obj, targets):
    seen = set()
    for entry in targets:
        if not isinstance(entry, dict):
            raise ValueError("Each targetResources entry must be an object.")
        fields = _fields(entry, {key: key for key in ("id", "type", "displayName", "userPrincipalName")})
        if fields:
            value = _json(fields)
            if value not in seen:
                _add(obj, "target-resource", value, identity=value)
                seen.add(value)


def _import(request):
    if not isinstance(request, dict):
        raise ValueError("Expected an import request object.")
    supplied_tenant, attach = _options(request)
    raw = _upload(request)
    records, format_, more_pages = _read(raw)
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError("Export must contain 1 to 1,000 audit records.")
    filename = _filename(request.get("filename"), format_)
    digest = hashlib.sha256(raw).hexdigest()
    source = _object("file", (digest,), {"filename": filename, "size-in-bytes": len(raw), "sha256": digest})
    if attach:
        _add(source, "attachment", filename, data=BytesIO(raw))

    events, tenants, seen = [], {}, {}
    target_count = 0
    for index, record in enumerate(records, 1):
        try:
            key, obj = _audit_event(record, supplied_tenant, format_)
            fingerprint = hashlib.sha256(_json(record).encode("ascii")).digest()
            if key in seen:
                if seen[key] != fingerprint:
                    raise ValueError("Conflicting records share the same log type, tenant and record ID.")
                continue
            seen[key] = fingerprint
            kind, tenant, _ = key
            if kind == "entra-directory-audit":
                targets = _targets(record)
                target_count += len(targets)
                if target_count > MAX_TARGETS:
                    raise ValueError("Export exceeds 1,000 directory audit target entries.")
                _add_targets(obj, targets)
            _reference(obj, source, "extracted-from", f"Audit record {index}")
            if tenant:
                if tenant not in tenants:
                    tenants[tenant] = _object(
                        "cloud-account", (tenant,), {"provider": "Microsoft", "account-id": tenant}
                    )
                _reference(obj, tenants[tenant], "related-to", "Reporting Microsoft tenant")
            events.append(obj)
        except (ValueError, OverflowError) as error:
            raise ValueError(f"Record {index}: {error}") from None
    return {
        "results": {"Object": [json.loads(obj.to_json()) for obj in [source, *events, *tenants.values()]]},
        "summary": {
            "records": len(records),
            "events": len(events),
            "duplicate_records": len(records) - len(events),
            "source_sha256": digest,
            "source_attached": attach,
        },
        "warnings": ["Graph export has a next page. Import additional saved pages separately."] if more_pages else [],
    }


def handler(q=False):
    if q is False:
        return False
    try:
        return _import(json.loads(q))
    except (binascii.Error, UnicodeError, json.JSONDecodeError, csv.Error, RecursionError):
        return {"error": "Unable to decode Microsoft audit upload. Supply valid JSON or AuditData CSV."}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import Microsoft audit logs. Check the request and object templates."}
    except ValueError as error:
        return {"error": f"Unable to import Microsoft audit logs: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "tenant_id": {"type": "String", "message": "Optional reporting tenant UUID"},
            "include_source": {
                "type": "Boolean",
                "message": "Attach the exact source log (may contain sensitive data)",
            },
        },
    }


def version():
    return dict(moduleinfo, config=[])
