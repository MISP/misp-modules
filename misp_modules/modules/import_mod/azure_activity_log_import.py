"""Import operator-supplied Azure Resource Manager Activity Log records."""

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
from uuid import UUID, uuid5

from pymisp import MISPObject
from pymisp.exceptions import PyMISPError

from misp_modules.lib.network_observation import dumps, loads

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Azure Activity Log Import",
    "description": "Import Azure Resource Manager Activity Log evidence from local JSON exports.",
    "module-type": ["import"],
    "data-source": "internal",
    "requirements": ["PyMISP"],
    "features": (
        "Reads Azure CLI, REST, Azure Monitor diagnostic and AzureActivity Log Analytics JSON. Keeps caller, resource,"
        " operation, result and correlation identifiers with the source file. Preserves actor authorization and"
        " explicit role-assignment targets. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/azure_activity_log_import.md)."
    ),
    "references": [
        "https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-schema",
        "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity",
        "https://learn.microsoft.com/en-us/azure/role-based-access-control/change-history-report",
    ],
    "input": "Saved Azure Activity Log JSON, optionally gzip-compressed.",
    "output": "A source file object and linked azure-activity-log-event objects.",
}

MAX_UPLOAD = 10 * 1024 * 1024
MAX_JSON = 20 * 1024 * 1024
MAX_RECORDS = 1000
MAX_COLUMNS = 128
MAX_TEXT = 4096
TEMPLATE = "azure-activity-log-event"
NAMESPACE = UUID("69411550-885f-4b55-8ff3-180c7fd2198f")
TIME = re.compile(
    r"(?P<second>[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<offset>[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
ARM_SUBSCRIPTION = re.compile(r"^/subscriptions/([^/\s]+)(?:/|$)", re.IGNORECASE)
ARM_ENTITY = re.compile(r"^/(?:subscriptions|providers|tenants|resourceGroups)/[^/\s]+", re.IGNORECASE)
ARM_OPERATION = re.compile(r"[^/\s]+\.[^/\s]+(?:/[^/\s]+)+")
ACTIVITY_CATEGORIES = {
    "administrative",
    "alert",
    "autoscale",
    "policy",
    "recommendation",
    "resourcehealth",
    "security",
    "servicehealth",
}
DIAGNOSTIC_ACTIONS = {"action", "delete", "read", "write"}
ROLE_ASSIGNMENT_OPERATIONS = {
    "microsoft.authorization/roleassignments/write",
    "microsoft.authorization/roleassignments/delete",
}
IDENTITY_URI = "http://schemas.microsoft.com/identity/claims/"
CLAIM_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/"
CALLER_CLAIMS = (
    "upn",
    CLAIM_URI + "upn",
    "preferred_username",
    "unique_name",
    CLAIM_URI + "name",
    "oid",
    IDENTITY_URI + "objectidentifier",
)

ARM_FIELDS = {
    "eventDataId": "event-id",
    "id": "event-record-id",
    "eventName": "event-name",
    "caller": "caller",
    "operationName": "operation",
    "resourceId": "resource-id",
    "resourceGroupName": "resource-group",
    "resourceProviderName": "resource-provider",
    "resourceType": "resource-type",
    "subscriptionId": "subscription-id",
    "tenantId": "tenant-id",
    "category": "category",
    "level": "level",
    "status": "result",
    "subStatus": "result-detail",
    "correlationId": "correlation-id",
    "operationId": "operation-id",
}
DIAGNOSTIC_FIELDS = {
    "eventDataId": "event-id",
    "caller": "caller",
    "operationName": "operation",
    "resourceId": "resource-id",
    "subscriptionId": "subscription-id",
    "tenantId": "tenant-id",
    "category": "diagnostic-category",
    "level": "level",
    "resultType": "result",
    "resultSignature": "result-signature",
    "correlationId": "correlation-id",
    "operationId": "operation-id",
}
ANALYTICS_FIELDS = {
    "EventDataId": "event-id",
    "Caller": "caller",
    "CallerIpAddress": "caller-address",
    "OperationNameValue": "operation",
    "ResourceId": "resource-id",
    "ResourceGroup": "resource-group",
    "ResourceProviderValue": "resource-provider",
    "SubscriptionId": "subscription-id",
    "TenantId": "workspace-id",
    "CategoryValue": "category",
    "Level": "level",
    "ActivityStatusValue": "result",
    "ActivitySubstatusValue": "result-detail",
    "CorrelationId": "correlation-id",
    "OperationId": "operation-id",
}
AUTHORIZATION_FIELDS = {"action": "authorization-action", "scope": "authorization-scope", "role": "authorization-role"}
EVIDENCE_FIELDS = {
    "role": "authorization-role",
    "roleAssignmentId": "authorization-role-assignment-id",
    "roleAssignmentScope": "authorization-role-assignment-scope",
    "roleDefinitionId": "authorization-role-definition-id",
    "principalId": "authorization-principal-id",
    "principalType": "authorization-principal-type",
}
ASSIGNMENT_FIELDS = {
    "principalid": "assigned-principal-id",
    "principaltype": "assigned-principal-type",
    "roledefinitionid": "assigned-role-definition-id",
    "scope": "assignment-scope",
}
TIME_FIELDS = {
    "arm": ("eventTimestamp", "submissionTimestamp"),
    "azure-monitor": ("time", None),
    "log-analytics": ("TimeGenerated", "EventSubmissionTimestamp"),
}


@lru_cache(maxsize=1)
def _template():
    definition = resources.files("misp_modules").joinpath("data", TEMPLATE, "definition.json")
    return json.loads(definition.read_text(encoding="utf-8"))


def _uuid(namespace, *parts):
    return str(uuid5(namespace, json.dumps(parts, ensure_ascii=True, separators=(",", ":"))))


def _add(obj, relation, value, **kwargs):
    attr = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
    attr.uuid = _uuid(UUID(obj.uuid), relation)


def _object(name, identity, values):
    options = {} if name == "file" else {"misp_objects_template_custom": _template()}
    obj = MISPObject(name, strict=True, standalone=False, **options)
    obj.uuid = _uuid(NAMESPACE, name, *identity)
    for relation, value in values.items():
        _add(obj, relation, value)
    return obj


def _text(value, field):
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT or not value.isprintable():
        raise ValueError(f"{field} must be nonempty printable text of at most 4,096 characters.")
    return value


def _scalar(value, field):
    if isinstance(value, dict):
        value = value.get("value") or value.get("localizedValue")
    return _text(value, field) if value not in (None, "") else None


def _fields(record, names):
    result = {}
    for field, relation in names.items():
        if (value := _scalar(record.get(field), field)) is not None:
            result[relation] = value
    return result


def _mapping(value, field):
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        try:
            value = loads(value)
        except ValueError as error:
            raise ValueError(f"{field} must be an object or a JSON-encoded object.") from error
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object or a JSON-encoded object.")
    return value


def _dynamic(record, column):
    dynamic = column + "_d"
    if value := _mapping(record.get(dynamic), dynamic):
        return value, dynamic
    return _mapping(record.get(column), column), column


def _timestamp(value, field):
    raw = _text(value, field)
    match = TIME.fullmatch(raw)
    if not match or match["offset"] == "-00:00":
        raise ValueError(f"{field} needs an offset-aware ISO 8601 timestamp with at most nine fractional digits.")
    offset = "+00:00" if match["offset"].upper() == "Z" else match["offset"]
    try:
        date = datetime.fromisoformat(match["second"].upper() + offset).astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise ValueError(f"{field} is outside the supported calendar or UTC offset.") from error
    microseconds = int((match["fraction"] or "").ljust(6, "0")[:6])
    return date.replace(microsecond=microseconds)


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
    data = request.get("data")
    if not isinstance(data, str) or len(data) > 4 * ((MAX_UPLOAD + 2) // 3):
        raise ValueError("Provide a base64 upload of at most 10 MiB.")
    raw = base64.b64decode(data, validate=True)
    if not raw or len(raw) > MAX_UPLOAD:
        raise ValueError("Upload must contain between 1 byte and 10 MiB.")
    compressed = raw.startswith(b"\x1f\x8b")
    if compressed:
        with gzip.GzipFile(fileobj=BytesIO(raw)) as archive:
            data = archive.read(MAX_JSON + 1)
    else:
        data = raw
    if len(data) > MAX_JSON:
        raise ValueError("Decoded Activity Log upload exceeds 20 MiB.")
    filename = request.get("filename")
    if filename in (None, ""):
        filename = "azure-activity.json.gz" if compressed else "azure-activity.json"
    filename = _text(filename, "filename").replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255:
        raise ValueError("Provide a printable basename of at most 255 characters.")
    return raw, filename, loads(data.decode("utf-8-sig"))


def _analytics_rows(tables):
    if not isinstance(tables, list) or len(tables) != 1 or not isinstance(tables[0], dict):
        raise ValueError("Provide one AzureActivity result table.")
    table = tables[0]
    columns, rows = table.get("columns"), table.get("rows")
    if not isinstance(columns, list) or not 1 <= len(columns) <= MAX_COLUMNS:
        raise ValueError("A Log Analytics result must have 1 to 128 columns.")
    names = [_text(item.get("name") if isinstance(item, dict) else None, "column name") for item in columns]
    if len(set(names)) != len(names):
        raise ValueError("The Log Analytics result has duplicate columns.")
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise ValueError("The Log Analytics result must contain at most 1,000 rows.")
    if any(not isinstance(row, list) or len(row) != len(names) for row in rows):
        raise ValueError("Every Log Analytics row must match its declared columns.")
    return [dict(zip(names, row)) for row in rows]


def _records(document):
    next_page, expected = False, None
    if isinstance(document, list):
        rows, format_ = document, "json-array"
    elif isinstance(document, dict):
        if "value" in document:
            rows, format_, expected = document["value"], "rest-response", "arm"
            next_link = document.get("nextLink")
            if next_link is not None and not isinstance(next_link, str):
                raise ValueError("nextLink must be a string.")
            next_page = bool(next_link)
        elif "records" in document:
            rows, format_, expected = document["records"], "diagnostic-envelope", "azure-monitor"
        elif "tables" in document:
            rows, format_, expected = _analytics_rows(document["tables"]), "log-analytics-response", "log-analytics"
        else:
            rows, format_ = [document], "event"
    else:
        raise ValueError("Expected an Azure Activity Log JSON object or array.")
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise ValueError("The upload must contain a JSON array of at most 1,000 events.")
    if not rows:
        if next_page:
            raise ValueError("The REST response has no events and reports another page.")
        raise ValueError("The upload contains no Azure Activity Log events.")
    return rows, format_, expected, next_page


def _schema(record):
    if not isinstance(record, dict):
        raise ValueError("Every Activity Log record must be an object.")
    if "operationName" in record and (
        "eventTimestamp" in record or "eventDataId" in record or "submissionTimestamp" in record
    ):
        return "arm"
    # Azure CLI projections can retain authorization.action without operationName.
    if "eventTimestamp" in record and "authorization" in record:
        action = _mapping(record["authorization"], "authorization").get("action")
        if isinstance(action, str) and ARM_OPERATION.fullmatch(action):
            return "arm"
    if (
        record.get("Type") in (None, "AzureActivity")
        and "TimeGenerated" in record
        and (record.get("Type") == "AzureActivity" or "OperationNameValue" in record and "EventDataId" in record)
    ):
        return "log-analytics"
    if (
        "time" in record
        and isinstance(record.get("operationName"), str)
        and ARM_OPERATION.fullmatch(record["operationName"])
    ):
        category = _scalar(record.get("category"), "category") or ""
        props = _mapping(record.get("properties"), "properties")
        native = _scalar(props.get("eventCategory"), "properties.eventCategory") or ""
        if native.casefold() in ACTIVITY_CATEGORIES or category.casefold() in ACTIVITY_CATEGORIES | DIAGNOSTIC_ACTIONS:
            return "azure-monitor"
    raise ValueError("Record does not match a supported Azure Activity Log schema.")


def _principal(claims, values, claim_path, caller_path):
    for keys, relation in (
        (("oid", IDENTITY_URI + "objectidentifier"), "caller-object-id"),
        (("tid", IDENTITY_URI + "tenantid"), "caller-tenant-id"),
        (("appid", "azp"), "caller-application-id"),
    ):
        for key in keys:
            if value := _scalar(claims.get(key), key):
                values[relation] = value
                break
    if "caller" in values:
        values["caller-source"] = caller_path
        return
    for key in CALLER_CLAIMS:
        if value := _scalar(claims.get(key), key):
            values.update({"caller": value, "caller-source": f"{claim_path}.{key}"})
            return


def _role_assignment(props, operation):
    if operation.casefold() not in ROLE_ASSIGNMENT_OPERATIONS:
        return {}
    request_values = {}
    # Request and response bodies use different casing between producers.
    for field, body in props.items():
        if field.casefold() not in {"requestbody", "responsebody"}:
            continue
        try:
            decoded = _mapping(body, field)
            lowered = {key.casefold(): value for key, value in decoded.items()}
            assignment = _mapping(lowered.get("properties", lowered), f"{field}.properties")
            values = _fields({key.casefold(): value for key, value in assignment.items()}, ASSIGNMENT_FIELDS)
            if values and (assignment_id := _scalar(lowered.get("id"), f"{field}.id")):
                values["assigned-role-assignment-id"] = assignment_id
        except ValueError:
            continue
        if values:
            # Use one reported body so principal, role and scope stay paired.
            if field.casefold() == "responsebody":
                return {**values, "assignment-source": field}
            request_values = {**values, "assignment-source": field}
    return request_values


def _status_code(props):
    status = props.get("statusCode")
    if type(status) is int:
        return str(status)
    return _scalar(status, "properties.statusCode")


def _event(record, expected):
    schema = _schema(record)
    if expected is not None and schema != expected:
        raise ValueError(f"The export envelope expects {expected} Activity Log records.")
    caller_path = "caller"
    if schema == "arm":
        claim_path = "claims"
        values = _fields(record, ARM_FIELDS)
        props = _mapping(record.get("properties"), "properties")
        claims = _mapping(record.get("claims"), "claims")
        auth = _mapping(record.get("authorization"), "authorization")
        if "operation" not in values and (action := _scalar(auth.get("action"), "authorization.action")):
            values.update({"operation": action, "operation-source": "authorization.action"})
        if "category" not in values and (category := _scalar(props.get("eventCategory"), "properties.eventCategory")):
            values["category"] = category
        client = _mapping(record.get("httpRequest"), "httpRequest")
    elif schema == "azure-monitor":
        claim_path = "identity.claims"
        values = _fields(record, DIAGNOSTIC_FIELDS)
        props = _mapping(record.get("properties"), "properties")
        identity = _mapping(record.get("identity"), "identity")
        claims = _mapping(identity.get("claims"), "identity.claims")
        auth = _mapping(identity.get("authorization"), "identity.authorization")
        client = {}
        category = _scalar(props.get("eventCategory"), "properties.eventCategory")
        if category:
            values["category"] = category
        elif (category := values.get("diagnostic-category")) and category.casefold() in ACTIVITY_CATEGORIES:
            values["category"] = category
        else:
            values["category"] = "Administrative"
        values.update(_fields(record, {"callerIpAddress": "caller-address", "location": "location"}))
    else:
        caller_path = "Caller"
        values = _fields(record, ANALYTICS_FIELDS)
        props, _ = _dynamic(record, "Properties")
        claims, claim_path = _dynamic(record, "Claims")
        auth, _ = _dynamic(record, "Authorization")
        client = _mapping(record.get("HTTPRequest"), "HTTPRequest")
        for field, relation in (
            ("OperationName", "operation"),
            ("ResourceProvider", "resource-provider"),
            ("_ResourceId", "resource-id"),
            ("Category", "category"),
            ("ActivityStatus", "result"),
            ("ActivitySubstatus", "result-detail"),
        ):
            if relation not in values and (value := _scalar(record.get(field), field)):
                values[relation] = value

    if not values.get("operation"):
        raise ValueError("Activity Log record requires a reported operation name.")
    values["source-schema"] = schema
    _principal(claims, values, claim_path, caller_path)
    for relation, value in _fields(
        client, {"clientIpAddress": "caller-address", "clientRequestId": "client-request-id"}
    ).items():
        values.setdefault(relation, value)
    if address := values.get("caller-address"):
        if "%" not in address:
            try:
                values["source-ip"] = str(ipaddress.ip_address(address))
            except ValueError:
                pass
    if "resource-id" not in values:
        entity = _scalar(props.get("entity"), "properties.entity")
        if entity and ARM_ENTITY.match(entity):
            values["resource-id"] = entity
    if "subscription-id" not in values and (subscription := ARM_SUBSCRIPTION.match(values.get("resource-id", ""))):
        values["subscription-id"] = subscription[1]
    if status := _status_code(props):
        values["status-code"] = status
    values.update(_fields(auth, AUTHORIZATION_FIELDS))
    for relation, value in _fields(_mapping(auth.get("evidence"), "authorization.evidence"), EVIDENCE_FIELDS).items():
        values.setdefault(relation, value)
    values.update(_role_assignment(props, values["operation"]))

    observed = None
    time_field, submission_field = TIME_FIELDS[schema]
    if record.get(time_field) is not None:
        observed = _timestamp(record[time_field], time_field)
        values.update({"event-time": observed.isoformat(), "event-time-raw": record[time_field]})
    if submission_field and record.get(submission_field) is not None:
        submission = _timestamp(record[submission_field], submission_field)
        values.update({"submission-time": submission.isoformat(), "submission-time-raw": record[submission_field]})
    return values, observed


def _import(request):
    if not isinstance(request, dict):
        raise ValueError("Expected an import request object.")
    attach = _include_source(request)
    raw, filename, document = _upload(request)
    entries, format_, expected, next_page = _records(document)
    digest = hashlib.sha256(raw).hexdigest()
    source = _object("file", (digest, filename), {"filename": filename, "sha256": digest, "size-in-bytes": len(raw)})
    if attach:
        _add(source, "attachment", filename, data=BytesIO(raw))

    events, seen = [], {}
    schemas = Counter()
    missing_timestamps = 0
    for index, entry in enumerate(entries, 1):
        try:
            values, observed = _event(entry, expected)
            schema = values["source-schema"]
            native_id = values.get("event-id") or values.get("event-record-id")
            identity = (source.uuid, index)
            if native_id:
                identity = (schema, native_id.casefold())
                fingerprint = hashlib.sha256(dumps(entry).encode("ascii")).digest()
                if identity in seen:
                    if seen[identity] != fingerprint:
                        raise ValueError("Conflicting records share the same Activity Log event identifier and schema.")
                    continue
                seen[identity] = fingerprint
            event = _object(TEMPLATE, identity, values)
            if observed is not None:
                event.first_seen = event.last_seen = observed
            else:
                missing_timestamps += 1
            ref = event.add_reference(source.uuid, "extracted-from", f"Azure Activity Log record {index}")
            ref.uuid = _uuid(UUID(event.uuid), "extracted-from", source.uuid)
            events.append(event)
            schemas[schema] += 1
        except (ValueError, OverflowError) as error:
            raise ValueError(f"Record {index}: {error}") from error

    warnings = ["The REST response reports another page. Import remaining saved pages separately."] if next_page else []
    if missing_timestamps:
        warnings.append(f"{missing_timestamps} records did not report an event timestamp.")
    return {
        "results": {"Object": [json.loads(obj.to_json(strict=True)) for obj in [source, *events]]},
        "summary": {
            "format": format_,
            "records": len(entries),
            "events": len(events),
            "duplicate_records": len(entries) - len(events),
            "schemas": dict(schemas),
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
        return {"error": "Unable to decode the upload. Supply Azure Activity Log UTF-8 JSON or gzip."}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import Azure Activity Log events. Check the request and object template."}
    except ValueError as error:
        return {"error": f"Unable to import Azure Activity Log events: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {"include_source": {"type": "Boolean", "message": "Attach the exact source audit log"}},
    }


def version():
    return dict(moduleinfo, config=[])
