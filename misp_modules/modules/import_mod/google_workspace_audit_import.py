"""Import saved Google Workspace Reports API audit activities."""

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
    "name": "Google Workspace Audit Logs Import",
    "description": "Import saved Google Workspace login, admin, Drive and OAuth token activity.",
    "module-type": ["import"],
    "data-source": "internal",
    "requirements": ["PyMISP"],
    "features": (
        "Reads Reports API activities.list JSON and keeps every nested event linked to its original activity ID."
        " Preserves event parameters and exposes actor, Drive and OAuth identifiers for investigation. See the"
        " [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/"
        "google_workspace_audit_import.md)."
    ),
    "references": [
        "https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list",
        "https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login",
        "https://developers.google.com/workspace/admin/reports/v1/appendix/activity/drive",
        "https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token",
    ],
    "input": "A saved activities.list JSON response, Activity or array of Activity records, optionally gzipped.",
    "output": "A source file and linked Google Workspace audit activity and event objects.",
}

NAMESPACE = UUID("fadff5ad-69ad-4f77-991f-d66460c7cb4c")
ACTIVITY = "google-workspace-audit-activity"
EVENT = "google-workspace-audit-event"
PAGE_KINDS = ("admin#reports#activities", "reports#activities", "reports#auditActivities")
PLACEHOLDER_PROFILE = "105250506097979753968"
MAX_UPLOAD = 10 * 1024 * 1024
MAX_JSON = 20 * 1024 * 1024
MAX_RECORDS = 1000
MAX_EVENTS = 2000
MAX_EVENT_ATTRIBUTES = 1000
MAX_ATTRIBUTES = 12000
MAX_TEXT = 4096
MAX_PARAMETER = 32 * 1024
EMAIL = re.compile(r"[^@\s]+@[^@\s]+")
EVENT_EMAIL_FIELDS = {"affected-user", "affected-group", "document-owner", "sharing-target"}
TIMESTAMP = re.compile(
    r"(?P<seconds>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<offset>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
PARAMETER_FIELDS = {
    "login": {
        "login_type": "login-type",
        "login_failure_type": "login-failure-type",
        "login_challenge_method": "login-challenge-method",
        "login_challenge_status": "login-challenge-status",
        "is_suspicious": "suspicious-login",
    },
    "admin": {
        "USER_EMAIL": "affected-user",
        "GROUP_EMAIL": "affected-group",
        "ROLE_ID": "admin-role-id",
        "ROLE_NAME": "admin-role-name",
        "ORG_UNIT_NAME": "organizational-unit",
        "SETTING_NAME": "setting-name",
    },
    "drive": {
        "doc_id": "document-id",
        "doc_title": "document-title",
        "doc_type": "document-type",
        "owner": "document-owner",
        "target_user": "sharing-target",
        "shared_drive_id": "shared-drive-id",
        "visibility": "new-visibility",
        "old_visibility": "old-visibility",
    },
    "token": {
        "client_id": "oauth-client-id",
        "client_type": "oauth-client-type",
        "app_name": "oauth-application-name",
        "scope": "oauth-scope",
    },
}


@lru_cache(maxsize=2)
def _template(name):
    return json.loads(
        resources.files("misp_modules")
        .joinpath("data", "google-workspace-audit", name, "definition.json")
        .read_text(encoding="utf-8")
    )


def _uuid(namespace, *parts):
    return str(uuid5(namespace, dumps(parts)))


def _object(name, *identity):
    options = {} if name == "file" else {"misp_objects_template_custom": _template(name)}
    obj = MISPObject(name, strict=True, standalone=False, **options)
    obj.uuid = _uuid(NAMESPACE, name, *identity)
    return obj


def _add(obj, relation, value, *, key=None, **kwargs):
    attr = obj.add_attribute(relation, value=value, to_ids=False, **kwargs)
    attr.uuid = _uuid(UUID(obj.uuid), relation, value if key is None else key)


def _reference(obj, target, relationship, comment):
    ref = obj.add_reference(target.uuid, relationship, comment)
    ref.uuid = _uuid(UUID(obj.uuid), relationship, target.uuid)


def _mapping(value, field):
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object.")
    return value


def _array(value, field):
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array.")
    return value


def _is_text(value):
    return isinstance(value, str) and len(value) <= MAX_TEXT and value.isprintable() and bool(value.strip())


def _text(value, field, *, multiline=False):
    printable = value
    if multiline and isinstance(value, str):
        printable = value.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    if not _is_text(printable):
        raise ValueError(f"{field} must be printable, nonempty text of at most {MAX_TEXT:,} characters.")
    return value


def _fields(obj, record, fields):
    for field, relation in fields.items():
        value = record.get(field)
        if value not in (None, ""):
            _add(obj, relation, _text(value, field))


def _include_source(request):
    config = request.get("config")
    if config is None:
        return False
    setting = _mapping(config, "config").get("include_source")
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
    payload = raw
    if compressed:
        with gzip.GzipFile(fileobj=BytesIO(raw)) as stream:
            payload = stream.read(MAX_JSON + 1)
    if len(payload) > MAX_JSON:
        raise ValueError("Decoded audit log exceeds 20 MiB.")

    filename = request.get("filename")
    if filename in (None, ""):
        filename = "google-workspace-audit.json.gz" if compressed else "google-workspace-audit.json"
    if not isinstance(filename, str):
        raise ValueError("filename must be text.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255 or not filename.isprintable():
        raise ValueError("Provide a printable basename of at most 255 characters.")
    return raw, filename, payload


def _records(payload):
    document = loads(payload.decode("utf-8-sig"))
    next_page = False
    if isinstance(document, list):
        records = document
    elif isinstance(document, dict) and "id" in document:
        records = [document]
    elif isinstance(document, dict) and (
        "items" in document or "nextPageToken" in document or document.get("kind") in PAGE_KINDS
    ):
        kind = document.get("kind")
        if kind is not None and kind not in PAGE_KINDS:
            raise ValueError("Expected a Google Workspace activities.list response.")
        records = _array(document.get("items", []), "items")
        token = document.get("nextPageToken", "")
        if not isinstance(token, str):
            raise ValueError("nextPageToken must be a string.")
        next_page = bool(token)
    else:
        raise ValueError("Expected an activities.list response, Activity or array of Activity records.")
    if len(records) > MAX_RECORDS:
        raise ValueError(f"The upload exceeds {MAX_RECORDS:,} activities.")
    if not records:
        if next_page:
            raise ValueError(
                "This response contains no activities and reports another page. Import the saved next page."
            )
        raise ValueError("The upload contains no activities.")
    return records, next_page


def _activity_id(record):
    activity_id = _mapping(record.get("id"), "id")
    customer = _text(activity_id.get("customerId"), "id.customerId")
    application = _text(activity_id.get("applicationName"), "id.applicationName")
    if application not in PARAMETER_FIELDS:
        raise ValueError("id.applicationName must be login, admin, drive or token.")
    qualifier = activity_id.get("uniqueQualifier")
    if type(qualifier) is int:
        qualifier = str(qualifier)
    qualifier = _text(qualifier, "id.uniqueQualifier")
    raw_time = _text(activity_id.get("time"), "id.time")
    return customer, application, raw_time, qualifier


def _activity_time(raw):
    match = TIMESTAMP.fullmatch(raw)
    if match is None or match["offset"] == "-00:00":
        raise ValueError("id.time needs RFC 3339 seconds, at most nine fractional digits, and a known UTC offset.")
    offset = "+00:00" if match["offset"] == "Z" else match["offset"]
    micros = (match["fraction"] or "").ljust(6, "0")[:6]
    return datetime.fromisoformat(f"{match['seconds']}.{micros}{offset}").astimezone(timezone.utc)


def _activity(record, identity, observed):
    customer, application, raw_time, qualifier = identity
    activity = _object(ACTIVITY, *identity)
    activity.first_seen = activity.last_seen = observed
    _add(activity, "customer-id", customer)
    _add(activity, "application-name", application)
    _add(activity, "activity-qualifier", qualifier)
    _add(activity, "activity-time-raw", raw_time)
    _add(activity, "activity-time", observed.isoformat())

    _fields(activity, record, {"ownerDomain": "owner-domain", "ipAddress": "source-address"})
    address = record.get("ipAddress")
    if address and "%" not in address:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            pass
        else:
            _add(activity, "ip-src", str(parsed))

    actor = _mapping(record.get("actor", {}), "actor")
    _fields(activity, actor, {"callerType": "caller-type", "key": "actor-key"})
    _fields(
        activity,
        _mapping(actor.get("applicationInfo", {}), "actor.applicationInfo"),
        {"oauthClientId": "oauth-client-id", "applicationName": "oauth-application-name"},
    )
    actor_keys = []
    email = actor.get("email")
    if email not in (None, ""):
        email = _text(email, "actor.email")
        valid_email = EMAIL.fullmatch(email) is not None
        _add(activity, "actor-email", email, disable_correlation=not valid_email)
        if valid_email:
            actor_keys.append(("email", email.casefold()))
    profile = actor.get("profileId")
    if profile not in (None, ""):
        profile = _text(profile, "actor.profileId")
        valid_profile = profile.isascii() and profile.isdecimal() and profile != PLACEHOLDER_PROFILE
        _add(activity, "actor-profile-id", profile, disable_correlation=not valid_profile)
        if valid_profile:
            actor_keys.append(("profile ID", profile))
    return activity, actor_keys


def _parameter_values(parameter, relation):
    if relation == "suspicious-login":
        value = parameter.get("boolValue")
        if isinstance(value, bool):
            yield "true" if value else "false"
        return
    value = parameter.get("value")
    if _is_text(value):
        yield value
    values = parameter.get("multiValue")
    if isinstance(values, list):
        yield from (value for value in values if _is_text(value))


def _event(activity, index, record, application, budget):
    record = _mapping(record, "event")
    event = _object(EVENT, activity.uuid, index)
    event.first_seen = event.last_seen = activity.first_seen
    _add(event, "event-index", index + 1)
    _fields(event, record, {"name": "event-name", "type": "event-type"})
    status = _mapping(record.get("status", {}), "status")
    _fields(event, status, {"eventStatus": "event-status", "errorCode": "error-code"})
    message = status.get("errorMessage")
    if message not in (None, ""):
        _add(event, "error-message", _text(message, "status.errorMessage", multiline=True))
    http_status = status.get("httpStatusCode")
    if http_status is not None:
        if type(http_status) is not int:
            raise ValueError("status.httpStatusCode must be an integer.")
        _add(event, "http-status-code", str(http_status))

    limit = min(MAX_EVENT_ATTRIBUTES, budget)
    derived = set()

    def add_distinct(relation, value):
        pair = (relation, value)
        if pair not in derived:
            if len(event.attributes) >= limit:
                raise ValueError("Audit event attributes exceed the import limit.")
            if relation in EVENT_EMAIL_FIELDS:
                _add(event, relation, value, disable_correlation=EMAIL.fullmatch(value) is None)
            else:
                _add(event, relation, value)
            derived.add(pair)

    resource_ids = _array(record.get("resourceIds", []), "resourceIds")
    for resource in resource_ids:
        add_distinct("resource-id", _text(resource, "resourceIds entry"))

    for field, raw_relation in (("parameters", "parameter"), ("sensitiveParameters", "sensitive-parameter")):
        parameters = _array(record.get(field, []), field)
        for position, parameter in enumerate(parameters):
            path = f"{field}[{position}]"
            raw = dumps(_mapping(parameter, path))
            if len(raw) > MAX_PARAMETER:
                raise ValueError(f"{path} exceeds 32 KiB of serialized JSON.")
            if len(event.attributes) >= limit:
                raise ValueError("Audit event attributes exceed the import limit.")
            _add(event, raw_relation, raw, key=position, comment=path)
            name = parameter.get("name")
            if field == "parameters" and isinstance(name, str):
                relation = PARAMETER_FIELDS[application].get(name)
                if relation:
                    for value in _parameter_values(parameter, relation):
                        add_distinct(relation, value)
    if len(event.attributes) > limit:
        raise ValueError("Audit event attributes exceed the import limit.")
    _reference(activity, event, "contains", f"events[{index}]")
    return event


def _link_actors(activity, customer, keys, anchors):
    matches = {}
    for label, value in keys:
        other = anchors.setdefault((customer, label, value), activity)
        if other is not activity:
            matches.setdefault(other.uuid, (other, []))[1].append(label)
    for other, labels in matches.values():
        _reference(activity, other, "related-to", "Same reported actor " + " and ".join(labels) + " in this customer")


def _import(request):
    request = _mapping(request, "request")
    attach = _include_source(request)
    raw, filename, payload = _upload(request)
    records, next_page = _records(payload)
    digest = hashlib.sha256(raw).hexdigest()
    source = _object("file", digest, filename)
    _add(source, "filename", filename)
    _add(source, "sha256", digest)
    _add(source, "size-in-bytes", len(raw))
    if attach:
        _add(source, "attachment", filename, data=BytesIO(raw), disable_correlation=True)

    activities, events = [], []
    seen, anchors = {}, {}
    applications = Counter()
    missing_events = 0
    budget = MAX_ATTRIBUTES
    for index, record in enumerate(records, 1):
        try:
            record = _mapping(record, "activity")
            identity = _activity_id(record)
            fingerprint = hashlib.sha256(dumps(record).encode("ascii")).digest()
            if identity in seen:
                if fingerprint != seen[identity]:
                    raise ValueError("Conflicting records share the same activity ID.")
                continue
            seen[identity] = fingerprint

            customer, application, timestamp, _qualifier = identity
            activity, actor_keys = _activity(record, identity, _activity_time(timestamp))
            _reference(activity, source, "extracted-from", f"Activity {index} in upload")
            nested = _array(record.get("events", []), "events")
            if len(events) + len(nested) > MAX_EVENTS:
                raise ValueError(f"The upload exceeds {MAX_EVENTS:,} nested events.")
            if not nested:
                missing_events += 1
            budget -= len(activity.attributes)
            if budget < 0:
                raise ValueError("Activity attributes exceed the import limit.")
            for offset, item in enumerate(nested):
                try:
                    event = _event(activity, offset, item, application, budget)
                except ValueError as error:
                    raise ValueError(f"events[{offset}]: {error}") from error
                events.append(event)
                budget -= len(event.attributes)
            _link_actors(activity, customer, actor_keys, anchors)
            activities.append(activity)
            applications[application] += 1
        except (ValueError, OverflowError) as error:
            raise ValueError(f"Activity {index}: {error}") from error

    warnings = ["The response reports another page. Import the remaining saved pages separately."] if next_page else []
    if missing_events:
        warnings.append(f"{missing_events:,} activities contain no nested events.")
    return {
        "results": {"Object": [json.loads(obj.to_json(strict=True)) for obj in [source, *activities, *events]]},
        "summary": {
            "records": len(records),
            "activities": len(activities),
            "events": len(events),
            "duplicate_records": len(records) - len(activities),
            "applications": dict(applications),
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
        return {"error": "Unable to decode the upload. Supply Reports API log data as UTF-8 JSON or gzip."}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import Google Workspace Audit Logs. Check the request and object templates."}
    except ValueError as error:
        return {"error": f"Unable to import Google Workspace Audit Logs: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {"include_source": {"type": "Boolean", "message": "Attach the exact source audit log"}},
    }


def version():
    return dict(moduleinfo, config=[])
