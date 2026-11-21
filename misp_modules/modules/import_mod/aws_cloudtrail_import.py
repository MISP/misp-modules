"""Import AWS CloudTrail audit records from local JSON and gzip files."""

import base64
import binascii
import gzip
import hashlib
import ipaddress
import json
import re
import zlib
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO
from uuid import UUID, uuid5

from pymisp import MISPObject
from pymisp.exceptions import PyMISPError

moduleinfo = {
    "name": "AWS CloudTrail Audit Logs Import",
    "description": "Import AWS CloudTrail JSON or JSON.gz audit records with source provenance.",
    "version": "1.0",
    "author": "MISP Project",
    "module-type": ["import"],
    "requirements": ["PyMISP"],
    "features": (
        "Imports native Records envelopes and individual CloudTrail event JSON offline. Maps identity, action,"
        " resource, outcome and time to unreviewed MISP objects. Links each record to a SHA-256 source file"
        " descriptor. Can attach the exact upload on request. Includes compatible object templates."
    ),
    "references": [
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html",
        "https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/aws_cloudtrail_import.md",
    ],
    "input": "Base64-encoded UTF-8 CloudTrail JSON or gzip-compressed JSON.",
    "output": "AWS CloudTrail audit event, source file, and linked cloud account, resource and IAM role objects.",
}
MAX_UPLOAD = 10 * 1024 * 1024
MAX_JSON = 20 * 1024 * 1024
MAX_RECORDS = 1000
MAX_RESOURCES = 1000
NAMESPACE = UUID("1193885c-01db-49f4-acf0-1ffebee6a02b")
EVENT_FIELDS = {
    "eventVersion": "event-version",
    "eventCategory": "event-category",
    "eventType": "event-type",
    "awsRegion": "aws-region",
    "recipientAccountId": "recipient-account-id",
    "sourceIPAddress": "source-address",
    "userAgent": "user-agent",
    "requestID": "request-id",
    "sharedEventID": "shared-event-id",
    "errorCode": "error-code",
}
IDENTITY_FIELDS = {
    "type": "principal-type",
    "principalId": "principal-id",
    "arn": "principal-arn",
    "accountId": "principal-account-id",
    "userName": "principal-name",
}
TIME_FORMAT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
ACCOUNT_FORMAT = re.compile(r"[0-9]{12}")


@lru_cache(maxsize=4)
def _template(name):
    path = resources.files("misp_modules").joinpath("data", "aws-cloudtrail", name, "definition.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _uuid(namespace, *parts):
    return str(uuid5(namespace, json.dumps(parts, ensure_ascii=True, separators=(",", ":"))))


def _object(name, identity, values):
    options = {} if name == "file" else {"misp_objects_template_custom": _template(name)}
    obj = MISPObject(name, strict=True, standalone=False, **options)
    obj.uuid = _uuid(NAMESPACE, name, *identity)
    for relation, value in values.items():
        _add(obj, relation, value)
    return obj


def _add(obj, relation, value, **kwargs):
    attribute = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
    attribute.uuid = _uuid(UUID(str(obj.uuid)), relation)


def _reference(obj, target, relationship, comment):
    ref = obj.add_reference(target.uuid, relationship, comment)
    ref.uuid = _uuid(UUID(str(obj.uuid)), relationship, str(target.uuid))


def _unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("CloudTrail JSON contains a duplicate key.")
    return obj


def _invalid_constant(_):
    raise ValueError("CloudTrail JSON contains a non-finite number.")


def _upload(request):
    encoded = request.get("data")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_UPLOAD + 2) // 3):
        raise ValueError("data requires a base64 upload of at most 10 MiB.")
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > MAX_UPLOAD:
        raise ValueError("Upload must be nonempty and at most 10 MiB.")
    compressed = raw.startswith(b"\x1f\x8b")
    filename = request.get("filename")
    if filename in (None, ""):
        filename = "cloudtrail.json.gz" if compressed else "cloudtrail.json"
    if not isinstance(filename, str):
        raise ValueError("filename must be text.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255 or not filename.isprintable():
        raise ValueError("filename requires a printable basename of at most 255 characters.")
    if compressed:
        with gzip.GzipFile(fileobj=BytesIO(raw)) as stream:
            payload = stream.read(MAX_JSON + 1)
    else:
        payload = raw
    if len(payload) > MAX_JSON:
        raise ValueError("Decoded CloudTrail JSON exceeds 20 MiB.")
    return raw, filename, payload


def _include_source(request):
    config = request.get("config")
    if config is None:
        return False
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    setting = config.get("include_source")
    if setting is None or setting is False:
        return False
    if setting is True:
        return True
    if isinstance(setting, str):
        setting = setting.strip().lower()
        if setting in ("", "false", "no", "0"):
            return False
        if setting in ("true", "yes", "1"):
            return True
    raise ValueError("include_source must be a boolean.")


def _records(payload):
    document = json.loads(payload.decode("utf-8-sig"), object_pairs_hook=_unique_keys, parse_constant=_invalid_constant)
    if not isinstance(document, dict):
        raise ValueError("Expected a CloudTrail Records envelope or one CloudTrail event object.")
    records = document.get("Records") if "Records" in document else [document]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError("CloudTrail Records must contain 1 to 1,000 events.")
    return records


def _text(value, field):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096 or not value.isprintable():
        raise ValueError(f"{field} must be nonempty printable text of at most 4,096 characters.")
    return value


def _fields(record, fields):
    return {
        relation: _text(record[field], field)
        for field, relation in fields.items()
        if record.get(field) not in (None, "")
    }


def _mapping(record, field):
    value = record.get(field)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object.")
    return value


def _event_id(record):
    value = _text(record.get("eventID"), "eventID")
    try:
        identifier = UUID(value)
    except ValueError:
        raise ValueError("eventID must be a hyphenated UUID.") from None
    if str(identifier) != value.lower():
        raise ValueError("eventID must be a hyphenated UUID.")
    return str(identifier)


def _timestamp(value):
    if not TIME_FORMAT.fullmatch(value) or value.endswith("-00:00"):
        raise ValueError("eventTime requires ISO 8601 seconds and a known timezone.")
    if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise ValueError("eventTime has an invalid UTC offset.")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _arn(value):
    parts = value.split(":", 5)
    if (
        len(parts) == 6
        and parts[0] == "arn"
        and (parts[1] == "aws" or parts[1].startswith("aws-"))
        and parts[2]
        and parts[5]
    ):
        return parts
    return None


def _outcome(record, name):
    errors = (record.get("errorCode"), record.get("errorMessage"))
    if any(isinstance(value, str) and value.strip() for value in errors):
        return "failure"
    response = record.get("responseElements")
    if name == "ConsoleLogin" and isinstance(response, dict):
        status = response.get("ConsoleLogin")
        if status in ("Success", "Failure"):
            return status.lower()
    return "unknown"


def _event(record):
    if not isinstance(record, dict):
        raise ValueError("Every CloudTrail record must be an object.")
    event_id = _event_id(record)
    event_name = _text(record.get("eventName"), "eventName")
    raw_time = _text(record.get("eventTime"), "eventTime")
    event_time = _timestamp(raw_time)
    identity = _mapping(record, "userIdentity")
    issuer = _mapping(_mapping(identity, "sessionContext"), "sessionIssuer")
    values = {
        "event-id": event_id,
        "event-name": event_name,
        "event-source": _text(record.get("eventSource"), "eventSource"),
        "event-time": event_time.isoformat(),
        "event-time-raw": raw_time,
        "outcome": _outcome(record, event_name),
        "review-status": "unreviewed",
    }
    values.update(_fields(record, EVENT_FIELDS))
    values.update(_fields(identity, IDENTITY_FIELDS))
    values.update(
        _fields(
            _mapping(identity, "onBehalfOf"),
            {"userId": "on-behalf-of-user-id", "identityStoreArn": "on-behalf-of-identity-store-arn"},
        )
    )
    values.update(_fields(issuer, {"arn": "session-issuer-arn"}))
    values.update(_fields(_mapping(record, "addendum"), {"originalEventID": "original-event-id"}))
    read_only = record.get("readOnly")
    if read_only is not None:
        if not isinstance(read_only, bool):
            raise ValueError("readOnly must be a JSON boolean.")
        values["read-only"] = read_only
    address = values.get("source-address")
    if address and "%" not in address:
        try:
            values["source-ip"] = str(ipaddress.ip_address(address))
        except ValueError:
            pass
    obj = _object("aws-cloudtrail-event", (event_id,), values)
    obj.first_seen = event_time
    obj.last_seen = event_time
    return obj, values


def _link_entity(obj, entities, name, values, comment):
    identity = tuple(values.items())
    key = (name, identity)
    if key not in entities:
        entities[key] = _object(name, identity, values)
    target = entities[key]
    if not any(ref.referenced_uuid == target.uuid for ref in obj.ObjectReference):
        _reference(obj, target, "related-to", comment)


def _link_accounts(obj, entities, values):
    principal = values.get("principal-account-id", "")
    recipient = values.get("recipient-account-id", "")
    for account_id in dict.fromkeys((principal, recipient)):
        if not ACCOUNT_FORMAT.fullmatch(account_id):
            continue
        fields = {"provider": "AWS", "account-id": account_id}
        if account_id == principal == recipient:
            role = "CloudTrail principal and recipient account"
        elif account_id == principal:
            role = "CloudTrail principal account"
        else:
            role = "CloudTrail recipient account"
        _link_entity(obj, entities, "cloud-account", fields, role)


def _link_role(obj, entities, values):
    role_arn = values.get("session-issuer-arn") or values.get("principal-arn", "")
    arn = _arn(role_arn)
    if not arn or arn[2] != "iam" or not arn[5].startswith("role/"):
        return
    name = arn[5].rsplit("/", 1)[-1]
    if not name:
        return
    role = {"role-id": role_arn, "name": name}
    if ACCOUNT_FORMAT.fullmatch(arn[4]):
        role["account-id"] = arn[4]
    _link_entity(obj, entities, "iam-role", role, "CloudTrail IAM role")


def _link_resources(obj, entities, resources_):
    for resource in resources_:
        if not isinstance(resource, dict):
            raise ValueError("Every CloudTrail resources entry must be an object.")
        identifier = resource.get("ARN")
        if identifier in (None, ""):
            continue
        identifier = _text(identifier, "resource identifier")
        arn = _arn(identifier)
        values = {"provider": "AWS", "resource-id": identifier}
        if arn:
            values["partition"] = arn[1]
            if arn[3]:
                values["region"] = arn[3]
        values.update(_fields(resource, {"accountId": "account-id", "type": "type"}))
        if arn and "account-id" not in values and ACCOUNT_FORMAT.fullmatch(arn[4]):
            values["account-id"] = arn[4]
        _link_entity(obj, entities, "cloud-resource", values, "Resource reported in CloudTrail resources")


def _import(request):
    if not isinstance(request, dict):
        raise ValueError("Expected an import request object.")
    include_source = _include_source(request)
    raw, filename, payload = _upload(request)
    records = _records(payload)
    digest = hashlib.sha256(raw).hexdigest()
    source = _object("file", (digest,), {"filename": filename, "size-in-bytes": len(raw), "sha256": digest})
    if include_source:
        _add(source, "attachment", filename, data=BytesIO(raw))

    events, entities, seen = [], {}, {}
    resource_count = 0
    for index, record in enumerate(records, 1):
        try:
            obj, values = _event(record)
            event_id = values["event-id"]
            canonical = json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True, allow_nan=False)
            fingerprint = hashlib.sha256(canonical.encode("ascii")).digest()
            if event_id in seen:
                if seen[event_id] != fingerprint:
                    raise ValueError("Conflicting records share the same eventID.")
                continue
            seen[event_id] = fingerprint
            resources_ = record.get("resources")
            if resources_ is None:
                resources_ = []
            if not isinstance(resources_, list):
                raise ValueError("resources must be an array.")
            resource_count += len(resources_)
            if resource_count > MAX_RESOURCES:
                raise ValueError("CloudTrail upload exceeds 1,000 resource entries.")
            _reference(obj, source, "extracted-from", f"CloudTrail record {index}")
            _link_accounts(obj, entities, values)
            _link_role(obj, entities, values)
            _link_resources(obj, entities, resources_)
            events.append(obj)
        except (ValueError, OverflowError) as error:
            raise ValueError(f"Record {index}: {error}") from None
    return {
        "results": {"Object": [json.loads(obj.to_json()) for obj in [source, *events, *entities.values()]]},
        "summary": {
            "records": len(records),
            "events": len(events),
            "duplicate_records": len(records) - len(events),
            "source_sha256": digest,
            "source_attached": include_source,
        },
    }


def handler(q=False):
    if q is False:
        return False
    try:
        return _import(json.loads(q))
    except (binascii.Error, UnicodeError, json.JSONDecodeError, OSError, EOFError, zlib.error, RecursionError):
        return {"error": "Unable to decode CloudTrail upload. Supply valid UTF-8 JSON or gzip-compressed JSON."}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import CloudTrail. Check the request and object templates."}
    except ValueError as error:
        return {"error": f"Unable to import CloudTrail: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "include_source": {
                "type": "Boolean",
                "message": "Attach the exact source log (may contain sensitive data)",
            },
        },
    }


def version():
    return dict(moduleinfo, config=[])
