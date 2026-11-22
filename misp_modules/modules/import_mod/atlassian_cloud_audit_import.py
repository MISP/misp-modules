"""Import saved Atlassian Administration audit CSV and Organizations Events API JSON."""

import base64
import binascii
import csv
import gzip
import hashlib
import ipaddress
import json
import re
import zlib
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO, StringIO
from urllib.parse import unquote, urlsplit
from uuid import UUID, uuid5

from pymisp import MISPObject
from pymisp.exceptions import PyMISPError

from misp_modules.lib.network_observation import dumps, loads

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Atlassian Cloud Audit Logs Import",
    "description": "Import Atlassian Administration audit CSV and Organizations Events API JSON.",
    "module-type": ["import"],
    "data-source": "internal",
    "requirements": ["PyMISP"],
    "features": (
        "Imports saved organization and site activity with reported actor, authentication, action and scope."
        " Preserves affected entities and event containers with their source positions. Links every event to the"
        " original export. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/"
        "import_mod/atlassian_cloud_audit_import.md)."
    ),
    "references": [
        "https://support.atlassian.com/security-and-access-policies/docs/export-audit-logs/",
        "https://support.atlassian.com/security-and-access-policies/docs/view-audit-log-activities/",
        "https://developer.atlassian.com/cloud/admin/organization/rest/api-group-events/",
    ],
    "input": "Saved Atlassian Administration audit CSV or Organizations Events API JSON, optionally gzip-compressed.",
    "output": "A source file and linked Atlassian Cloud audit event and entity objects.",
}

EVENT = "atlassian-audit-event"
ENTITY = "atlassian-audit-entity"
NAMESPACE = UUID("37d6612d-31ea-4fba-be7c-c11f0ba0c870")
MAX_UPLOAD = 10 * 1024 * 1024
MAX_PAYLOAD = 20 * 1024 * 1024
MAX_RECORDS = 10000
MAX_ENTITIES = 4000
MAX_COLUMNS = 128
MAX_TEXT = 4096
MAX_RAW_ATTRIBUTE = 32 * 1024
FRAGMENT_SIZE = 15 * 1024
EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
ORGANIZATION_PATH = re.compile(r"/(?:admin/)?v1/orgs/([^/]+)/events(?:-stream|/[^/]+)?/?")
TIME_ZONE = r"(?P<zone>\s*(?:UTC|GMT)?(?:[+-][0-9]{1,2}(?::?[0-9]{2})?)|\s*(?:UTC|GMT|Z))?"
ISO_TIME = re.compile(
    r"(?P<seconds>[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2})?)"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?" + TIME_ZONE,
    re.IGNORECASE,
)
CSV_NAMED_TIME = re.compile(
    r"(?P<date>[a-z]{3,9} [0-9]{1,2}, [0-9]{4})(?:\s+[–—-]\s+|,?\s+)"
    r"(?P<clock>[0-9]{1,2}:[0-9]{2}(?::[0-9]{2})?)(?P<period>\s+(?:AM|PM))?" + TIME_ZONE,
    re.IGNORECASE,
)
UTC_OFFSET = re.compile(r"(?P<sign>[+-])(?P<hours>[0-9]{1,2})(?::?(?P<minutes>[0-9]{2}))?")
CSV_FIELDS = {
    "activity": ("activity", "action", "event", "activitytype", "eventtype"),
    "action-id": ("actionid", "activityid", "eventaction"),
    "actor-name": ("actor", "actorname", "actordisplayname", "performedby", "username"),
    "actor-id": ("actorid", "accountid", "actoraccountid"),
    "actor-email-raw": ("actoremail", "email", "useremail"),
    "on-behalf-of-name": ("onbehalfof", "onbehalfofname"),
    "on-behalf-of-id": ("onbehalfofid",),
    "on-behalf-of-email-raw": ("onbehalfofemail",),
    "source-address": ("ipaddress", "ip", "sourceip"),
    "location": ("location",),
    "app-name": ("app", "application", "product"),
    "auth-type": ("authenticationtype", "authtype"),
    "organization-id": ("organizationid", "organisationid", "orgid"),
    "organization": ("organization", "organisation", "org"),
    "site-id": ("siteid", "cloudid"),
    "site": ("site", "sitename", "siteurl"),
    "unit": ("unit", "unitname"),
    "unit-id": ("unitid",),
}
CSV_ACTION = (*CSV_FIELDS["activity"], *CSV_FIELDS["action-id"])
CSV_TIMESTAMP = (
    "timestamp",
    "timestamputc",
    "datetime",
    "datetimeutc",
    "dateandtime",
    "eventtime",
    "activitytime",
    "createdat",
)
CSV_DATE = ("dateutc", "date")
CSV_CLOCK = ("timeutc", "time")
ORG_KINDS = {"org", "organization", "organisation"}
SITE_KINDS = {"site", "cloudsite"}
PLACEHOLDERS = {"-", "none", "null", "redacted", "unknown", "unavailable", "n/a"}


@lru_cache(maxsize=2)
def _template(name):
    path = resources.files("misp_modules").joinpath("data", "atlassian-audit", name, "definition.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _uuid(namespace, *parts):
    return str(uuid5(namespace, dumps(parts)))


def _object(name, *identity):
    options = {} if name == "file" else {"misp_objects_template_custom": _template(name)}
    obj = MISPObject(name, strict=True, standalone=False, **options)
    obj.uuid = _uuid(NAMESPACE, name, *identity)
    return obj


def _add(obj, relation, value, *, key=None, **kwargs):
    attr = obj.add_attribute(relation, value=value, to_ids=False, **kwargs)
    attr.uuid = _uuid(UUID(obj.uuid), relation, key)


def _reference(obj, target, relation, comment):
    ref = obj.add_reference(target.uuid, relation, comment)
    ref.uuid = _uuid(UUID(obj.uuid), relation, target.uuid)


def _text(value):
    if isinstance(value, str) and value.strip() and len(value) <= MAX_TEXT and value.isprintable():
        return value
    return None


def _required(value, field):
    if (text := _text(value)) is None:
        raise ValueError(f"{field} must be nonempty printable text of at most {MAX_TEXT:,} characters.")
    return text


def _mapping(value, field):
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object.")
    return value


def _array(value, field):
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array.")
    return value


def _select(record, fields):
    return {relation: value for key, relation in fields.items() if (value := _text(record.get(key))) is not None}


def _offset(value):
    value = value.strip().upper()
    if value in ("Z", "UTC", "GMT"):
        return timezone.utc
    value = value.removeprefix("UTC").removeprefix("GMT")
    match = UTC_OFFSET.fullmatch(value)
    if match is None:
        raise ValueError("Use a known UTC offset such as +00:00 or -05:00.")
    hours, minutes = int(match["hours"]), int(match["minutes"] or "0")
    if hours > 23 or minutes > 59:
        raise ValueError("UTC offset is out of range.")
    period = timedelta(hours=hours, minutes=minutes)
    if match["sign"] == "-" and not period:
        raise ValueError("Use a known UTC offset such as +00:00 or -05:00.")
    return timezone(-period if match["sign"] == "-" else period)


def _options(request):
    config = request.get("config")
    config = {} if config is None else _mapping(config, "config")
    choices = {}
    for key in ("organization_id", "site", "csv_utc_offset"):
        value = config.get(key)
        if value not in (None, ""):
            choices[key] = _required(value, key).strip()
    if "csv_utc_offset" in choices:
        choices["csv_utc_offset"] = _offset(choices["csv_utc_offset"])
    attach = config.get("include_source")
    if isinstance(attach, str):
        value = attach.strip().lower()
        if value in ("true", "yes", "1"):
            attach = True
        elif value in ("", "false", "no", "0"):
            attach = False
    if attach is not None and not isinstance(attach, bool):
        raise ValueError("include_source must be a boolean.")
    return choices, bool(attach)


def _upload(request):
    encoded = request.get("data")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_UPLOAD + 2) // 3):
        raise ValueError("Provide a base64 upload of at most 10 MiB.")
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > MAX_UPLOAD:
        raise ValueError("Upload must contain between 1 byte and 10 MiB.")
    payload = raw
    if raw.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=BytesIO(raw)) as stream:
            payload = stream.read(MAX_PAYLOAD + 1)
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("Decompressed export exceeds 20 MiB.")
    return raw, payload.decode("utf-8-sig")


def _source(request, raw, digest, format_, attach):
    filename = request.get("filename")
    if filename in (None, ""):
        filename = f"atlassian-audit.{format_}" + (".gz" if raw.startswith(b"\x1f\x8b") else "")
    if not isinstance(filename, str):
        raise ValueError("filename must be text.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255 or not filename.isprintable():
        raise ValueError("Provide a printable basename of at most 255 characters.")
    source = _object("file", digest, filename)
    for relation, value in (("filename", filename), ("sha256", digest), ("size-in-bytes", len(raw))):
        _add(source, relation, value)
    if attach:
        _add(source, "attachment", filename, data=BytesIO(raw), disable_correlation=True)
    return source


def _header(value):
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _first(record, keys):
    return next((text for key in keys if (text := _text(record.get(key))) is not None), None)


def _csv_records(payload):
    reader = csv.reader(StringIO(payload, newline=""), strict=True)
    original = next(reader, [])
    header = [_header(column) for column in original]
    columns = set(header)
    if (
        not columns.intersection(CSV_ACTION)
        or not columns.intersection((*CSV_TIMESTAMP, *CSV_DATE, *CSV_CLOCK))
        or "" in columns
        or len(header) > MAX_COLUMNS
        or len(header) != len(columns)
    ):
        raise ValueError("Expected an Atlassian audit CSV with unique headers for activity and date or time.")
    for row in reader:
        if not row:
            continue
        if len(row) != len(header):
            raise ValueError(f"CSV row ending at line {reader.line_num} has the wrong number of columns.")
        yield (
            dict(zip(original, row, strict=True)),
            dict(zip(header, row, strict=True)),
            f"CSV row ending at line {reader.line_num}",
        )


def _scope_from_links(links):
    link = _text(links.get("self")) if isinstance(links, dict) else None
    if not link:
        return None
    try:
        url = urlsplit(link)
        if (url.scheme or url.netloc) and (url.scheme != "https" or url.netloc.casefold() != "api.atlassian.com"):
            return None
    except ValueError:
        return None
    match = ORGANIZATION_PATH.fullmatch(url.path)
    return _text(unquote(match[1])) if match else None


def _api_records(document, warnings):
    if isinstance(document, list):
        for index, record in enumerate(document, 1):
            yield record, None, f"JSON record {index}"
        return
    document = _mapping(document, "Organizations Events API response")
    if "data" not in document:
        yield document, None, "JSON event"
        return
    data = document["data"]
    links = _mapping(document.get("links") or {}, "links")
    meta = _mapping(document.get("meta") or {}, "meta")
    if any(isinstance(cursor, str) and cursor.strip() for cursor in (links.get("next"), meta.get("next"))):
        warnings.add("The Atlassian response has a next page. Import the remaining saved pages separately.")
    scope = _scope_from_links(links)
    if isinstance(data, list):
        for index, record in enumerate(data, 1):
            yield record, scope, f"data[{index - 1}]"
    else:
        yield _mapping(data, "data"), scope, "data"


def _timestamp(value, default_zone=None, *, csv_export=False):
    match = ISO_TIME.fullmatch(value.strip())
    if match is not None:
        zone = _offset(match["zone"]) if match["zone"] else default_zone
        if zone is None:
            return None
        seconds = match["seconds"]
        if len(seconds) == 16:
            seconds += ":00"
        fraction = (match["fraction"] or "").ljust(6, "0")[:6]
        return datetime.fromisoformat(f"{seconds}.{fraction}").replace(tzinfo=zone).astimezone(timezone.utc)
    if csv_export and (named := CSV_NAMED_TIME.fullmatch(value.strip())):
        zone = _offset(named["zone"]) if named["zone"] else default_zone
        if zone is None:
            return None
        clock = named["clock"]
        if clock.count(":") == 1:
            clock += ":00"
        period = named["period"] or ""
        clock_format = "%I:%M:%S %p" if period else "%H:%M:%S"
        month_format = "%b" if len(named["date"].split()[0]) == 3 else "%B"
        instant = datetime.strptime(f"{named['date']} {clock}{period.upper()}", f"{month_format} %d, %Y {clock_format}")
        return instant.replace(tzinfo=zone).astimezone(timezone.utc)
    return None


def _csv_fields(row):
    fields = {relation: value for relation, keys in CSV_FIELDS.items() if (value := _first(row, keys)) is not None}
    if "activity" not in fields and "action-id" not in fields:
        raise ValueError("The CSV row is missing its activity.")
    timestamp_column = next((key for key in CSV_TIMESTAMP if _text(row.get(key))), None)
    time_columns = [timestamp_column] if timestamp_column else []
    if timestamp_column is None:
        for aliases in (CSV_DATE, CSV_CLOCK):
            if column := next((key for key in aliases if _text(row.get(key))), None):
                time_columns.append(column)
    time = " ".join(row[key] for key in time_columns)
    fields["event-time-raw"] = _required(time, "CSV event time")
    if event_id := _first(row, ("eventid", "auditid", "recordid")):
        fields["event-id"] = event_id
    actor = fields.get("actor-name", "")
    if "actor-email-raw" not in fields and EMAIL.fullmatch(actor):
        fields["actor-email-raw"] = actor
    return fields, any(column.endswith("utc") for column in time_columns)


def _principal(record, prefix):
    return _select(record, {"id": f"{prefix}-id", "name": f"{prefix}-name", "email": f"{prefix}-email-raw"})


def _api_fields(record, envelope_scope, budget):
    record = _mapping(record, "Organizations Events API event")
    if record.get("type") != "events":
        raise ValueError("Expected an Organizations Events API event with type events.")
    attrs = _mapping(record.get("attributes"), "attributes")
    fields = {
        "event-id": _required(record.get("id"), "event id"),
        "action-id": _required(attrs.get("action"), "attributes.action"),
        "event-time-raw": _required(attrs.get("time"), "attributes.time"),
    }
    actor = _mapping(attrs.get("actor") or {}, "attributes.actor")
    fields.update(_principal(actor, "actor"))
    fields.update(_principal(_mapping(actor.get("onBehalfOf") or {}, "actor.onBehalfOf"), "on-behalf-of"))
    fields.update(
        _select(
            _mapping(actor.get("auth") or {}, "actor.auth"),
            {"authType": "auth-type", "tokenId": "token-id", "tokenLabel": "token-label"},
        )
    )
    app = _mapping(actor.get("app") or {}, "actor.app")
    fields.update(_select(app, {"id": "app-id", "type": "app-type"}))
    app_attrs = _mapping(app.get("attributes") or {}, "actor.app.attributes")
    if app_name := _first(app_attrs, ("name", "displayName")):
        fields["app-name"] = app_name
    fields.update(
        _select(
            _mapping(attrs.get("location") or {}, "attributes.location"),
            {
                "ip": "source-address",
                "geo": "location",
                "countryName": "country",
                "regionName": "region",
                "city": "city",
            },
        )
    )
    fields.update(_select(attrs, {"processedAt": "processed-time-raw"}))
    message = _mapping(record.get("message") or {}, "message")
    fields.update(_select(message, {"format": "message-format"}))
    scope = _scope_from_links(record.get("links")) or envelope_scope
    if scope:
        fields["organization-id"] = scope

    entities = []
    for role in ("context", "container"):
        items = attrs.get(role)
        items = [] if items is None else _array(items, f"attributes.{role}")
        if len(entities) + len(items) > budget:
            raise ValueError(f"Export exceeds {MAX_ENTITIES:,} audit entities. Upload a smaller export.")
        for index, item in enumerate(items):
            source = f"attributes.{role}[{index}]"
            item = _mapping(item, source)
            entity = {"entity-role": role, "entity-id": _required(item.get("id"), f"{source}.id")}
            entity.update(_select(item, {"type": "entity-type"}))
            metadata = _mapping(item.get("attributes") or {}, f"{source}.attributes")
            if name := _first(metadata, ("name", "displayName", "title", "siteName", "url")):
                entity["entity-name"] = name
            entity.update(_select(metadata, {"key": "entity-key", "email": "entity-email-raw"}))
            entity.update(_select(_mapping(item.get("links") or {}, f"{source}.links"), {"self": "source-link"}))
            entities.append((source, entity))
    return fields, entities


def _scope_fields(fields, entities, options):
    if "organization-id" not in fields:
        organizations = {
            entity["entity-id"]
            for _, entity in entities
            if entity["entity-role"] == "container" and _header(entity.get("entity-type", "")) in ORG_KINDS
        }
        if len(organizations) == 1:
            fields["organization-id"] = organizations.pop()
        elif not organizations and (scope := options.get("organization_id")):
            fields["organization-id"] = scope
    scopes = []
    if "site-id" in fields or "site" in fields:
        scopes.append((fields.pop("site-id", None), fields.pop("site", None)))
    for _, entity in entities:
        if entity["entity-role"] == "container" and _header(entity.get("entity-type", "")) in SITE_KINDS:
            scopes.append((entity["entity-id"], entity.get("entity-name")))
    if not scopes and options.get("site"):
        scopes.append((None, options["site"]))
    return scopes


def _add_fields(obj, values):
    for relation, value in values.items():
        if relation.endswith("-email-raw") and EMAIL.fullmatch(value):
            _add(obj, relation.removesuffix("-raw"), value)
        elif relation in ("actor-id", "on-behalf-of-id") and value.casefold() in PLACEHOLDERS | {"system", "0"}:
            _add(obj, relation, value, disable_correlation=True)
        else:
            _add(obj, relation, value)


def _add_ip(obj, address):
    if not address or "%" in address:
        return
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return
    if not ip.is_unspecified:
        _add(obj, "ip-src", str(ip))


def _raw_record(obj, evidence):
    if len(evidence) <= MAX_RAW_ATTRIBUTE:
        _add(obj, "raw-record", evidence)
        return
    total = (len(evidence) + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
    for index, offset in enumerate(range(0, len(evidence), FRAGMENT_SIZE), 1):
        # JSON string delimiters preserve whitespace when the MISP attribute is trimmed.
        part = json.dumps(evidence[offset : offset + FRAGMENT_SIZE], ensure_ascii=True)
        _add(obj, "raw-record-fragment", part, key=index, comment=f"Part {index} of {total}")


def _event_object(fields, sites, identity, time, evidence, source, position, format_):
    obj = _object(EVENT, *identity)
    _add_fields(obj, fields)
    _add(obj, "source-format", format_)
    if time is not None:
        obj.first_seen = obj.last_seen = time
        _add(obj, "event-time", time.isoformat())
    for relation, column in (("site-id", 0), ("site", 1)):
        for value in dict.fromkeys(pair[column] for pair in sites if pair[column] is not None):
            _add(obj, relation, value, key=value)
    _add_ip(obj, fields.get("source-address"))
    _raw_record(obj, evidence)
    _reference(obj, source, "extracted-from", position)
    return obj


def _import(request):
    request = _mapping(request, "Import request")
    options, attach = _options(request)
    raw, payload = _upload(request)
    warnings = set()
    format_ = "json" if payload.lstrip().startswith(("{", "[")) else "csv"
    records = _api_records(loads(payload), warnings) if format_ == "json" else _csv_records(payload)
    digest = hashlib.sha256(raw).hexdigest()
    source = _source(request, raw, digest, format_, attach)
    seen = {}
    events, entities = [], []
    count = uncertain = entity_count = 0
    for count, (record, metadata, position) in enumerate(records, 1):
        try:
            if count > MAX_RECORDS:
                raise ValueError(f"Export exceeds {MAX_RECORDS:,} audit events. Upload a smaller export.")
            assumed_zone = None
            if format_ == "csv":
                fields, utc_header = _csv_fields(metadata)
                details = []
                assumed_zone = timezone.utc if utc_header else options.get("csv_utc_offset")
            else:
                fields, details = _api_fields(record, metadata, MAX_ENTITIES - entity_count)
            sites = _scope_fields(fields, details, options)
            evidence = dumps(record)
            native_id = fields.get("event-id")
            if native_id and native_id.casefold() not in PLACEHOLDERS:
                identity = ("event", fields.get("organization-id", ""), native_id)
                signature = hashlib.sha256(evidence.encode("ascii")).digest()
                if identity in seen:
                    if seen[identity] != signature:
                        raise ValueError("Conflicting records share the same organization and event ID.")
                    continue
                seen[identity] = signature
            else:
                identity = ("source", source.uuid, position)
            try:
                time = _timestamp(fields["event-time-raw"], assumed_zone, csv_export=format_ == "csv")
            except (ValueError, OverflowError):
                if format_ == "json":
                    raise
                time = None
            if time is None:
                if format_ == "json":
                    raise ValueError("attributes.time must be an ISO timestamp with a known UTC offset.")
                uncertain += 1
            event = _event_object(fields, sites, identity, time, evidence, source, position, format_)
            for path, values in details:
                entity = _object(ENTITY, event.uuid, path)
                _add_fields(entity, values)
                _reference(event, entity, "contains", path)
                entities.append(json.loads(entity.to_json(strict=True)))
            events.append(json.loads(event.to_json(strict=True)))
            entity_count += len(details)
        except (ValueError, OverflowError) as error:
            raise ValueError(f"{position}: {error}") from error
    if not events:
        raise ValueError(" ".join(["The export contains no audit events.", *sorted(warnings)]))
    if uncertain:
        warnings.add(f"{uncertain:,} CSV timestamps were retained as text because a UTC time could not be determined.")
    return {
        "results": {"Object": [json.loads(source.to_json(strict=True)), *events, *entities]},
        "summary": {
            "format": format_,
            "records": count,
            "events": len(events),
            "entities": entity_count,
            "duplicate_records": count - len(events),
            "csv_timestamps_without_utc": uncertain,
            "source_sha256": digest,
            "source_attached": attach,
        },
        "warnings": sorted(warnings),
    }


def handler(q=False):
    if q is False:
        return False
    try:
        return _import(json.loads(q))
    except (binascii.Error, UnicodeError, json.JSONDecodeError, OSError, EOFError, zlib.error, RecursionError):
        return {"error": "Unable to decode the upload. Supply Atlassian audit logs as UTF-8 JSON or CSV, or gzip."}
    except (ValueError, csv.Error) as error:
        return {"error": f"Unable to import Atlassian Cloud audit logs: {error}"}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import Atlassian Cloud audit logs. Check the request and object templates."}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "organization_id": {"type": "String", "message": "Organization ID when the export does not report one"},
            "site": {"type": "String", "message": "Site name or URL when the export does not report one"},
            "csv_utc_offset": {"type": "String", "message": "Known UTC offset for local CSV times, such as +00:00"},
            "include_source": {"type": "Boolean", "message": "Attach the exact source audit export"},
        },
    }


def version():
    return dict(moduleinfo, config=[])
