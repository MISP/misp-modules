"""Import saved GitHub Enterprise audit and Git event exports."""

import base64
import binascii
import csv
import gzip
import hashlib
import ipaddress
import json
import re
import zlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO, StringIO
from uuid import UUID, uuid5

from pymisp import MISPObject
from pymisp.exceptions import PyMISPError

from misp_modules.lib.network_observation import dumps, loads

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "GitHub Enterprise Audit Logs Import",
    "description": "Import saved GitHub organization and enterprise audit logs and Git events.",
    "module-type": ["import"],
    "data-source": "internal",
    "requirements": ["PyMISP"],
    "features": (
        "Reads audit log JSON and CSV, including GitHub's separate gzip-compressed Git-event JSON Lines export."
        " Keeps reported enterprise, organization and repository scope and exposes actor, membership, policy and"
        " application fields. Links every event to the source file. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/"
        "github_enterprise_audit_import.md)."
    ),
    "references": [
        (
            "https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/"
            "reviewing-audit-logs-for-your-enterprise/exporting-audit-log-activity-for-your-enterprise"
        ),
        (
            "https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/"
            "reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise"
        ),
    ],
    "input": "Saved GitHub audit events as JSON, JSON Lines or CSV, optionally gzip-compressed.",
    "output": "A source file and linked GitHub audit event objects.",
}

EVENT = "github-audit-event"
NAMESPACE = UUID("25acb671-df00-45c7-9a74-0893bb093dff")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_UPLOAD = 10 * 1024 * 1024
MAX_PAYLOAD = 20 * 1024 * 1024
MAX_RECORDS = 1000
MAX_COLUMNS = 1024
MAX_RECORD_SIZE = 256 * 1024
MAX_TEXT = 4096
MAX_RAW_ATTRIBUTE = 32 * 1024
FRAGMENT_SIZE = 15 * 1024
ACTION = re.compile(r"[a-zA-Z0-9_-]+\.[a-zA-Z0-9_.-]+")
HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
LOGIN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]*(?:\[bot\])?")
APPLICATION_CLIENT_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*")
FULL_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]*/[a-zA-Z0-9_.-]+")
ISO_TIME = re.compile(
    r"(?P<seconds>[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<offset>Z| UTC|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)

SCOPE_FIELDS = {
    "enterprise": ("business", "enterprise"),
    "enterprise-id": ("business_id", "enterprise_id"),
    "organization": ("org", "organization"),
    "organization-id": ("org_id", "organization_id"),
    "repository": ("repo", "repository"),
    "repository-id": ("repo_id", "repository_id"),
}
DETAIL_FIELDS = {
    "actor-id": ("actor_id",),
    "target-user-id": ("user_id",),
    "team": ("team",),
    "operation-type": ("operation_type",),
    "permission": ("permission",),
    "old-permission": ("old_permission",),
    "visibility": ("visibility",),
    "previous-visibility": ("previous_visibility",),
    "ruleset-id": ("ruleset_id",),
    "ruleset-name": ("ruleset_name",),
    "default-workflow-permissions": ("default_workflow_permissions_value",),
    "integration": ("integration",),
    "oauth-application-id": ("oauth_application_id",),
    "application-client-id": ("application_client_id",),
    "repository-selection": ("repository_selection",),
    "access-type": ("programmatic_access_type",),
    "request-id": ("request_id",),
    "transport": ("transport_protocol_name", "transport_protocol"),
    "git-external-id": ("external_id",),
    "source-address": ("actor_ip",),
    "source-country-code": ("actor_location.country_code",),
    "user-agent": ("user_agent",),
}
ACCOUNT_FIELDS = {"actor": ("actor",), "target-user": ("user", "target_login"), "previous-user": ("old_user",)}
BOOLEAN_VALUES = {"true": "1", "false": "0", "1": "1", "0": "0"}
PLACEHOLDERS = {"none", "null", "unknown", "redacted", "n/a"}


@lru_cache(maxsize=1)
def _template():
    definition = resources.files("misp_modules").joinpath("data", EVENT, "definition.json")
    return json.loads(definition.read_text(encoding="utf-8"))


def _uuid(namespace, *parts):
    return str(uuid5(namespace, dumps(parts)))


def _add(obj, relation, value, *, key=None, **kwargs):
    attr = obj.add_attribute(relation, value=value, to_ids=False, **kwargs)
    attr.uuid = _uuid(UUID(obj.uuid), relation, key)


def _options(request):
    config = request.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    host = config.get("github_host", "")
    if not isinstance(host, str):
        raise ValueError("GitHub host must be a hostname.")
    host = host.strip().lower() or "github.com"
    if len(host) > 253 or not HOST.fullmatch(host):
        raise ValueError("GitHub host must be a hostname without a scheme, port or path.")

    attach = config.get("include_source")
    if isinstance(attach, str):
        attach = attach.strip().lower()
        if attach in ("yes", "true", "1"):
            return host, True
        if attach in ("", "no", "false", "0"):
            return host, False
    if attach is None or isinstance(attach, bool):
        return host, bool(attach)
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
            payload = stream.read(MAX_PAYLOAD + 1)
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("Decompressed export exceeds 20 MiB.")
    return raw, payload.decode("utf-8-sig"), compressed


def _source(request, digest, raw, format_, compressed, attach):
    filename = request.get("filename")
    if filename in (None, ""):
        extension = "jsonl" if format_ == "json-lines" else format_
        filename = f"github-audit.{extension}" + (".gz" if compressed else "")
    if not isinstance(filename, str):
        raise ValueError("filename must be text.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255 or not filename.isprintable():
        raise ValueError("Provide a printable basename of at most 255 characters.")
    source = MISPObject("file", strict=True, standalone=False)
    source.uuid = _uuid(NAMESPACE, "file", digest, filename)
    _add(source, "filename", filename)
    _add(source, "sha256", digest)
    _add(source, "size-in-bytes", len(raw))
    if attach:
        _add(source, "attachment", filename, data=BytesIO(raw), disable_correlation=True)
    return source


def _csv_records(payload):
    rows = csv.reader(StringIO(payload, newline=""), strict=True)
    header = next(rows, [])
    columns = set(header)
    if (
        len(header) > MAX_COLUMNS
        or "" in columns
        or len(columns) != len(header)
        or "action" not in columns
        or not columns.intersection(("created_at", "@timestamp"))
    ):
        raise ValueError("Expected GitHub CSV with unique headers, action and a timestamp column.")
    for row in rows:
        if not row:
            continue
        if len(row) != len(header):
            raise ValueError(f"CSV row ending at line {rows.line_num} has the wrong number of columns.")
        yield dict(zip(header, row, strict=True)), f"CSV row ending at line {rows.line_num}"


def _json_lines(payload):
    for line, text in enumerate(StringIO(payload), 1):
        if not text.strip():
            continue
        try:
            yield loads(text), f"JSON Lines line {line}"
        except ValueError as error:
            raise ValueError(f"Invalid JSON Lines at line {line}: {error}") from error


def _records(payload):
    if not payload.strip():
        raise ValueError("The export contains no audit events.")
    if not payload.lstrip().startswith(("[", "{")):
        return _csv_records(payload), "csv"
    try:
        document = loads(payload)
    except json.JSONDecodeError as error:
        if error.msg == "Extra data" and payload.lstrip().startswith("{"):
            return _json_lines(payload), "json-lines"
        raise
    records = document if isinstance(document, list) else [document]
    return ((record, f"JSON record {index}") for index, record in enumerate(records, 1)), "json"


def _scalar(value):
    if type(value) in (int, bool):
        return dumps(value)
    if isinstance(value, str) and value.isprintable() and value.strip() and len(value) <= MAX_TEXT:
        return value
    return None


def _timestamp(value, field):
    if type(value) is int or (isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,16}", value)):
        return EPOCH + timedelta(milliseconds=int(value))
    match = ISO_TIME.fullmatch(value) if isinstance(value, str) else None
    if match is None or match["offset"] == "-00:00":
        raise ValueError(f"{field} must be epoch milliseconds or a timestamp with a known UTC offset.")
    offset = "+00:00" if match["offset"] in ("Z", " UTC") else match["offset"]
    micros = (match["fraction"] or "").ljust(6, "0")[:6]
    return datetime.fromisoformat(f"{match['seconds']}.{micros}{offset}").astimezone(timezone.utc)


def _lookup(record, field):
    if field in record:
        return record[field]
    parent, separator, child = field.partition(".")
    if separator and isinstance(record.get(parent), dict):
        return record[parent].get(child)
    return None


def _details(record, format_):
    details = record.get("data")
    if format_ == "csv" and isinstance(details, str) and details.startswith("{"):
        try:
            details = loads(details)
        except (ValueError, RecursionError):
            return {}
    return details if isinstance(details, dict) else {}


def _field(record, details, aliases):
    for field in aliases:
        for value in (_lookup(record, field), record.get(f"data.{field}"), _lookup(details, field)):
            output = _scalar(value)
            if output is not None:
                return output
    return None


def _usable_name(value, pattern):
    return pattern.fullmatch(value) is not None and len(value) <= 191 and value.casefold() not in PLACEHOLDERS


def _event_fields(event, record, format_, host, action):
    details = _details(record, format_)
    values = {}
    for relation, aliases in (SCOPE_FIELDS | DETAIL_FIELDS).items():
        value = _field(record, details, aliases)
        if value is not None:
            values[relation] = value

    bot_flag = (_field(record, details, ("actor_is_bot",)) or "").strip().casefold()
    if bot_flag in BOOLEAN_VALUES:
        values["actor-is-bot"] = BOOLEAN_VALUES[bot_flag]

    if action.partition(".")[0] in ("integration", "integration_installation", "oauth_application"):
        name = _field(record, details, ("name",))
        if name is not None:
            values["application-name"] = name

    for relation, aliases in ACCOUNT_FIELDS.items():
        value = _field(record, details, aliases)
        if value is None:
            continue
        if _usable_name(value, LOGIN):
            _add(event, relation, value, disable_correlation=host != "github.com")
        else:
            _add(event, f"{relation}-raw", value)

    for relation, value in values.items():
        if relation == "repository":
            _add(event, relation, value, disable_correlation=host != "github.com" or not _usable_name(value, FULL_NAME))
        elif relation == "application-client-id":
            _add(
                event,
                relation,
                value,
                disable_correlation=host != "github.com" or not _usable_name(value, APPLICATION_CLIENT_ID),
            )
        else:
            _add(event, relation, value)

    address = values.get("source-address")
    if address and "%" not in address:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return
        if not ip.is_unspecified:
            _add(event, "ip-src", str(ip))


def _raw_record(event, raw):
    if len(raw) <= MAX_RAW_ATTRIBUTE:
        _add(event, "raw-record", raw)
        return
    total = (len(raw) + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
    for index, offset in enumerate(range(0, len(raw), FRAGMENT_SIZE), 1):
        # Use a JSON string for each fragment so whitespace inside the value survives attribute trimming.
        part = json.dumps(raw[offset : offset + FRAGMENT_SIZE], ensure_ascii=True)
        _add(event, "raw-record-fragment", part, key=index, comment=f"Part {index} of {total}")


def _event(record, raw, identity, format_, host, source, position):
    action = record.get("action")
    if not isinstance(action, str) or len(action) > MAX_TEXT or not ACTION.fullmatch(action):
        raise ValueError("Expected a GitHub audit action such as org.add_member or git.clone.")
    time_field = "created_at" if record.get("created_at") not in (None, "") else "@timestamp"
    time = _timestamp(record.get(time_field), time_field)
    category = action.partition(".")[0]
    event_kind = "git" if category == "git" else "audit"

    event = MISPObject(EVENT, strict=True, standalone=False, misp_objects_template_custom=_template())
    event.uuid = _uuid(NAMESPACE, EVENT, *identity)
    event.first_seen = event.last_seen = time
    _add(event, "action", action)
    _add(event, "action-category", category)
    _add(event, "event-kind", event_kind)
    _add(event, "event-time", time.isoformat())
    _add(event, "github-host", host)
    for field, relation in (
        ("created_at", "created-at-raw"),
        ("@timestamp", "timestamp-raw"),
        ("_document_id", "document-id"),
    ):
        value = _scalar(record.get(field))
        if value is not None:
            _add(event, relation, value)
    _event_fields(event, record, format_, host, action)
    _raw_record(event, raw)
    ref = event.add_reference(source.uuid, "extracted-from", position)
    ref.uuid = _uuid(UUID(event.uuid), "extracted-from", source.uuid)
    return event_kind, event


def _import(request):
    if not isinstance(request, dict):
        raise ValueError("Expected an import request object.")
    host, attach = _options(request)
    raw, payload, compressed = _upload(request)
    records, format_ = _records(payload)
    digest = hashlib.sha256(raw).hexdigest()
    source = _source(request, digest, raw, format_, compressed, attach)
    events, seen = [], {}
    kinds = Counter()
    count = 0
    for count, (record, position) in enumerate(records, 1):
        if count > MAX_RECORDS:
            raise ValueError(f"Export exceeds {MAX_RECORDS:,} audit records. Upload a smaller export.")
        try:
            if not isinstance(record, dict):
                raise ValueError("Each audit record must be an object.")
            evidence = dumps(record)
            if len(evidence) > MAX_RECORD_SIZE:
                raise ValueError("A record exceeds 256 KiB of serialized JSON.")
            native_id = record.get("_document_id")
            if isinstance(native_id, str) and _scalar(native_id) and native_id.casefold() not in PLACEHOLDERS:
                fingerprint = hashlib.sha256(evidence.encode("ascii")).digest()
                if native_id in seen:
                    if seen[native_id] != fingerprint:
                        raise ValueError("Conflicting records share the same _document_id.")
                    continue
                seen[native_id] = fingerprint
                identity = (host, "document", native_id)
            else:
                identity = (host, "source", source.uuid, position)
            kind, event = _event(record, evidence, identity, format_, host, source, position)
            kinds[kind] += 1
            events.append(event)
        except (ValueError, OverflowError) as error:
            raise ValueError(f"{position}: {error}") from error
    if not events:
        raise ValueError("The export contains no audit events.")
    return {
        "results": {"Object": [json.loads(obj.to_json(strict=True)) for obj in [source, *events]]},
        "summary": {
            "format": format_,
            "records": count,
            "events": len(events),
            "duplicate_records": count - len(events),
            "event_kinds": dict(kinds),
            "source_sha256": digest,
            "source_attached": attach,
        },
    }


def handler(q=False):
    if q is False:
        return False
    try:
        return _import(json.loads(q))
    except (binascii.Error, UnicodeError, json.JSONDecodeError, OSError, EOFError, zlib.error, RecursionError):
        return {"error": "Unable to decode the upload. Supply GitHub audit JSON, JSON Lines or CSV as UTF-8 or gzip."}
    except (ValueError, csv.Error) as error:
        return {"error": f"Unable to import GitHub Enterprise audit logs: {error}"}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import GitHub Enterprise audit logs. Check the request and object template."}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "github_host": {"type": "String", "message": "GitHub hostname (defaults to github.com)"},
            "include_source": {"type": "Boolean", "message": "Attach the exact source audit export"},
        },
    }


def version():
    return dict(moduleinfo, config=[])
