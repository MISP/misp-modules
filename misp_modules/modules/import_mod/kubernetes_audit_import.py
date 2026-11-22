"""Import saved Kubernetes API audit events and their EKS and AKS export wrappers."""

import base64
import binascii
import gzip
import hashlib
import ipaddress
import json
import re
import zlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    "name": "Kubernetes API Audit Logs Import",
    "description": "Import Kubernetes API audit events and group stages by cluster and audit ID.",
    "module-type": ["import"],
    "data-source": "internal",
    "requirements": ["PyMISP"],
    "features": (
        "Reads native audit.k8s.io/v1 JSON Lines, EKS CloudWatch Logs and AKS diagnostic or Log Analytics JSON."
        " Preserves each stage, the reported identity, API target and response, and links them to the request and"
        " original export. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/"
        "import_mod/kubernetes_audit_import.md)."
    ),
    "references": [
        "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/",
        "https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/",
        "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
        "https://learn.microsoft.com/en-us/azure/aks/monitor-aks-reference",
    ],
    "input": "Native Kubernetes audit v1 JSON Lines or JSON, EKS CloudWatch Logs JSON, or AKS diagnostic JSON.",
    "output": "A source file and linked Kubernetes audit request and stage objects.",
}

REQUEST = "kubernetes-audit-request"
STAGE = "kubernetes-audit-stage"
AUDIT_VERSION = "audit.k8s.io/v1"
NAMESPACE = UUID("34b097b0-c2af-4016-a4ae-74ae19eddbf1")
MAX_UPLOAD = 10 * 1024 * 1024
MAX_PAYLOAD = 20 * 1024 * 1024
MAX_STAGES = 2000
MAX_ROWS = 4000
MAX_TEXT = 4096
MAX_VALUES = 256
STAGES = {"RequestReceived": 0, "ResponseStarted": 1, "ResponseComplete": 2, "Panic": 2}
AKS_CATEGORIES = {"kube-audit", "kube-audit-admin"}
AKS_FIELDS = {
    "AuditId": "auditID",
    "Level": "level",
    "Stage": "stage",
    "RequestUri": "requestURI",
    "Verb": "verb",
    "User": "user",
    "ImpersonatedUser": "impersonatedUser",
    "UserAgent": "userAgent",
    "SourceIps": "sourceIPs",
    "ObjectRef": "objectRef",
    "ResponseStatus": "responseStatus",
    "RequestReceivedTime": "requestReceivedTimestamp",
    "StageReceivedTime": "stageTimestamp",
    "Annotations": "annotations",
    "RequestObject": "requestObject",
    "ResponseObject": "responseObject",
}
AKS_DYNAMIC = {
    "User",
    "ImpersonatedUser",
    "SourceIps",
    "ObjectRef",
    "ResponseStatus",
    "Annotations",
    "RequestObject",
    "ResponseObject",
}
TIMESTAMP = re.compile(
    r"(?P<seconds>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<offset>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
OBJECT_FIELDS = {
    "namespace": "namespace",
    "resource": "resource",
    "subresource": "subresource",
    "name": "object-name",
    "uid": "object-uid",
    "apiGroup": "api-group",
    "apiVersion": "object-api-version",
}


@dataclass
class ExportRecord:
    event: dict
    position: str
    format: str
    cluster: str | None = None
    provider: dict = field(default_factory=dict)


@dataclass
class AuditStage:
    record: ExportRecord
    digest: str
    context: dict
    received: tuple[datetime, int] | None
    observed: tuple[datetime, int] | None


@lru_cache(maxsize=2)
def _template(name):
    path = resources.files("misp_modules").joinpath("data", "kubernetes-audit", name, "definition.json")
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


def _link(obj, target, relationship, comment=None):
    ref = obj.add_reference(target.uuid, relationship, comment)
    ref.uuid = _uuid(UUID(obj.uuid), relationship, target.uuid)


def _text(value, *, multiline=False):
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        return None
    if not all(c.isprintable() or (multiline and c in "\r\n\t") for c in value):
        return None
    return value


def _identifier(value, name):
    text = _text(value)
    if text is None or text != text.strip():
        raise ValueError(f"{name} must be nonempty printable text without leading or trailing whitespace.")
    return text


def _mapping(value, name):
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object.")
    return value


def _array(value, name):
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array.")
    return value


def _selected(record, fields):
    return {relation: value for key, relation in fields.items() if (value := _text(record.get(key))) is not None}


def _options(request):
    config = request.get("config")
    config = {} if config is None else _mapping(config, "config")
    cluster = config.get("cluster_id")
    if cluster not in (None, ""):
        cluster = _identifier(cluster, "Cluster ID")
    attach = config.get("include_source")
    if isinstance(attach, str):
        value = attach.strip().lower()
        if value in ("true", "yes", "1"):
            attach = True
        elif value in ("", "false", "no", "0"):
            attach = False
    if attach is not None and not isinstance(attach, bool):
        raise ValueError("include_source must be a boolean.")
    return cluster or None, bool(attach)


def _decode_upload(raw, limit):
    payload = raw
    if raw.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=BytesIO(raw)) as stream:
            payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("Decompressed export exceeds 20 MiB.")
    return payload


def _upload(request):
    data = request.get("data")
    if not isinstance(data, str) or len(data) > 4 * ((MAX_UPLOAD + 2) // 3):
        raise ValueError("Provide a base64 upload of at most 10 MiB.")
    raw = base64.b64decode(data, validate=True)
    if not raw or len(raw) > MAX_UPLOAD:
        raise ValueError("Upload must contain between 1 byte and 10 MiB.")
    return raw, _decode_upload(raw, MAX_PAYLOAD).decode("utf-8-sig")


def _source(request, raw, digest, attach):
    filename = request.get("filename")
    if filename in (None, ""):
        filename = "kubernetes-audit.json.gz" if raw.startswith(b"\x1f\x8b") else "kubernetes-audit.json"
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


def _documents(payload):
    if not payload.strip():
        raise ValueError("The export contains no audit events.")
    try:
        document = loads(payload)
    except json.JSONDecodeError as error:
        if error.msg != "Extra data" or not payload.lstrip().startswith("{"):
            raise
        for line, text in enumerate(StringIO(payload), 1):
            if text.strip():
                try:
                    document = loads(text)
                except ValueError as error:
                    raise ValueError(f"JSON Lines line {line}: {error}") from error
                yield document, f"JSON Lines line {line}"
        return
    if isinstance(document, list):
        yield from ((row, f"JSON record {index}") for index, row in enumerate(document, 1))
    else:
        yield document, "JSON document"


def _native(record, *, list_item=False):
    record = _mapping(record, "Kubernetes audit event")
    if (
        record.get("apiVersion", AUDIT_VERSION if list_item else None) != AUDIT_VERSION
        or record.get("kind", "Event" if list_item else None) != "Event"
    ):
        raise ValueError("Expected a native audit.k8s.io/v1 Event.")
    return dict(record, apiVersion=AUDIT_VERSION, kind="Event")


def _embedded(value):
    return loads(value) if isinstance(value, str) else value


def _subscription(envelope, remaining):
    data = _mapping(envelope, "awslogs").get("data")
    if not isinstance(data, str) or len(data) > 4 * ((MAX_UPLOAD + 2) // 3):
        raise ValueError("Expected a base64 CloudWatch subscription payload of at most 10 MiB.")
    payload = _decode_upload(base64.b64decode(data, validate=True), remaining)
    document = _mapping(loads(payload.decode("utf-8-sig")), "CloudWatch subscription payload")
    if "logEvents" not in document:
        raise ValueError("CloudWatch subscription payload is missing logEvents.")
    return document, len(payload)


def _cloudwatch(row, envelope, position):
    row = _mapping(row, "CloudWatch event")
    stream = _text(row.get("logStreamName")) or _text(envelope.get("logStream"))
    group = _text(envelope.get("logGroup"))
    account = _text(envelope.get("owner"))
    if stream and stream.startswith(
        ("kube-apiserver-", "authenticator-", "kube-scheduler-", "kube-controller-manager-")
    ):
        if stream != "kube-apiserver-audit" and not stream.startswith("kube-apiserver-audit-"):
            return None
    if "message" not in row:
        raise ValueError("CloudWatch event is missing message.")
    cluster = f"{account}:{group}" if account and group else group
    provider = _selected(row, {"eventId": "provider-event-id", "id": "provider-event-id"})
    for key, value in (
        ("provider-log-stream", stream),
        ("provider-log-group", group),
        ("provider-account-id", account),
    ):
        if value is not None:
            provider[key] = value
    return ExportRecord(_native(_embedded(row["message"])), position, "eks-cloudwatch", cluster, provider)


def _azure(row, position):
    resource = next(
        (value for key in ("_ResourceId", "resourceId", "ResourceId") if (value := _text(row.get(key)))), None
    )
    category = _text(row.get("category")) or _text(row.get("Category"))
    provider = _selected(row, {"PodName": "provider-pod", "Type": "provider-table"})
    if resource:
        provider["provider-resource-id"] = resource
    if category and category not in AKS_CATEGORIES:
        return None
    if category:
        properties = _mapping(row.get("properties", {}), "Azure diagnostic properties")
        log = properties.get("log", row.get("log_s", row.get("log")))
        provider["provider-category"] = category
        return ExportRecord(_native(_embedded(log)), position, "aks-diagnostics", resource, provider)
    if "AuditId" not in row or row.get("Type") not in (None, "", "AKSAudit", "AKSAuditAdmin"):
        raise ValueError("Expected an AKSAudit or AKSAuditAdmin record.")
    event = {"apiVersion": AUDIT_VERSION, "kind": "Event"}
    for column, key in AKS_FIELDS.items():
        value = row.get(column)
        if value in (None, ""):
            continue
        if column in AKS_DYNAMIC and isinstance(value, str) and value.lstrip().startswith(("{", "[")):
            value = loads(value)
        event[key] = value
    return ExportRecord(event, position, "aks-log-analytics", resource, provider)


def _table_records(tables):
    for index, table in enumerate(_array(tables, "Log Analytics tables"), 1):
        table = _mapping(table, "Log Analytics table")
        names = [
            _identifier(_mapping(column, "column").get("name"), "column name")
            for column in _array(table.get("columns"), "Log Analytics columns")
        ]
        if len(names) > MAX_VALUES or len(names) != len(set(names)):
            raise ValueError(f"Log Analytics table {index} must have at most {MAX_VALUES} unique columns.")
        for offset, values in enumerate(_array(table.get("rows"), "Log Analytics rows"), 1):
            if not isinstance(values, list) or len(values) != len(names):
                raise ValueError(f"Log Analytics table {index} row {offset} has the wrong number of columns.")
            yield dict(zip(names, values, strict=True)), f"tables[{index - 1}].rows[{offset - 1}]"


def _records(document, position, warnings):
    record = _mapping(document, "Export record")
    if record.get("kind") == "EventList" and record.get("apiVersion") == AUDIT_VERSION:
        for i, item in enumerate(_array(record.get("items"), "EventList items")):
            path = f"{position}.items[{i}]"
            yield _at_position(path, lambda: ExportRecord(_native(item, list_item=True), path, "native"))
    elif "logEvents" in record or "events" in record:
        key = "logEvents" if "logEvents" in record else "events"
        if record.get("nextToken"):
            warnings.add("The CloudWatch response has another page. Import the remaining saved pages separately.")
        elif record.get("nextForwardToken") or record.get("nextBackwardToken"):
            warnings.add(
                "The CloudWatch GetLogEvents response has pagination tokens. "
                "Verify that all pages for the requested time range were collected."
            )
        for i, row in enumerate(_array(record.get(key), f"CloudWatch {key}")):
            path = f"{position}.{key}[{i}]"
            yield _at_position(path, lambda: _cloudwatch(row, record, path))
    elif "tables" in record or "records" in record:
        if "tables" in record:
            rows = _table_records(record["tables"])
            if record.get("error"):
                warnings.add("Log Analytics reported an error alongside the returned rows.")
        else:
            rows = ((row, f"records[{i}]") for i, row in enumerate(_array(record["records"], "Azure records")))
        for row, label in rows:
            path = f"{position}.{label}"
            yield _at_position(path, lambda: _azure(_mapping(row, "Azure record"), path))
    elif "AuditId" in record or "category" in record or "Category" in record:
        yield _azure(record, position)
    elif "message" in record and "logStreamName" in record:
        yield _cloudwatch(record, {}, position)
    else:
        yield ExportRecord(_native(record), position, "native")


def _at_position(position, parse):
    try:
        return parse()
    except (ValueError, OverflowError) as error:
        raise ValueError(f"{position}: {error}") from error


def _timestamp(value, name):
    if value in (None, ""):
        return None
    match = TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None or match["offset"] == "-00:00":
        raise ValueError(f"{name} requires an RFC 3339 timestamp with a known UTC offset.")
    offset = "+00:00" if match["offset"] == "Z" else match["offset"]
    fraction = (match["fraction"] or "").ljust(9, "0")
    observed = datetime.fromisoformat(f"{match['seconds']}.{fraction[:6]}{offset}").astimezone(timezone.utc)
    return observed, int(fraction[6:])


def _context(event):
    result = _selected(event, {"verb": "verb", "requestURI": "request-uri"})
    user = _mapping(event.get("user") or {}, "user")
    result.update(_selected(user, {"username": "username", "uid": "user-uid"}))
    impersonated = _mapping(event.get("impersonatedUser") or {}, "impersonatedUser")
    result.update(_selected(impersonated, {"username": "impersonated-username", "uid": "impersonated-user-uid"}))
    username = result.get("username", "")
    parts = username.split(":")
    if len(parts) == 4 and parts[:2] == ["system", "serviceaccount"] and all(parts[2:]):
        result["service-account"] = "/".join(parts[2:])
    result.update(_selected(_mapping(event.get("objectRef") or {}, "objectRef"), OBJECT_FIELDS))
    return result


def _scope(record, cluster, digest):
    label = record.cluster or cluster
    if not label:
        return ("upload", digest), None
    # Azure ARM resource IDs are case-insensitive. CloudWatch log groups are case-sensitive.
    azure_scope = (record.cluster and record.format.startswith("aks-")) or label.casefold().startswith(
        "/subscriptions/"
    )
    scope = label.casefold() if azure_scope else label
    return ("cluster", scope), label


def _stage_row(record):
    event = record.event
    _identifier(event.get("stage"), "stage")
    _identifier(event.get("auditID"), "auditID")
    received = _timestamp(event.get("requestReceivedTimestamp"), "requestReceivedTimestamp")
    observed = _timestamp(event.get("stageTimestamp"), "stageTimestamp")
    digest = hashlib.sha256(dumps(event).encode("ascii")).hexdigest()
    return AuditStage(record, digest, _context(event), received, observed)


def _reported_list(value, path):
    items = _array(value, path)
    if len(items) > MAX_VALUES:
        raise ValueError(f"{path} exceeds {MAX_VALUES} entries.")
    for index, item in enumerate(items):
        if (text := _text(item)) is not None:
            yield index, text


def _stage_object(request, row, source):
    event = row.record.event
    stage = _object(STAGE, request.uuid, row.digest)
    fields = {
        "audit-id": event["auditID"],
        "stage": event["stage"],
        "source-format": row.record.format,
        **row.context,
        **row.record.provider,
    }
    fields.update(
        _selected(
            event,
            {
                "level": "audit-level",
                "requestReceivedTimestamp": "request-time-raw",
                "stageTimestamp": "stage-time-raw",
                "userAgent": "user-agent",
            },
        )
    )
    if row.received:
        fields["request-time"] = row.received[0].isoformat()
    if row.observed:
        fields["stage-time"] = row.observed[0].isoformat()
        stage.first_seen = stage.last_seen = row.observed[0]
    response = _mapping(event.get("responseStatus") or {}, "responseStatus")
    fields.update(_selected(response, {"status": "response-status", "reason": "response-reason"}))
    if type(response.get("code")) is int:
        fields["response-code"] = str(response["code"])
    if message := _text(response.get("message"), multiline=True):
        fields["response-message"] = message
    annotations = _mapping(event.get("annotations") or {}, "annotations")
    fields.update(
        _selected(
            annotations,
            {
                "authorization.k8s.io/decision": "authorization-decision",
                "authorization.k8s.io/reason": "authorization-reason",
            },
        )
    )
    for relation, value in fields.items():
        _add(stage, relation, value)
    for principal_field, relation in (("user", "user-group"), ("impersonatedUser", "impersonated-user-group")):
        principal = _mapping(event.get(principal_field) or {}, principal_field)
        path = f"{principal_field}.groups"
        for index, group in _reported_list(principal.get("groups") or [], path):
            _add(stage, relation, group, key=index, comment=f"{path}[{index}]")
    addresses = event.get("sourceIPs") or []
    for index, address in _reported_list(addresses, "sourceIPs"):
        _add(stage, "source-address", address, key=index, comment=f"sourceIPs[{index}]")
        if "%" in address:
            continue
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not ip.is_unspecified:
            _add(stage, "ip-src", str(ip), key=index, comment=f"sourceIPs[{index}]")
    _link(stage, source, "extracted-from", row.record.position)
    _link(request, stage, "contains", event["stage"])
    return stage


def _request_objects(groups, source):
    parents, children = [], []
    for (scope, audit_id), (cluster, rows) in groups.items():
        request = _object(REQUEST, *scope, audit_id)
        _add(request, "audit-id", audit_id)
        if cluster:
            _add(request, "cluster-id", cluster)
        received = [row.received for row in rows if row.received]
        observed = [row.observed for row in rows if row.observed]
        if received:
            _add(request, "request-time", min(received)[0].isoformat())
        if observed:
            _add(request, "last-stage-time", max(observed)[0].isoformat())
        if received or observed:
            request.first_seen = min(received + observed)[0]
            request.last_seen = max(received + observed)[0]
        context = max(rows, key=lambda row: len(row.context)).context
        for relation, value in context.items():
            _add(request, relation, value)
        _link(request, source, "extracted-from")
        parents.append(request)
        ordered = sorted(
            rows, key=lambda row: (row.observed is None, row.observed, STAGES.get(row.record.event["stage"], 3))
        )
        for row in ordered:
            children.append(_at_position(row.record.position, lambda: _stage_object(request, row, source)))
    return parents, children


def _import(request):
    request = _mapping(request, "Import request")
    cluster, attach = _options(request)
    raw, payload = _upload(request)
    digest = hashlib.sha256(raw).hexdigest()
    source = _source(request, raw, digest, attach)
    warnings, seen = set(), set()
    groups = {}
    formats = Counter()
    total = skipped = duplicates = 0
    remaining_subscription_bytes = MAX_PAYLOAD
    for document, position in _documents(payload):
        try:
            if isinstance(document, dict) and "awslogs" in document:
                document, size = _subscription(document["awslogs"], remaining_subscription_bytes)
                remaining_subscription_bytes -= size
                position += ".awslogs.data"
            for record in _records(document, position, warnings):
                total += 1
                if total > MAX_ROWS:
                    raise ValueError(f"Export exceeds {MAX_ROWS:,} rows. Upload a smaller export.")
                if record is None:
                    skipped += 1
                    continue
                scope, label = _scope(record, cluster, digest)
                row = _at_position(record.position, lambda: _stage_row(record))
                identity = (scope, record.event["auditID"])
                key = (identity, row.digest)
                if key in seen:
                    duplicates += 1
                    continue
                if len(seen) >= MAX_STAGES:
                    raise ValueError(f"Export exceeds {MAX_STAGES:,} unique stages. Upload a smaller export.")
                seen.add(key)
                groups.setdefault(identity, (label, []))[1].append(row)
                formats[record.format] += 1
        except (ValueError, OverflowError) as error:
            raise ValueError(f"{position}: {error}") from error
    if not groups:
        message = "The export contains no Kubernetes audit events."
        raise ValueError(" ".join([message, *sorted(warnings)]))
    parents, children = _request_objects(groups, source)
    if skipped:
        warnings.add(f"Skipped {skipped:,} records from non-audit categories or streams.")
    return {
        "results": {"Object": [json.loads(obj.to_json(strict=True)) for obj in [source, *parents, *children]]},
        "summary": {
            "requests": len(parents),
            "stages": len(children),
            "duplicate_stages": duplicates,
            "skipped_rows": skipped,
            "formats": dict(formats),
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
        return {"error": "Unable to decode the upload. Supply Kubernetes audit exports as UTF-8 JSON or gzip."}
    except (TypeError, PyMISPError):
        return {"error": "Unable to import Kubernetes API audit logs. Check the request and object templates."}
    except ValueError as error:
        return {"error": f"Unable to import Kubernetes API audit logs: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "cluster_id": {"type": "String", "message": "Cluster identifier when the export does not report one"},
            "include_source": {"type": "Boolean", "message": "Attach the exact source audit export"},
        },
    }


def version():
    return dict(moduleinfo, config=[])
