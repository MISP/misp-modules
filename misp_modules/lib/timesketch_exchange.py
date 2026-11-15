"""Network-free exchange of selected timeline entries and timestamped observations."""

import ast
import base64
import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO, StringIO
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid5

from pymisp import MISPEvent, MISPObject

MAX_INPUT = 20 * 1024 * 1024
MAX_ROWS = 1000
MAX_ROW = 128 * 1024
MAX_DEPTH = 32
MAX_EXPORT = 5000
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
NAMESPACE = UUID("28a5cb1c-f2a3-48fd-8968-c69b65a494ad")
CONTEXT = {
    "event-id": ("_id", "misp_source_event_id"),
    "source-index": ("_index", "misp_source_index"),
    "sketch-id": ("sketch_id", "misp_source_sketch_id"),
    "timeline-id": ("__ts_timeline_id", "timeline_id", "misp_source_timeline_id"),
    "timeline-name": ("timeline_name", "misp_source_timeline_name"),
    "source-url": ("source_url", "misp_source_url"),
    "parser": ("parser", "misp_source_parser"),
    "data-type": ("data_type", "misp_source_data_type"),
    "display-name": ("display_name", "misp_source_display_name"),
}
ANNOTATIONS = {
    "source-tags": ("tag", "misp_source_tags"),
    "source-labels": ("label", "timesketch_label", "misp_source_labels"),
    "source-comments": ("comment", "misp_source_comments"),
    "pathspec": ("pathspec", "misp_source_pathspec"),
}
OBJECT_TIMES = {
    "file": ("creation-time", "modification-time", "access-time", "compilation-timestamp"),
    "process": ("creation-time", "start-time"),
    "network-connection": ("first-packet-seen", "last-packet-seen"),
    "network-socket": ("first-packet-seen", "last-packet-seen"),
    "windows-event-log-record": ("event-time",),
    "windows-event-log-detection": ("detection-time",),
}
CONTEXT_RELATIONS = {
    "filename",
    "fullpath",
    "path",
    "name",
    "image",
    "pid",
    "computer",
    "channel",
    "provider",
    "event-id",
    "record-id",
    "source-evtx",
    "rule-id",
    "rule-title",
    "source-sha256",
    "ip-src",
    "ip-dst",
    "src-port",
    "dst-port",
}


@lru_cache(maxsize=1)
def template():
    # Identical to MISP/misp-objects/objects/timesketch-timeline/definition.json v4.
    return json.loads(
        resources.files("misp_modules").joinpath("data", "timesketch-timeline", "definition.json").read_text()
    )


def dumps(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Non-finite JSON value: " + value)


def loads(text):
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)


def boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "0", "1"):
        return value.lower() in ("true", "1")
    raise ValueError(f"{name} must be true, false, 1 or 0.")


def _text(value, field):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not str(value).strip() or "\x00" in str(value):
        raise ValueError(f"{field} must be non-empty text or an integer identifier.")
    return str(value)


def _integer(value):
    if (
        isinstance(value, bool)
        or not isinstance(value, (str, int))
        or not re.fullmatch(r"[+-]?[0-9]{1,20}", str(value))
    ):
        raise ValueError("Epoch values must be integer strings or JSON integers.")
    return int(value)


def epoch(value, unit="us"):
    integer = _integer(value)
    if unit == "ns":
        if integer % 1000:
            raise ValueError("Nanosecond time cannot be represented without rounding.")
        integer //= 1000
    elif unit in ("ms", "s"):
        integer *= {"ms": 1000, "s": 1000000}[unit]
    elif unit != "us":
        raise ValueError("Numeric datetime requires an explicit s/ms/us/ns unit.")
    try:
        return EPOCH + timedelta(microseconds=integer)
    except OverflowError:
        raise ValueError("Epoch is outside the supported datetime range.") from None


def instant(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T"
            r" ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
            value,
        )
        or value.endswith("-00:00")
    ):
        raise ValueError("Datetime needs a known offset and at most microsecond precision.")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except OverflowError:
        raise ValueError("Datetime is outside the supported UTC range.") from None


def microseconds(value):
    delta = value - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def resolve_time(date=None, timestamp=None, unit=None):
    date_present, stamp_present = date not in (None, ""), timestamp not in (None, "")
    if not date_present and not stamp_present:
        raise ValueError("No observation time supplied.")
    parsed_date, parsed_stamp, quantum = None, None, 1
    if date_present:
        if isinstance(date, (str, int)) and not isinstance(date, bool) and re.fullmatch(r"[+-]?[0-9]+", str(date)):
            parsed_date = epoch(date, unit)
            quantum = {"s": 1000000, "ms": 1000}.get(unit, 1)
        else:
            parsed_date = instant(date)
    if stamp_present:
        parsed_stamp = epoch(timestamp)
    if parsed_date is not None and parsed_stamp is not None:
        # CLI pandas JSON dates are quantized to the explicitly declared unit.
        difference = microseconds(parsed_stamp) - microseconds(parsed_date)
        if not 0 <= difference < quantum:
            raise ValueError("Source datetime and microsecond timestamp disagree.")
    return parsed_stamp if parsed_stamp is not None else parsed_date


def _bounded(row):
    if not isinstance(row, dict) or not row:
        raise ValueError("Every timeline entry must be a non-empty object.")
    stack = [(row, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ValueError("Timeline entry nesting exceeds 32 levels.")
        if isinstance(value, dict):
            for key in value:
                key.encode("utf-8")
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            value.encode("utf-8")
    if len(dumps(row).encode()) > MAX_ROW:
        raise ValueError("A normalized timeline entry exceeds 128 KiB.")


def _unwrap(data):
    if isinstance(data, dict) and "objects" in data:
        data = data["objects"]  # Timesketch Explore response.
    elif isinstance(data, dict) and isinstance(data.get("hits"), dict):
        data = data["hits"].get("hits")
    return data if isinstance(data, list) else [data]


def read_rows(text, format_):
    automatic = format_ == "auto"
    if automatic:
        format_ = "json" if text.lstrip().startswith(("{", "[")) else "csv"
    if format_ == "json":
        try:
            return _unwrap(loads(text)), "json"
        except json.JSONDecodeError:
            if not automatic or text.lstrip().startswith("["):
                raise
            format_ = "jsonl"
    rows = []
    if format_ == "jsonl":
        for line in text.split("\n"):
            if not line.strip():
                continue
            if len(rows) >= MAX_ROWS:
                raise ValueError("Export exceeds 1000 entries.")
            rows.append(loads(line))
        return rows, "jsonl"
    reader = csv.DictReader(StringIO(text, newline=""), strict=True)
    header = reader.fieldnames
    if not header or any(not key for key in header) or len(set(header)) != len(header):
        raise ValueError("CSV requires unique non-empty headers.")
    for row in reader:
        if len(rows) >= MAX_ROWS:
            raise ValueError("Export exceeds 1000 entries.")
        if None in row or any(value is None for value in row.values()):
            raise ValueError("CSV row does not match the header column count.")
        rows.append(row)
    return rows, "csv"


def _structured(value):
    # pandas CSV exports may contain Python list/dict representations.
    if isinstance(value, str) and value.lstrip().startswith(("[", "{")):
        for parser in (loads, ast.literal_eval):
            try:
                parsed = parser(value)
                if isinstance(parsed, (dict, list)):
                    _bounded({"value": parsed})
                    return parsed
            except (ValueError, SyntaxError, RecursionError):
                pass
    return value


def _annotations(data):
    result = {}
    for relation, aliases in ANNOTATIONS.items():
        values = [_structured(data[key]) for key in aliases if data.get(key) not in (None, "")]
        if values:
            if any(dumps(value) != dumps(values[0]) for value in values[1:]):
                raise ValueError(f"Conflicting source {relation} fields.")
            result[relation] = values[0]
    return result


def _annotated(annotations):
    for relation in ("source-tags", "source-labels", "source-comments"):
        value = annotations.get(relation)
        if isinstance(value, dict) and "labels" in value:
            value = value["labels"]  # Plaso EventTag metadata alone is not an annotation.
        if value not in (None, "", "-", "null") and bool(value):
            return True
    return False


def _add(obj, relation, value, **kwargs):
    attribute = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
    attribute.uuid = str(uuid5(UUID(str(obj.uuid)), dumps([relation, str(value)])))


def _link(source, target, relationship):
    ref = source.add_reference(target.uuid, relationship)
    ref.uuid = str(uuid5(UUID(str(source.uuid)), dumps([str(target.uuid), relationship])))


def import_findings(request):
    config = request.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    format_ = config.get("format", "auto")
    selection = config.get("selection", "all")
    unit = config.get("datetime_unit")
    if format_ in (None, ""):
        format_ = "auto"
    if selection in (None, ""):
        selection = "all"
    if unit == "":
        unit = None
    if format_ not in ("auto", "json", "jsonl", "csv") or selection not in ("all", "selected", "annotated"):
        raise ValueError("format must be auto/json/jsonl/csv; selection must be all/selected/annotated.")
    if unit not in (None, "s", "ms", "us", "ns"):
        raise ValueError("datetime_unit must be empty, s, ms, us or ns.")
    defaults = {}
    for key in ("sketch_id", "timeline_id", "source_url"):
        if config.get(key) not in (None, ""):
            defaults[key] = _text(config[key], key)
    encoded = request.get("data")
    if not isinstance(encoded, str) or not encoded or len(encoded) > 4 * ((MAX_INPUT + 2) // 3):
        raise ValueError("data must contain a base64-encoded export of at most 20 MiB.")
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > MAX_INPUT:
        raise ValueError("Export must be non-empty and at most 20 MiB.")
    rows, format_ = read_rows(raw.decode("utf-8-sig"), format_)
    if not rows or len(rows) > MAX_ROWS:
        raise ValueError("Export must contain 1–1000 entries.")
    chosen = []
    for number, row in enumerate(rows, 1):
        _bounded(row)
        data = row.get("_source") if isinstance(row.get("_source"), dict) else row
        if (
            not isinstance(data.get("message"), str)
            or not data["message"].strip()
            or not any(k in data for k in ("datetime", "timestamp"))
        ):
            raise ValueError("Each entry needs a non-empty message and datetime or microsecond timestamp.")
        annotations = _annotations(data)
        selected_value = row.get("selected", data.get("selected", data.get("misp_source_selected")))
        selected = boolean(selected_value, "selected")
        if selection == "selected" and not selected or selection == "annotated" and not _annotated(annotations):
            continue
        chosen.append((number, row, data, annotations, selected_value))
    if not chosen:
        raise ValueError("No timeline entries match the requested selection.")
    filename = request.get("filename")
    if filename in (None, ""):
        filename = "timeline-findings." + format_
    filename = _text(filename, "filename").replace("\\", "/").rsplit("/", 1)[-1]
    if len(filename) > 4096 or filename in ("", ".", "..") or any(ord(c) < 32 for c in filename):
        raise ValueError("filename requires a basename without control characters.")
    digest = hashlib.sha256(raw).hexdigest()
    event, warnings = MISPEvent(), Counter()
    source = MISPObject("file", strict=True, standalone=False)
    source.comment = "Imported timeline export; its hash describes the export bytes, not the referenced evidence."
    source.uuid = str(uuid5(NAMESPACE, dumps([digest, filename])))
    for relation, value in {"filename": filename, "sha256": digest, "size-in-bytes": len(raw)}.items():
        _add(source, relation, value)
    if len(chosen) == len(rows):
        _add(source, "attachment", filename, data=BytesIO(raw))
    else:
        warnings["Source attachment omitted to avoid including excluded entries; original export hash retained"] += 1
    event.add_object(source)
    for number, row, data, annotations, selected_value in chosen:
        context = {}
        for relation, aliases in CONTEXT.items():
            values = []
            for key in aliases:
                for container in ([row, data] if data is not row else [data]):
                    if container.get(key) not in (None, ""):
                        values.append(_text(container[key], key))
            if values and len(set(values)) != 1:
                raise ValueError(f"Conflicting source {relation} identifiers.")
            default_key = relation.replace("-", "_")
            value = values[0] if values else defaults.get(default_key)
            if value is not None:
                context[relation] = value
        if isinstance(row.get("_source"), str):
            context.setdefault("timeline-name", row["_source"])
        obj = MISPObject("timesketch-timeline", strict=True, standalone=False, misp_objects_template_custom=template())
        obj.uuid = str(uuid5(NAMESPACE, dumps([str(source.uuid), number, context, unit])))
        for relation, value in {
            "message": data["message"],
            "row-number": number,
            "raw-event": dumps(row),
            "source-sha256": digest,
            "source-format": format_,
            **context,
        }.items():
            _add(obj, relation, value)
        for key in ("timestamp_desc", "timestamp"):
            if data.get(key) not in (None, ""):
                value = data[key]
                _add(obj, key, str(value) if isinstance(value, (str, int)) else dumps(value))
        if data.get("datetime") not in (None, ""):
            value = data["datetime"]
            _add(obj, "datetime-raw", str(value) if isinstance(value, (str, int)) else dumps(value))
            if unit:
                _add(obj, "datetime-unit", unit)
        if selected_value is not None:
            _add(obj, "selected", boolean(selected_value, "selected"))
        for relation, value in annotations.items():
            _add(obj, relation, dumps(value))
        try:
            parsed = resolve_time(data.get("datetime"), data.get("timestamp"), unit)
            _add(obj, "datetime", parsed.isoformat())
        except ValueError as error:
            warnings[str(error) + " Original time retained without normalization"] += 1
        event.add_object(obj)
        _link(source, obj, "derived-from")
    return {
        "results": {"Object": json.loads(event.to_json())["Object"]},
        "summary": {
            "input_entries": len(rows),
            "imported": len(chosen),
            "excluded": len(rows) - len(chosen),
            "source_sha256": digest,
        },
        "warnings": [f"{message}: {count}" for message, count in sorted(warnings.items())],
    }


def _records(container, key):
    value = container.get(key, [])
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"{key} must be a list of objects.")
    return value


def _tags(*containers):
    names = set()
    for container in containers:
        for key in ("Tag", "EventTag", "AttributeTag"):
            for value in _records(container, key):
                tag = value.get("Tag", value)
                if isinstance(tag, dict) and isinstance(tag.get("name"), str):
                    names.add(tag["name"])
    return sorted(names)


def _attributes(obj):
    return [a for a in _records(obj, "Attribute") if not boolean(a.get("deleted"), "deleted")]


def _fields(attributes):
    result = {}
    for attr in attributes:
        relation = attr.get("object_relation")
        if relation in result:
            raise ValueError("Ambiguous repeated timeline relation: " + str(relation))
        result[relation] = attr.get("value")
    return result


def export_findings(request):
    config = request.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    misp_url = config.get("misp_url")
    if misp_url is None:
        misp_url = ""
    if not isinstance(misp_url, str):
        raise ValueError("misp_url must be an HTTP(S) base URL.")
    if misp_url:
        parts = urlsplit(misp_url)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
        ):
            raise ValueError("misp_url must be an HTTP(S) base URL without credentials, query or fragment.")
    data = request.get("data")
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ValueError("data must contain an event or list of events.")
    rows, skipped, seen = [], Counter(), set()

    def emit(event, obj, attr, value, description, message, scope, source=None):
        try:
            parsed = value if isinstance(value, datetime) else instant(value)
            message = _text(message, "message")
            description = _text(description, "timestamp_desc")
        except ValueError as error:
            skipped[str(error)] += 1
            return
        metadata = {
            "misp_event_uuid": str(event.get("uuid") or ""),
            "misp_event_id": str(event.get("id") or ""),
            "misp_object_uuid": str(obj.get("uuid") or ""),
            "misp_object_name": str(obj.get("name") or ""),
            "misp_attribute_uuid": str(attr.get("uuid") or ""),
            "misp_object_relation": str(attr.get("object_relation") or description),
            "misp_tags": _tags(event, obj, attr),
        }
        if obj:
            metadata["misp_object_references"] = [
                {key: reference[key] for key in ("referenced_uuid", "relationship_type", "comment") if key in reference}
                for reference in _records(obj, "ObjectReference")
            ]
            metadata["misp_context"] = {}
            for attribute in _attributes(obj):
                relation = attribute.get("object_relation")
                if relation in CONTEXT_RELATIONS and isinstance(attribute.get("value"), (str, int)):
                    metadata["misp_context"].setdefault(relation, []).append(attribute["value"])
        identity = dumps([metadata, scope, microseconds(parsed), message, description])
        row_id = str(uuid5(NAMESPACE, identity))
        if row_id in seen:
            skipped["duplicate observation"] += 1
            return
        seen.add(row_id)
        row = {
            "datetime": parsed.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "timestamp": microseconds(parsed),
            "timestamp_desc": description,
            "message": message,
            "misp_observation_id": row_id,
            **metadata,
        }
        if source:
            row.update(source)
        if misp_url and (event.get("uuid") or event.get("id")):
            row["misp_event_url"] = (
                misp_url.rstrip("/") + "/events/view/" + quote(str(event.get("uuid") or event["id"]), safe="")
            )
        row["misp_distribution"] = {
            level: {key: container[key] for key in ("distribution", "sharing_group_id") if key in container}
            for level, container in (("event", event), ("object", obj), ("attribute", attr))
        }
        if len(rows) >= MAX_EXPORT:
            raise ValueError("Export exceeds 5000 observations; narrow the selection.")
        rows.append(row)

    for event_index, envelope in enumerate(data):
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if boolean(event.get("deleted"), "deleted") or boolean(envelope.get("deleted"), "deleted"):
            continue
        collections = dict(event, **envelope)
        event = dict(event, **{key: collections[key] for key in ("Tag", "EventTag") if key in collections})
        sources = [(attr, {}, (event_index, "attribute", i)) for i, attr in enumerate(_attributes(collections))]
        for object_index, obj in enumerate(_records(collections, "Object")):
            if boolean(obj.get("deleted"), "deleted"):
                continue
            attributes = _attributes(obj)
            scope = (event_index, "object", object_index)
            if obj.get("name") in ("timesketch-timeline", "timesketch_message"):
                try:
                    fields = _fields(attributes)
                    time = resolve_time(
                        fields.get("datetime", fields.get("datetime-raw")),
                        fields.get("timestamp"),
                        fields.get("datetime-unit"),
                    )
                except ValueError as error:
                    skipped[str(error)] += 1
                    continue
                metadata = {}
                for relation in CONTEXT:
                    if fields.get(relation) not in (None, ""):
                        key = "misp_source_" + relation.replace("-", "_")
                        if relation == "source-index":
                            key = "misp_source_index"
                        elif relation == "source-url":
                            key = "misp_source_url"
                        metadata[key] = fields[relation]
                for relation in ANNOTATIONS:
                    if fields.get(relation) not in (None, ""):
                        try:
                            value = loads(fields[relation])
                        except (TypeError, ValueError):
                            value = fields[relation]
                        metadata["misp_source_" + relation.removeprefix("source-").replace("-", "_")] = value
                for relation in ("source-sha256", "row-number"):
                    if fields.get(relation) not in (None, ""):
                        metadata["misp_source_" + relation.replace("source-", "export_").replace("-", "_")] = fields[
                            relation
                        ]
                if "selected" in fields:
                    metadata["misp_source_selected"] = boolean(fields["selected"], "selected")
                emit(
                    event,
                    obj,
                    {},
                    time,
                    fields.get("timestamp_desc")
                    or ("Timesketch message" if obj["name"] == "timesketch_message" else None),
                    fields.get("message"),
                    scope,
                    metadata,
                )
                continue
            for attribute_index, attr in enumerate(attributes):
                sources.append((attr, obj, (*scope, attribute_index)))
                relation = attr.get("object_relation")
                if relation in OBJECT_TIMES.get(obj.get("name"), ()):
                    label = ", ".join(
                        str(a.get("value", ""))
                        for a in attributes
                        if a.get("object_relation") in ("filename", "name", "image", "computer", "rule-title")
                    )
                    emit(
                        event,
                        obj,
                        attr,
                        attr.get("value"),
                        relation,
                        f"{obj['name']}: {label or obj.get('uuid', 'observation')}",
                        (*scope, relation, attribute_index),
                    )
        for attr, obj, scope in sources:
            for field in ("first_seen", "last_seen"):
                if attr.get(field) not in (None, ""):
                    try:
                        value = attr[field]
                        parsed = (
                            epoch(value, "s")
                            if isinstance(value, int) or isinstance(value, str) and re.fullmatch(r"[+-]?[0-9]+", value)
                            else instant(value)
                        )
                    except ValueError as error:
                        skipped[str(error)] += 1
                        continue
                    emit(
                        event,
                        obj,
                        attr,
                        parsed,
                        field,
                        f"{attr.get('type', 'attribute')}: {attr.get('value', '')}",
                        (*scope, field),
                    )
    if not rows:
        return {
            "error": "No supported timestamped observations selected.",
            "summary": {"observations": 0, "skipped": dict(skipped)},
        }
    output = "".join(dumps(row) + "\n" for row in rows).encode()
    if len(output) > MAX_INPUT:
        raise ValueError("Export exceeds 20 MiB; narrow the selection.")
    return {
        "response": [],
        "data": base64.b64encode(output).decode(),
        "summary": {"observations": len(rows), "skipped": dict(skipped)},
        "warnings": [f"Skipped {count}: {message}" for message, count in sorted(skipped.items())],
    }
