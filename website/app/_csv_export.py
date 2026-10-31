# Bundled from misp_modules/modules/export_mod/csv_export.py; checked by tests/test_csv_export.py.
"""Generic, spreadsheet-safe CSV export of MISP attributes."""

import base64
import csv
import io
import json

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "description": "Export event and object attributes of any type as CSV.",
    "module-type": ["export"],
    "name": "CSV Export",
    "logo": "",
    "requirements": [],
    "features": (
        "Exports one row per attribute, including object attributes and non-IDS attributes, from every supplied event."
        " Retains event and object context, tags and composite values. Deleted events, objects and attributes are"
        " excluded. UTF-8 CSV cells are quoted as needed and formula-like cells are prefixed with an apostrophe for"
        " spreadsheet safety. No additional dependencies are required."
    ),
    "references": [],
    "input": "MISP events in standard, bare or legacy export format.",
    "output": "Base64-encoded UTF-8 CSV with a fixed header, including for empty input.",
}
moduleconfig = []
LEADING_CONTROLS = "".join(chr(index) for index in range(33))

ATTRIBUTE_FIELDS = (
    "uuid",
    "category",
    "type",
    "value",
    "comment",
    "to_ids",
    "distribution",
    "timestamp",
    "first_seen",
    "last_seen",
)
CSV_FIELDS = (
    "event_id",
    "event_uuid",
    "event_info",
    "object_uuid",
    "object_name",
    "object_relation",
    *ATTRIBUTE_FIELDS,
    "event_tags",
    "object_tags",
    "attribute_tags",
)


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _deleted(container):
    return str(container.get("deleted", False)).lower() in ("true", "1")


def _tags(container):
    names = set()
    for key in ("Tag", "EventTag", "AttributeTag"):
        for tag in _records(container, key):
            tag = tag.get("Tag", tag)
            if isinstance(tag, dict) and isinstance(tag.get("name"), str):
                names.add(tag["name"])
    return json.dumps(sorted(names), ensure_ascii=False)


def _cell(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, bool)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        value = str(value)
    # CSV quoting alone does not stop spreadsheet formula evaluation. Check
    # past leading whitespace/control characters without changing the value.
    start = value.lstrip(LEADING_CONTROLS)
    if start.startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def _rows(data):
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if _deleted(event):
            continue
        # Legacy exports put collections alongside Event metadata.
        collections = dict(event, **envelope)
        context = {f"event_{key}": event.get(key, "") for key in ("id", "uuid", "info")}
        context["event_tags"] = _tags(collections)
        sources = [(attribute, {}) for attribute in _records(collections, "Attribute")]
        for obj in _records(collections, "Object"):
            if not _deleted(obj):
                sources.extend((attribute, obj) for attribute in _records(obj, "Attribute"))
        for attribute, obj in sources:
            if _deleted(attribute):
                continue
            yield {
                **context,
                **{field: attribute.get(field, "") for field in ATTRIBUTE_FIELDS},
                "object_uuid": obj.get("uuid", ""),
                "object_name": obj.get("name", ""),
                "object_relation": attribute.get("object_relation", ""),
                "object_tags": _tags(obj),
                "attribute_tags": _tags(attribute),
            }


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        data = request.get("data")
        if not isinstance(data, list) or any(not isinstance(event, dict) for event in data):
            raise ValueError("data must be a list of MISP events.")
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in _rows(data):
            writer.writerow({field: _cell(value) for field, value in row.items()})
    except (ValueError, TypeError) as exc:
        return {"error": f"CSV export: {exc}"}
    return {"response": [], "data": base64.b64encode(output.getvalue().encode("utf-8")).decode("ascii")}


def introspection():
    return {
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "csv",
        "responseType": "text/csv",
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
