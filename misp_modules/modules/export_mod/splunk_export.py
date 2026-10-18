"""Export MISP indicators as a Splunk CSV lookup, retaining their provenance."""

import base64
import csv
import io
import json
from collections import Counter

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "description": "Export event and object indicators as a Splunk CSV lookup with CIM field mapping hints.",
    "module-type": ["export"],
    "name": "Splunk Lookup Export",
    "logo": "",
    "requirements": [],
    "features": (
        "Exports attributes from every supplied event, including object attributes, to a UTF-8 CSV lookup. Only"
        " attributes marked to_ids are included by default; set include_non_ids to true to include other attributes."
        " Deleted attributes and objects are always excluded. Composite attributes are split into independent hunting"
        " pivots while retaining the original value, port, UUIDs and object context. Event, object and attribute tags"
        " are combined in a JSON array. Unsupported or malformed indicators are counted in the API response warnings."
        " No Splunk connection or additional Python package is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/splunk_export.md) for"
        " supported types, lookup setup and bounded SPL examples."
    ),
    "references": [
        "https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/lookup",
        "https://help.splunk.com/en/data-management/common-information-model/6.0/overview/overview-of-the-splunk-common-information-model",
    ],
    "input": "A list of MISP events in standard or legacy export format.",
    "output": "Base64-encoded UTF-8 CSV lookup; optional warnings describe skipped indicators.",
}

moduleconfig = ["include_non_ids"]

# These are matching hints, not a claim that one field exists in every CIM data model.
TYPE_MAPPING = {
    "ip-src": ("ip", "src_ip"),
    "ip-dst": ("ip", "dest_ip"),
    "domain": ("domain", "query"),
    "hostname": ("hostname", "dest"),
    "url": ("url", "url"),
    "email-src": ("email", "src_user"),
    "email-dst": ("email", "recipient"),
    "filename": ("filename", "file_name"),
    **{kind: (kind, "file_hash") for kind in ("md5", "sha1", "sha256", "sha512")},
}
COMPOSITE_TYPES = {
    "domain|ip",
    "ip-src|port",
    "ip-dst|port",
    "hostname|port",
    "filename|md5",
    "filename|sha1",
    "filename|sha256",
    "filename|sha512",
    "malware-sample",
}
CSV_FIELDS = (
    "indicator",
    "indicator_type",
    "cim_fields",
    "port",
    "misp_type",
    "original_value",
    "event_uuid",
    "event_id",
    "event_info",
    "attribute_uuid",
    "object_uuid",
    "object_name",
    "object_relation",
    "category",
    "comment",
    "to_ids",
    "tags",
    "first_seen",
    "last_seen",
)


def _boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        if value.lower() in ("true", "1"):
            return True
        if value.lower() in ("false", "0"):
            return False
    raise ValueError(f"{name} must be true, false, 1 or 0.")


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _tags(*containers):
    names = set()
    for container in containers:
        for key in ("Tag", "EventTag", "AttributeTag"):
            for tag in _records(container, key):
                tag = tag.get("Tag", tag)
                if isinstance(tag, dict) and isinstance(tag.get("name"), str):
                    names.add(tag["name"])
    return json.dumps(sorted(names), ensure_ascii=False)


def _indicators(kind, value):
    """Yield (value, normalized type, CIM fields, port) for independent pivots."""
    if kind in TYPE_MAPPING:
        yield value, *TYPE_MAPPING[kind], ""
        return
    first, separator, second = value.rpartition("|")
    if not separator or not first or not second:
        raise ValueError("A composite indicator must have two non-empty components.")
    if kind.endswith("|port"):
        if not second.isascii() or not second.isdecimal() or not 0 <= int(second) <= 65535:
            raise ValueError("Invalid port.")
        yield first, *TYPE_MAPPING[kind.split("|")[0]], str(int(second))
    elif kind == "domain|ip":
        if "|" in first:
            raise ValueError("Invalid domain|ip indicator.")
        yield first, "domain", "query", ""
        yield second, "ip", "src_ip,dest_ip", ""
    else:
        # Split from the right so filenames containing a pipe remain intact.
        hash_type = "md5" if kind == "malware-sample" else kind.split("|")[1]
        yield first, "filename", "file_name", ""
        yield second, hash_type, "file_hash", ""


def _rows(data, include_non_ids, skipped):
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        # Legacy export envelopes place collections alongside Event metadata.
        collections = dict(event, **envelope)
        if _boolean(event.get("deleted"), "deleted"):
            continue
        sources = [(attribute, {}) for attribute in _records(collections, "Attribute")]
        for obj in _records(collections, "Object"):
            if not _boolean(obj.get("deleted"), "deleted"):
                sources.extend((attribute, obj) for attribute in _records(obj, "Attribute"))
        for attribute, obj in sources:
            if _boolean(attribute.get("deleted"), "deleted"):
                continue
            to_ids = _boolean(attribute.get("to_ids"), "to_ids")
            if not include_non_ids and not to_ids:
                continue
            kind = attribute.get("type")
            if not isinstance(kind, str) or kind not in TYPE_MAPPING and kind not in COMPOSITE_TYPES:
                skipped["unsupported"] += 1
                continue
            value = attribute.get("value")
            if not isinstance(value, str) or not value.strip():
                skipped["malformed"] += 1
                continue
            try:
                indicators = list(_indicators(kind, value))
            except ValueError:
                skipped["malformed"] += 1
                continue
            metadata = {
                "misp_type": kind,
                "original_value": value,
                "event_uuid": event.get("uuid", ""),
                "event_id": event.get("id", ""),
                "event_info": event.get("info", ""),
                "attribute_uuid": attribute.get("uuid", ""),
                "object_uuid": obj.get("uuid", ""),
                "object_name": obj.get("name", ""),
                "object_relation": attribute.get("object_relation", ""),
                "category": attribute.get("category", ""),
                "comment": attribute.get("comment", ""),
                "to_ids": str(to_ids).lower(),
                "tags": _tags(event, envelope, obj, attribute),
                "first_seen": attribute.get("first_seen", ""),
                "last_seen": attribute.get("last_seen", ""),
            }
            for indicator, indicator_type, cim_fields, port in indicators:
                yield dict(
                    metadata, indicator=indicator, indicator_type=indicator_type, cim_fields=cim_fields, port=port
                )


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
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        include_non_ids = _boolean(config.get("include_non_ids"), "include_non_ids")
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        skipped = Counter()
        seen = set()
        for row in _rows(data, include_non_ids, skipped):
            identity = tuple(str(row[field]) for field in CSV_FIELDS)
            if identity not in seen:
                seen.add(identity)
                writer.writerow(row)
    except (ValueError, TypeError) as exc:
        return {"error": f"Splunk export: {exc}"}
    response = {"response": [], "data": base64.b64encode(output.getvalue().encode("utf-8")).decode("ascii")}
    if skipped:
        response["warnings"] = [f"Skipped {count} {reason} attribute(s)." for reason, count in sorted(skipped.items())]
    return response


def introspection():
    return {
        "input": sorted(TYPE_MAPPING.keys() | COMPOSITE_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "csv",
        "responseType": "text/csv",
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
