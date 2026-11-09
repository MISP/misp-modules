"""Package selected events as a standard MISP feed, using PyMISP's serializer."""

import base64
import copy
import csv
import io
import json
import re
import uuid
import zipfile
from datetime import date

from pymisp import MISPEvent, PyMISPError, pymisp_json_default

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "MISP Feed Export",
    "logo": "",
    "description": "Generate a MISP feed ZIP from the selected events, with a manifest and hash index.",
    "module-type": ["export"],
    "require_standard_format": True,
    "fetch_options": {"includeAttachments": True},
    "requirements": ["PyMISP"],
    "features": (
        "Uses PyMISP to_feed to create manifest.json, hashes.csv and UUID-named event files. Accepts multiple"
        " events and returns a downloadable ZIP without fetching other events or publishing files. Defaults to"
        " published events with distribution All and inheriting data. See the usage guide at"
        " https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/misp_feed.md."
    ),
    "input": "A selected collection of complete MISP events, in standard, flat or legacy export format.",
    "output": "Base64-encoded ZIP containing a standard MISP feed directory.",
    "references": ["https://github.com/MISP/PyMISP/tree/main/examples/feed-generator"],
}
moduleconfig = [
    "valid_distributions",
    "include_unpublished",
    "with_distribution",
    "with_local_tags",
    "exclude_attribute_types",
    "max_events",
    "max_size_mb",
]


class FeedError(ValueError):
    """A local validation diagnostic without source event contents."""


def _boolean(value, name, default=False):
    if value is None or value == "":
        return default
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "0", "1"):
        return value.lower() in ("true", "1")
    raise FeedError(f"{name} must be true or false.")


def _list(value, name):
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise FeedError(f"{name} must be a list of objects.")
    return value


def _identifier(value, name):
    if not isinstance(value, str):
        raise FeedError(f"{name} must contain a UUID.")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise FeedError(f"{name} must contain a UUID.") from None
    if not parsed.int or str(parsed) != value.lower():
        raise FeedError(f"{name} must contain a canonical, non-empty UUID.")
    return str(parsed)


def _integer(value, name, default, maximum):
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,9}", str(value)) or not 1 <= int(value) <= maximum:
        raise FeedError(f"{name} must be between 1 and {maximum}.")
    return int(value)


def _distribution(value):
    if isinstance(value, bool) or str(value) not in ("0", "1", "2", "3", "4", "5"):
        raise FeedError("Distribution must be an integer from 0 to 5.")
    return int(value)


def _tags(container, local):
    source = container.pop("Tag", [])
    for key in ("EventTag", "AttributeTag"):
        source += [item.get("Tag", item) for item in _list(container.pop(key, []), key)]
    tags = []
    for tag in _list(source, "Tag"):
        tag["exportable"] = _boolean(tag.get("exportable"), "Tag.exportable", True)
        tag["local"] = _boolean(tag.get("local"), "Tag.local")
        if tag["exportable"] and (local or not tag["local"]):
            tags.append(tag)
    container["Tag"] = tags


def _prepare_child(child, allowed, excluded, local, timestamp, kind):
    if _boolean(child.get("deleted"), "deleted"):
        return None
    distribution = _distribution(child.get("distribution", 5))
    if distribution not in allowed or child.get("type") in excluded:
        return None
    child["uuid"] = _identifier(child.get("uuid"), kind + ".uuid")
    child.setdefault("timestamp", timestamp)
    child["distribution"] = distribution
    _tags(child, local)
    return child


def _event(envelope, allowed, excluded, local):
    if not isinstance(envelope, dict):
        raise FeedError("Each event must be an object.")
    source = envelope.get("Event", envelope)
    if not isinstance(source, dict):
        raise FeedError("Event must be an object.")
    event = copy.deepcopy(source)
    # Core legacy exports put selected collections next to Event metadata.
    for key in ("Attribute", "Object", "Tag", "EventTag", "EventReport", "Orgc", "CryptographicKey"):
        if key in envelope:
            event[key] = copy.deepcopy(envelope[key])
    if _boolean(event.get("deleted"), "Event.deleted"):
        return None, "deleted"
    event["uuid"] = _identifier(event.get("uuid"), "Event.uuid")
    if "published" not in event or "distribution" not in event:
        raise FeedError("Events must include published and distribution fields.")
    event["published"] = _boolean(event["published"], "Event.published")
    event["protected"] = _boolean(event.get("protected"), "Event.protected")
    event["distribution"] = _distribution(event["distribution"])
    if event["distribution"] == 5:
        raise FeedError("An event cannot inherit its distribution.")
    if not isinstance(event.get("info"), str) or not event["info"].strip():
        raise FeedError("Events must include info.")
    org = event.get("Orgc")
    if not isinstance(org, dict) or not isinstance(org.get("name"), str) or not org["name"].strip():
        raise FeedError("Events must include their creator organisation name and UUID.")
    org["uuid"] = _identifier(org.get("uuid"), "Orgc.uuid")
    if not isinstance(event.get("date"), str):
        raise FeedError("Events must include a date.")
    date.fromisoformat(event["date"])
    timestamp = event.get("timestamp")
    if isinstance(timestamp, bool) or not re.fullmatch(r"[0-9]{1,12}", str(timestamp)):
        raise FeedError("Events must include an integer timestamp.")
    timestamp = int(timestamp)
    event["timestamp"] = timestamp
    event.setdefault("publish_timestamp", timestamp)
    _tags(event, local)
    event["Attribute"] = [
        prepared
        for item in _list(event.get("Attribute", []), "Attribute")
        if (prepared := _prepare_child(item, allowed, excluded, local, timestamp, "Attribute"))
    ]
    objects = []
    for obj in _list(event.get("Object", []), "Object"):
        if not _prepare_child(obj, allowed, set(), local, timestamp, "Object"):
            continue
        obj["Attribute"] = [
            prepared
            for item in _list(obj.get("Attribute", []), "Object.Attribute")
            if (prepared := _prepare_child(item, allowed, excluded, local, timestamp, "Attribute"))
        ]
        if obj["Attribute"]:
            objects.append(obj)
    event["Object"] = objects
    event["EventReport"] = [
        prepared
        for report in _list(event.get("EventReport", []), "EventReport")
        if (prepared := _prepare_child(report, allowed, set(), local, timestamp, "EventReport"))
    ]
    remaining = {item["uuid"] for item in event["Attribute"]}
    remaining.update(obj["uuid"] for obj in objects)
    remaining.update(attr["uuid"] for obj in objects for attr in obj["Attribute"])
    for obj in objects:
        obj["ObjectReference"] = [
            ref
            for ref in _list(obj.get("ObjectReference", []), "ObjectReference")
            if ref.get("referenced_uuid") in remaining and not _boolean(ref.get("deleted"), "deleted")
        ]
    return event, ""


def _json(value):
    return json.dumps(value, default=pymisp_json_default, ensure_ascii=False, sort_keys=True, allow_nan=False).encode(
        "utf-8"
    )


def _isolate_fields(event):
    # PyMISP adds distribution to mutable class-level feed fields. Give each
    # object a private copy so a configured export cannot affect later requests.
    for item in [
        event,
        *event.attributes,
        *event.objects,
        *event.event_reports,
        *(attr for obj in event.objects for attr in obj.attributes),
    ]:
        item._fields_for_feed = set(item._fields_for_feed) - {"distribution", "SharingGroup", "sharing_group_id"}


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("config", {}), dict):
            raise FeedError("Request and config must be objects.")
        config = request.get("config", {})
        flags = {
            key: _boolean(config.get(key), key)
            for key in ("include_unpublished", "with_distribution", "with_local_tags")
        }
        levels = config.get("valid_distributions")
        if levels is None or levels == "":
            levels = "3,5"
        if not isinstance(levels, str):
            raise FeedError("valid_distributions must be a comma-separated string, e.g. 3,5.")
        allowed = {_distribution(value.strip()) for value in levels.split(",")}
        exclusions = config.get("exclude_attribute_types")
        if exclusions is None:
            exclusions = ""
        if not isinstance(exclusions, str):
            raise FeedError("exclude_attribute_types must be comma-separated.")
        excluded = {value.strip() for value in exclusions.split(",") if value.strip()}
        maximum = _integer(config.get("max_events"), "max_events", 1000, 100000)
        budget = _integer(config.get("max_size_mb"), "max_size_mb", 128, 2048) * 1024 * 1024
        data = request.get("data")
        if isinstance(data, dict):
            data = data.get("response", [data])
        events = _list(data, "data")
        if not events or len(events) > maximum:
            raise FeedError("Select at least one event and stay within max_events; the feed is never truncated.")
        manifest, hashes, seen, skipped = {}, set(), set(), {}
        output = io.BytesIO()
        total = 0
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:

            def write(name, content):
                nonlocal total
                total += len(content)
                if total > budget:
                    raise FeedError("Feed exceeds max_size_mb; narrow the selection or raise the configured limit.")
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, content)

            for envelope in events:
                event, reason = _event(envelope, allowed, excluded, flags["with_local_tags"])
                if event is not None:
                    if event["uuid"] in seen:
                        raise FeedError("Duplicate event UUIDs are not allowed in a feed.")
                    seen.add(event["uuid"])
                    if not flags["include_unpublished"] and not event["published"]:
                        reason = "unpublished"
                    elif event["distribution"] not in allowed:
                        reason = "distribution"
                if reason:
                    skipped[reason] = skipped.get(reason, 0) + 1
                    continue
                if _boolean(event.get("protected"), "Event.protected"):
                    raise FeedError(
                        "Protected events require signed feed files; use the standalone generator with signatures."
                    )
                model = MISPEvent()
                model.load({"Event": event})
                _isolate_fields(model)
                feed = model.to_feed(
                    valid_distributions=sorted(allowed),
                    with_meta=True,
                    with_distribution=flags["with_distribution"],
                    with_local_tags=flags["with_local_tags"],
                )
                body = feed["Event"]
                hashes.update((digest, event["uuid"]) for digest in body.pop("_hashes"))
                manifest.update(body.pop("_manifest"))
                write(event["uuid"] + ".json", _json(feed))
            if not manifest:
                raise FeedError("No events pass the published/distribution filters.")
            write("manifest.json", _json(manifest))
            text = io.StringIO(newline="")
            csv.writer(text, lineterminator="\n").writerows(sorted(hashes))
            write("hashes.csv", text.getvalue().encode("utf-8"))
        return {
            "response": [],
            "data": base64.b64encode(output.getvalue()).decode("ascii"),
            "summary": {"events": len(manifest), "skipped": skipped, "uncompressed_bytes": total},
        }
    except FeedError as error:
        return {"error": "MISP feed export: " + str(error)}
    except (ValueError, TypeError, KeyError, OverflowError, PyMISPError):
        # PyMISP errors may echo attribute values or attachment contents.
        return {
            "error": (
                "MISP feed export failed: invalid input, configuration or feed content. Check required metadata,"
                " UUIDs, publication/distribution filters, protected events and configured size limits."
            )
        }


def introspection():
    return {
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "zip",
        "responseType": "application/zip",
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
