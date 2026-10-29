"""MISP event input, public feed browsing, and export file handling."""

import base64
import binascii
import json
import re
import time
from functools import lru_cache

import requests
from werkzeug.utils import secure_filename

from . import home_core as HomeModel
from .module_config import build_module_config

MAX_EXPORT_SIZE = 20 * 1024 * 1024
FEEDS = {"circl": {"name": "CIRCL OSINT", "url": "https://www.circl.lu/doc/misp/feed-osint/"}}
UUID_PATTERN = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


class FeedError(ValueError):
    """A public feed could not be read."""


def read_feed_json(feed, filename):
    # URLs are constructed exclusively from this registry and validated UUIDs.
    # Reject redirects rather than allowing a feed to redirect into a private host.
    if feed not in FEEDS:
        raise ValueError("Choose a supported OSINT feed.")
    try:
        started = time.monotonic()
        with requests.get(FEEDS[feed]["url"] + filename, stream=True,
                          timeout=(5, 20), allow_redirects=False) as response:
            if response.status_code != 200:
                raise FeedError("The OSINT feed is unavailable. Please try again.")
            data = bytearray()
            for chunk in response.iter_content(65536):
                data.extend(chunk)
                if len(data) > MAX_EXPORT_SIZE or time.monotonic() - started > 30:
                    raise FeedError("The feed response exceeded the size or time limit.")
        return json.loads(data)
    except (requests.RequestException, ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, FeedError):
            raise
        raise FeedError("Unable to read the OSINT feed. Please try again.") from None


@lru_cache(maxsize=8)
def feed_manifest(feed, cache_period):
    manifest = read_feed_json(feed, "manifest.json")
    if not isinstance(manifest, dict):
        raise FeedError("The OSINT feed returned an invalid manifest.")
    return manifest


def get_manifest(feed):
    return feed_manifest(feed, int(time.monotonic() // 300))


def list_feed_events(feed, search="", page=1):
    if feed not in FEEDS:
        raise ValueError("Choose a supported OSINT feed.")
    events = []
    for uuid, entry in get_manifest(feed).items():
        if not UUID_PATTERN.fullmatch(uuid) or not isinstance(entry, dict):
            continue
        event = {"uuid": uuid, "info": str(entry.get("info", uuid)),
                 "date": str(entry.get("date", ""))}
        if search.casefold() in (event["info"] + " " + uuid).casefold():
            events.append(event)
    events.sort(key=lambda item: (item["date"], item["uuid"]), reverse=True)
    return {"events": events[(page - 1) * 100:page * 100], "total": len(events), "page": page}


def normalize_events(data):
    """Provide nested events and the sibling collections used by legacy exporters."""
    if isinstance(data, dict) and "response" in data:
        data = data["response"]
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data:
        raise ValueError("Provide a MISP event or a non-empty event collection.")
    normalized = []
    for envelope in data:
        if not isinstance(envelope, dict):
            raise ValueError("Each MISP event must be an object.")
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict) or not any(key in event for key in ("info", "uuid", "Attribute", "Object")):
            raise ValueError("The JSON does not contain a MISP event.")
        event = dict(event)
        for key in ("Attribute", "Object"):
            records = envelope.get(key, event.get(key, []))
            if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
                raise ValueError(f"{key} must be a list of objects.")
            event[key] = records
        for obj in event["Object"]:
            attrs = obj.get("Attribute", [])
            if not isinstance(attrs, list) or any(not isinstance(attr, dict) for attr in attrs):
                raise ValueError("Object Attribute must be a list of objects.")
        # Include other collections (Orgc, Tag, Galaxy, ...) for legacy modules.
        normalized.append({**event, **envelope, "Event": event,
                           "Attribute": event["Attribute"], "Object": event["Object"]})
    return normalized


def build_export_request(form, files):
    modules = HomeModel.get_modules(("export",))
    if not isinstance(modules, list):
        raise ValueError(modules.get("message", "Unable to load export modules."))
    module = next((m for m in modules if m["name"] == form.get("module")), None)
    if not module:
        raise ValueError("Select an active export module.")
    config = build_module_config(module, form.get("config", "{}"))
    if form.get("source") == "file":
        upload = files.get("file")
        if not upload or not upload.filename:
            raise ValueError("Choose a MISP JSON file to export.")
        raw = upload.read(MAX_EXPORT_SIZE + 1)
        if len(raw) > MAX_EXPORT_SIZE:
            raise ValueError("MISP JSON must be at most 20 MiB.")
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            raise ValueError("Upload a valid MISP JSON file.") from None
        label = secure_filename(upload.filename) or "misp-event.json"
    elif form.get("source") == "feed":
        feed, uuid = form.get("feed", ""), form.get("event", "")
        if feed not in FEEDS or not UUID_PATTERN.fullmatch(uuid):
            raise ValueError("Select an event from a supported OSINT feed.")
        if uuid not in get_manifest(feed):
            raise ValueError("The selected event is no longer in the feed. Refresh the event list.")
        data = read_feed_json(feed, uuid + ".json")
        label = uuid + ".json"
    else:
        raise ValueError("Choose a MISP JSON file or an OSINT feed event.")
    events = normalize_events(data)
    sources = module["mispattributes"].get("inputSource", [])
    if len(events) > 1 and sources and "event-collection" not in sources:
        raise ValueError("This module supports one event at a time. Upload a single MISP event.")
    return ({"query": [label], "input": "export", "modules": [module["name"]],
             "config": {module["name"]: config}, "parent_id": ""},
            {"data": events}, module["mispattributes"])


def decode_export(result):
    try:
        return base64.b64decode(result["data"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error):
        raise ValueError("The export module returned invalid file data.") from None


def prepare_export_result(result, metadata, label):
    data = decode_export(result)
    extension = re.sub(r"[^a-zA-Z0-9]", "", str(metadata.get("outputFileExtension", "bin")))[:16] or "bin"
    filename = (secure_filename(label.rsplit(".", 1)[0]) or "misp-export") + "." + extension
    try:
        preview = data.decode("utf-8")
        if any(ord(char) < 32 and char not in "\t\r\n" for char in preview):
            preview = None
    except UnicodeError:
        preview = None
    if metadata.get("responseType", "").split(";", 1)[0].lower() in ("application/pdf", "application/zip", "application/octet-stream"):
        preview = None
    return {**result, "export": {"filename": filename, "size": len(data),
                                 "preview": preview[:200000] if preview is not None else None,
                                 "truncated": preview is not None and len(preview) > 200000}}
