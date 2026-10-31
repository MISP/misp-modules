"""Find an existing Wayback Machine snapshot and return a page-capture object."""

import json
import re
from datetime import datetime, timezone
from importlib import resources
from urllib.parse import urlsplit
from uuid import UUID

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["url", "link", "domain", "hostname"], "format": "misp_standard"}
moduleinfo = {
    "version": "1.0",
    "author": "MISP",
    "description": "Query the Internet Archive Wayback Machine for an existing web page snapshot.",
    "module-type": ["expansion"],
    "name": "Webarchive (Wayback Machine)",
    "logo": "",
    "requirements": ["requests", "PyMISP"],
    "features": (
        "Query the Wayback Availability API for the latest accessible snapshot, or the snapshot closest to an"
        " optional timestamp (1-14 digits, YYYYMMDDhhmmss). Return a page-capture object containing the queried"
        " URL, archive link and UTC capture date, referencing the original attribute. Domain and hostname"
        " inputs query http://<value>/. No API key is needed. Only existing snapshots are queried; pages are"
        " neither submitted for archiving nor downloaded. No accessible snapshot returns an explanatory error."
    ),
    "references": ["https://archive.org/help/wayback_api.php"],
    "input": "A url, link, domain or hostname attribute with type, value and UUID.",
    "output": "A page-capture object linked to the original attribute, with to_ids=false on generated attributes.",
}
moduleconfig = ["timestamp"]
AVAILABILITY_URL = "https://archive.org/wayback/available"


def _query_url(attribute):
    value = attribute["value"]
    if not isinstance(value, str) or not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("The attribute value must be a non-empty string without whitespace or control characters.")
    if attribute["type"] in ("domain", "hostname"):
        value = value.encode("idna").decode("ascii").rstrip(".")
        if len(value) > 253 or any(
            not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in value.split(".")
        ):
            raise ValueError("Invalid domain or hostname.")
        value = f"http://{value}/"
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("An HTTP or HTTPS URL with a hostname is required.")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid URL port.")
    return value


def _snapshot(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("archived_snapshots"), dict):
        raise ValueError("Invalid response from the Wayback Availability API.")
    closest = payload["archived_snapshots"].get("closest")
    if closest is None or closest == {}:
        return None
    if not isinstance(closest, dict):
        raise ValueError("Invalid snapshot metadata from the Wayback Availability API.")
    if closest.get("available") is not True or str(closest.get("status")) != "200":
        return None
    archive = closest.get("url")
    timestamp = closest.get("timestamp")
    if not isinstance(archive, str) or not isinstance(timestamp, str) or not re.fullmatch(r"[0-9]{14}", timestamp):
        raise ValueError("The snapshot is missing a valid archive URL or capture timestamp.")
    parsed = urlsplit(archive)
    if (
        parsed.scheme not in ("http", "https")
        or parsed.hostname != "web.archive.org"
        or not parsed.path.startswith("/web/")
    ):
        raise ValueError("Invalid Wayback Machine archive URL.")
    captured = datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    return archive, captured


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "The request must be a JSON object."}
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type: expected url, link, domain or hostname."}

    try:
        if not isinstance(attribute["uuid"], str):
            raise ValueError("The source attribute UUID must be a string.")
        UUID(attribute["uuid"])
        url = _query_url(attribute)
        config = request.get("config", {})
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("The module config must be a JSON object.")
        params = {"url": url}
        timestamp = config.get("timestamp")
        if timestamp not in (None, ""):
            if not isinstance(timestamp, str) or not re.fullmatch(r"[0-9]{1,14}", timestamp):
                raise ValueError("timestamp must contain 1-14 digits (YYYYMMDDhhmmss).")
            params["timestamp"] = timestamp

        source = MISPAttribute()
        source.from_dict(**attribute)
        response = requests.get(AVAILABILITY_URL, params=params, timeout=15)
        response.raise_for_status()
        snapshot = _snapshot(response.json())
        if snapshot is None:
            return {"error": f"No accessible archive found for {url} in the Wayback Machine."}

        # Bundle the upstream template until it is included in supported PyMISP releases.
        template = json.loads(
            resources.files("misp_modules").joinpath("data", "page-capture", "definition.json").read_text()
        )
        capture = MISPObject("page-capture", strict=True, misp_objects_template_custom=template)
        archive, captured = snapshot
        capture.add_attribute("url", url, to_ids=False)
        capture.add_attribute("archive", archive, to_ids=False)
        capture.add_attribute("capture-date", captured, to_ids=False)
        capture.comment = "Existing Wayback Machine snapshot returned by the Availability API (HTTP status 200)."
        capture.add_reference(source.uuid, "related-to")
        event = MISPEvent()
        event.add_attribute(**source)
        event.add_object(capture)
        data = json.loads(event.to_json())
        return {"results": {key: data[key] for key in ("Attribute", "Object")}}
    except requests.RequestException as error:
        return {"error": f"Wayback Machine request failed: {error}"}
    except (TypeError, ValueError, PyMISPError) as error:
        return {"error": f"Webarchive expansion failed: {error}"}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
