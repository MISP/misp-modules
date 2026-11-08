"""Parse MISP export events into VirusTotal Graph nodes."""

import re
from urllib.parse import urlsplit

from misp_modules.lib.vt_graph_parser.errors import GraphImportError
from misp_modules.lib.vt_graph_parser.helpers.wrappers import MispAttribute

MISP_INPUT_ATTR = [
    "hostname",
    "domain",
    "ip-src",
    "ip-dst",
    "md5",
    "sha1",
    "sha256",
    "url",
    "filename|md5",
    "filename|sha1",
    "filename|sha256",
    "filename",
    "target-user",
    "target-email",
]
GRAPH_ID_PATTERN = re.compile(r"g[0-9a-f]{64}")
VIRUSTOTAL_GRAPH_LINK_PREFIX = "https://www.virustotal.com/graph/"


def boolean(value, name):
    """Parse the booleans sent as strings by MISP module configuration."""
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise GraphImportError(f"{name} must be true, false, 1 or 0.")


def _collection(value, name):
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise GraphImportError(f"{name} must be a list of objects.")
    return value


def _graph_id(value):
    if not isinstance(value, str):
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or parsed.netloc != "www.virustotal.com" or any(ord(char) < 33 for char in value):
            return ""
        match = re.fullmatch(r"/(?:gui/)?graph/(g[0-9a-f]{64})/?", parsed.path)
        return match[1] if match else ""
    except ValueError:
        return ""


def _parse_data(attributes, objects):
    attributes = _collection(attributes, "Attribute")
    objects = _collection(objects, "Object")
    active = [attr for attr in attributes if not boolean(attr.get("deleted"), "deleted")]
    attributes_data = list(active)
    for object_ in objects:
        if not boolean(object_.get("deleted"), "deleted"):
            attributes_data.extend(
                attr
                for attr in _collection(object_.get("Attribute", []), "Object.Attribute")
                if not boolean(attr.get("deleted"), "deleted")
            )

    # Prefer the largest numeric MISP attribute ID; without IDs, use input order.
    links = []
    for index, attr in enumerate(active):
        graph_id = _graph_id(attr.get("value")) if attr.get("type") == "link" else ""
        if graph_id:
            identifier = str(attr.get("id", ""))
            links.append((int(identifier) if re.fullmatch(r"[0-9]{1,20}", identifier) else -1, index, graph_id))
    graph_id = max(links)[2] if links else ""
    parsed = []
    for attr in attributes_data:
        if attr.get("type") in MISP_INPUT_ATTR:
            category = attr.get("category", "")
            if not isinstance(category, str):
                raise GraphImportError("MISP attribute categories must be strings.")
            parsed.append(MispAttribute(attr["type"], category, attr.get("value")))
    return parsed, graph_id


def parse_pymisp_response(payload):
    """Accept flat exports, wrapped events and selected collections beside Event."""
    if not isinstance(payload, dict):
        raise GraphImportError("Each exported event must be an object.")
    event = payload.get("Event", payload)
    if not isinstance(event, dict) or boolean(event.get("deleted"), "Event.deleted"):
        raise GraphImportError("Each exported event must be a non-deleted object.")
    attributes = payload["Attribute"] if "Attribute" in payload else event.get("Attribute", [])
    objects = payload["Object"] if "Object" in payload else event.get("Object", [])
    parsed, graph_id = _parse_data(attributes, objects)
    if not parsed:
        raise GraphImportError("Each exported event must contain at least one supported active attribute.")
    return parsed, graph_id
