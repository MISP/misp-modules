import base64
import json
import os
from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import urlparse

from pymisp import MISPAttribute, MISPEvent, MISPObject
from url_archiver import url_archiver

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["link", "url"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.2",
    "author": "Alexandre Dulaunoy",
    "description": (
        "Module to cache web pages of analysis reports, OSINT sources. The module returns a page-capture object"
        " holding the cached page."
    ),
    "module-type": ["expansion"],
    "name": "URL Archiver",
    "logo": "",
    "requirements": ["urlarchiver: python library to fetch and archive URL on the file-system"],
    "features": (
        "This module takes a link or url attribute as input and caches the related web page. It returns a"
        " page-capture object holding the cached page, the URL it was fetched from and the date of the capture."
    ),
    "references": ["https://github.com/adulau/url_archiver"],
    "input": "A link or url attribute.",
    "output": "A page-capture object holding the cached page.",
}
moduleconfig = ["archivepath"]


def _filename(url):
    """A name for the stored capture, taken from the URL it was fetched from."""
    parsed = urlparse(url)
    return os.path.basename(parsed.path) or parsed.hostname or "capture"


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    archive_path = (request.get("config") or {}).get("archivepath") or "/tmp/"

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        misperrors["error"] = "Link is missing"
        return misperrors
    tocache = attribute["value"]

    try:
        data = __archiveLink(archive_path, tocache)
    except Exception as e:
        return {"error": f"Unable to cache {tocache}: {e}"}

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    # Typed explicitly, since pymisp does not bundle the page-capture template
    # yet.
    misp_object = MISPObject("page-capture")
    misp_object.add_attribute("url", **{"type": "url", "value": tocache})
    misp_object.add_attribute(
        "attachment",
        **{"type": "attachment", "value": _filename(tocache), "data": BytesIO(base64.b64decode(data))},
    )
    # This module is the capturing party, so the capture is taken now. Nothing
    # upstream carries a date.
    misp_object.add_attribute(
        "capture-date", **{"type": "datetime", "value": datetime.now(tz=timezone.utc).isoformat()}
    )
    hostname = urlparse(tocache).hostname
    if hostname:
        misp_object.add_attribute("domain", **{"type": "domain", "value": hostname})
    misp_object.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(misp_object)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def __archiveLink(archive_path, tocache):
    archiver = url_archiver.Archive(archive_path=archive_path)
    return archiver.fetch(url=tocache, armor=True)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
