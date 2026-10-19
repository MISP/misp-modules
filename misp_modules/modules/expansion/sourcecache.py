import base64
import ipaddress
import json
import os
import socket
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


NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(address):
    """The IPv4 address an IPv6 address carries and is routed to: IPv4-mapped
    (::ffff:0:0/96), 6to4 (2002::/16) or the NAT64 well-known prefix
    (64:ff9b::/96). None for an IPv4 address or any other IPv6 address."""
    if address.version != 6:
        return None
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None:
        return address.sixtofour
    if address in NAT64_PREFIX:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def _is_public_address(ip):
    """Whether an address, IPv4 or IPv6, is globally routable, and so is the
    IPv4 address an IPv6 one carries: 64:ff9b::7f00:1 reaches 127.0.0.1."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    embedded = _embedded_ipv4(address)
    return address.is_global and (embedded is None or embedded.is_global)


def is_safe_url(url):
    """Whether the URL may be fetched: an http or https URL whose host resolves
    only to globally routable addresses, IPv4 and IPv6 alike, so that enriching
    an attribute cannot make the server request loopback, private, unique local
    or link-local targets such as cloud metadata endpoints. An IPv6 address
    that carries an IPv4 one must be routable on both counts.

    A backslash, whitespace or control character is refused outright: urlparse
    and the requests stack behind url_archiver split such a URL differently, so
    "http://127.0.0.1\\@example.com/" would be checked as example.com and
    fetched from 127.0.0.1."""
    if "\\" in url or any(ord(char) <= 32 or ord(char) == 127 for char in url):
        return False
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
    except ValueError:
        # an unclosed or invalid bracketed IPv6 host, as in "http://[::1/"
        return False
    if parsed.scheme not in ("http", "https") or not hostname:
        return False
    try:
        resolved = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError):
        return False
    return all(_is_public_address(info[4][0]) for info in resolved)


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
    if not is_safe_url(tocache):
        return {"error": f"Blocked URL {tocache}: only http and https URLs of public addresses are cached."}

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
