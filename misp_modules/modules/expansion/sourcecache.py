import ipaddress
import json
import socket
from urllib.parse import urlparse

from url_archiver import url_archiver

misperrors = {"error": "Error"}
mispattributes = {"input": ["link", "url"], "output": ["attachment", "malware-sample"]}
moduleinfo = {
    "version": "0.1",
    "author": "Alexandre Dulaunoy",
    "description": (
        "Module to cache web pages of analysis reports, OSINT sources. The module returns a link of the cached page."
    ),
    "module-type": ["expansion"],
    "name": "URL Archiver",
    "logo": "",
    "requirements": ["urlarchiver: python library to fetch and archive URL on the file-system"],
    "features": (
        "This module takes a link or url attribute as input and caches the related web page. It returns then a link of"
        " the cached page."
    ),
    "references": ["https://github.com/adulau/url_archiver"],
    "input": "A link or url attribute.",
    "output": "A malware-sample attribute describing the cached page.",
}
moduleconfig = ["archivepath"]


def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        resolved = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        return False
    for info in resolved:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return False
    return True


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get("config"):
        archive_path = request["config"]["archivepath"]
    else:
        archive_path = "/tmp/"
    if request.get("link"):
        tocache = request["link"]
        output = ["attachment"]
    elif request.get("url"):
        tocache = request["url"]
        output = ["malware-sample"]
    else:
        misperrors["error"] = "Link is missing"
        return misperrors
    if not is_safe_url(tocache):
        misperrors["error"] = "Blocked URL"
        return misperrors
    data = __archiveLink(archive_path, tocache)
    mispattributes["output"] = output
    enc_data = data.decode("ascii")
    r = {"results": [{"types": mispattributes["output"], "values": tocache, "data": enc_data}]}
    return r


def __archiveLink(archive_path, tocache):
    archiver = url_archiver.Archive(archive_path=archive_path)
    return archiver.fetch(url=tocache, armor=True)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
