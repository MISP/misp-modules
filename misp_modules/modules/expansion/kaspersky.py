import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import quote, urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["md5", "sha1", "sha256", "ip-src", "ip-dst", "domain", "hostname", "url"],
    "format": "misp_standard",
}
moduleconfig = ["apikey", "url", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Kaspersky Threat Intelligence Portal",
    "description": "Retrieve Kaspersky commercial Threat Intelligence Portal reports.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Uses Bearer authentication with GET /api/hash, /api/ip, /api/domain or /api/url and explicit report sections."
        " url defaults to https://tip.kaspersky.com. Requires a commercial TIP key; this is separate from the public"
        " OpenTIP API. File hashes, sizes and names become file objects; DNS resolutions become domain-ip objects."
        " Zone, license/quota and report sections are retained as provider context without changing detection flags."
        " max_results defaults to 25 (1-100) for files and DNS resolutions."
    ),
    "references": ["https://tip.kaspersky.com/"],
    "input": "md5, sha1, sha256, ip-src, ip-dst, domain, hostname, url MISP attribute.",
    "output": "Referenced enrichment objects and pivotable attributes.",
}
TIMEOUT = 30
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


class ModuleError(ValueError):
    """An actionable error that contains no request credentials."""


def _request(method, url, response_format="json", **kwargs):
    try:
        response = requests.request(method, url, timeout=TIMEOUT, allow_redirects=False, verify=True, **kwargs)
    except requests.RequestException:
        raise ModuleError("The service request failed or timed out.") from None
    if response.status_code in (404, 204):
        return None
    if response.status_code not in (200, 201, 202):
        raise ModuleError(f"The service returned HTTP {response.status_code}.")
    if response_format == "bytes":
        return response.content
    if response_format == "xml":
        if b"<!ENTITY" in response.content.upper() or re.search(b"<!DOCTYPE[^>]*\\[", response.content, re.I):
            raise ModuleError("The service returned XML with a forbidden declaration.")
        try:
            return ET.fromstring(response.content)
        except ET.ParseError:
            raise ModuleError("The service returned invalid XML.") from None
    try:
        return response.json()
    except ValueError:
        raise ModuleError("The service returned invalid JSON.") from None


def _base(config, default=None):
    value = config.get("url") or default
    if not isinstance(value, str):
        raise ModuleError("Missing url configuration.")
    value = value.strip().rstrip("/")
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or (parts.port == 0)
    ):
        raise ModuleError("url must be an HTTPS URL without credentials, a query or a fragment.")
    return value


def _domain(value):
    if not isinstance(value, str):
        raise ModuleError("Invalid domain or hostname.")
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(
        (re.fullmatch("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split("."))
    ):
        raise ModuleError("Invalid domain or hostname.")
    return value


def _hash(kind, value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-fA-F]{%d}" % HASH_LENGTHS[kind], value):
        raise ModuleError(f"Invalid {kind} hash.")
    return value.lower()


def _value(attribute):
    kind, value = (attribute["type"], attribute["value"].strip())
    if kind in HASH_LENGTHS:
        return _hash(kind, value)
    if kind in ("ip-src", "ip-dst"):
        return str(ip_address(value))
    if kind in ("domain", "hostname"):
        return _domain(value)
    if kind == "url":
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ModuleError("Invalid HTTP(S) URL.")
    return value


def _limit(config, key="max_results", default=25, maximum=100):
    value = config.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not str(value).isdigit() or (not 1 <= int(value) <= maximum):
        raise ModuleError(f"{key} must be an integer between 1 and {maximum}.")
    return int(value)


def _annotation(event, attribute, title, data):
    obj = MISPObject("annotation")
    obj.comment = title
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True, indent=2), to_ids=False, disable_correlation=True)
    obj.add_reference(attribute["uuid"], "describes")
    event.add_object(obj)


def _file(event, attribute, data, mapping=None):
    mapping = mapping or {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}
    obj = MISPObject("file")
    for kind, key in mapping.items():
        if data.get(key):
            obj.add_attribute(kind, value=_hash(kind, data[key]), to_ids=False)
    for relation, key in (("filename", "filename"), ("mimetype", "mimetype"), ("size-in-bytes", "size")):
        if data.get(key) is not None and data[key] != "":
            obj.add_attribute(relation, value=data[key], to_ids=False)
    if obj.attributes:
        obj.add_reference(attribute["uuid"], "related-to")
        event.add_object(obj)


def _rows(data, key):
    if (
        not isinstance(data, dict)
        or not isinstance(data.get(key), list)
        or (not all((isinstance(row, dict) for row in data[key])))
    ):
        raise ModuleError("The service returned an unexpected response.")
    return data[key]


def _cap(event, attribute, rows, limit, more=False):
    if len(rows) > limit or more:
        _annotation(
            event, attribute, moduleinfo["name"] + " result limit", {"limit": limit, "more_results_available": True}
        )
    return rows[:limit]


def _results(event):
    data = json.loads(event.to_json())
    return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all((attribute.get(k) for k in ("type", "value", "uuid"))):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Unsupported attribute type.")
        if not isinstance(attribute["value"], str) or not attribute["value"].strip():
            raise ModuleError("The attribute value must be a nonempty string.")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        for key in ["apikey"]:
            if not isinstance(config.get(key), str) or not config[key].strip():
                raise ModuleError(f"Missing {key} configuration.")
        event = MISPEvent()
        event.add_attribute(**attribute)
        return _expand(event, attribute, config)
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, OverflowError, OSError, AttributeError, IndexError):
        return {"error": "Invalid request or service response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)


def _expand(event, attribute, config):
    value = _value(attribute)
    limit = _limit(config)
    kind = attribute["type"]
    if kind in HASH_LENGTHS:
        endpoint, section = ("hash", "FileGeneralInfo")
        extra = "FileNames,DetectionsInfo"
    elif kind in ("ip-src", "ip-dst"):
        if ip_address(value).version != 4:
            raise ModuleError("This Kaspersky TIP endpoint supports IPv4 addresses.")
        endpoint, section, extra = ("ip", "IpGeneralInfo", "IpDnsResolutions")
    elif kind in ("domain", "hostname"):
        endpoint, section, extra = ("domain", "DomainGeneralInfo", "DomainDnsResolutions")
    else:
        endpoint, section, extra = ("url", "UrlGeneralInfo", "FilesDownloaded")
    data = _request(
        "GET",
        _base(config, "https://tip.kaspersky.com") + "/api/" + endpoint + "/" + quote(value, safe=""),
        headers={"Authorization": "Bearer " + config["apikey"], "Accept": "application/json"},
        params={"sections": "LicenseInfo,Zone," + section + "," + extra},
    )
    if data is None:
        return _results(event)
    if not isinstance(data, dict) or not isinstance(data.get(section), dict):
        raise ModuleError("Kaspersky returned an unexpected report or no licensed report data.")
    _annotation(event, attribute, "Kaspersky TIP report", data)
    mapping = {"md5": "Md5", "sha1": "Sha1", "sha256": "Sha256"}
    if endpoint == "hash":
        info = data[section]
        if info.get(mapping[kind]) and _hash(kind, info[mapping[kind]]) != value:
            raise ModuleError("Kaspersky returned a different file hash.")
        _file(event, attribute, dict(info, size=info.get("Size")), mapping)
        filenames = []
        for row in _optional_rows(data, "FileNames"):
            names = row.get("FileNames", row.get("FileName"))
            if isinstance(names, str):
                filenames.append(names)
            elif isinstance(names, list) and all(isinstance(name, str) for name in names):
                filenames.extend(names)
            elif names is not None:
                raise ModuleError("Kaspersky returned an invalid filename section.")
        for filename in _cap(event, attribute, filenames, limit):
            _file(event, attribute, dict(info, filename=filename), mapping)
    elif endpoint in ("ip", "domain"):
        key = "IpDnsResolutions" if endpoint == "ip" else "DomainDnsResolutions"
        for row in _cap(event, attribute, _optional_rows(data, key), limit):
            obj = MISPObject("domain-ip", strict=True)
            obj.add_attribute("domain", value=_domain(row["Domain"] if endpoint == "ip" else value), to_ids=False)
            obj.add_attribute("ip", value=str(ip_address(value if endpoint == "ip" else row["Ip"])), to_ids=False)
            if row.get("FirstSeen"):
                obj.add_attribute("first-seen", value=row["FirstSeen"], to_ids=False)
            if row.get("LastSeen"):
                obj.add_attribute("last-seen", value=row["LastSeen"], to_ids=False)
            obj.add_reference(attribute["uuid"], "related-to")
            event.add_object(obj)
    elif endpoint == "url":
        for row in _cap(event, attribute, _optional_rows(data, "FilesDownloaded"), limit):
            _file(event, attribute, dict(row, size=row.get("Size")), mapping)
    return _results(event)


def _optional_rows(data, key):
    return [] if data.get(key) is None else _rows(data, key)
