import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst", "domain", "hostname"], "format": "misp_standard"}
moduleconfig = ["url", "username", "password", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "IVRE",
    "description": "Retrieve active scan observations from an IVRE web API.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "url is the complete HTTPS view endpoint, for example https://ivre.example/cgi/view. Sends a structured f"
        " filter (host or domain) and q=limit:N, with JSON output and string dates. Optional username/password use HTTP"
        " Basic authentication. max_results defaults to 25 (1-100). Returns domain-ip and ip-port objects for open"
        " ports, with scan context in annotations. This module performs no scans and requires the IVRE view API to be"
        " exposed."
    ),
    "references": [
        "https://doc.ivre.rocks/en/latest/usage/web-ui.html",
        "https://github.com/ivre/ivre/blob/master/ivre/web/app.py",
    ],
    "input": "ip-src, ip-dst, domain, hostname MISP attribute.",
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
    if response.status_code == 204:
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
        for key in ["url"]:
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
    base = _base(config)
    if bool(config.get("username")) != bool(config.get("password")):
        raise ModuleError("username and password must be configured together.")
    auth = (config["username"], config["password"]) if config.get("username") else None
    field = (
        "host"
        if attribute["type"] in ("ip-src", "ip-dst")
        else "hostname" if attribute["type"] == "hostname" else "domain"
    )
    data = _request(
        "GET",
        base,
        params={
            "f": json.dumps({"f": field, "a": [value]}),
            "q": "limit:" + str(limit + 1),
            "format": "json",
            "datesasstrings": "1",
        },
        auth=auth,
    )
    if data is None:
        return _results(event)
    if not isinstance(data, list) or not all((isinstance(row, dict) for row in data)):
        raise ModuleError("IVRE returned an unexpected scan response.")
    for row in _cap(event, attribute, data, limit):
        address = str(ip_address(row["addr"]))
        if field == "host" and address != value:
            raise ModuleError("IVRE returned a different host.")
        _annotation(event, attribute, "IVRE scan context", row)
        for hostname in row.get("hostnames", [])[:limit]:
            obj = MISPObject("domain-ip", strict=True)
            obj.add_attribute("ip", value=address, to_ids=False)
            obj.add_attribute("domain", value=_domain(hostname["name"]), to_ids=False)
            obj.add_reference(attribute["uuid"], "related-to")
            event.add_object(obj)
        ports = [p for p in row.get("ports", []) if p.get("state_state") == "open" and p.get("port", -1) >= 0]
        for port in _cap(event, attribute, ports, limit):
            number = port["port"]
            if isinstance(number, bool) or not isinstance(number, int) or (not 0 <= number <= 65535):
                raise ModuleError("IVRE returned an invalid port.")
            obj = MISPObject("ip-port", strict=True)
            obj.add_attribute("ip", value=address, to_ids=False)
            obj.add_attribute("dst-port", value=number, to_ids=False)
            if port.get("protocol"):
                obj.add_attribute("protocol", value=port["protocol"], to_ids=False)
            obj.add_reference(attribute["uuid"], "related-to")
            event.add_object(obj)
    return _results(event)
