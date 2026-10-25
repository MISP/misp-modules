import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import quote, urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "hostname", "ip-src", "ip-dst"], "format": "misp_standard"}
moduleconfig = ["apikey", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Host.io",
    "description": "Retrieve Host.io DNS, website and co-hosted domain observations.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Uses Bearer authentication and GET /api/full/{domain} or /api/domains/ip/{ip}. max_results defaults to 5"
        " (1-100), matching the free plan page size. A single page is requested; a notice identifies additional"
        " domains. DNS records become a dns-record object; website, IPinfo and related-domain metadata remain in a"
        " referenced annotation."
    ),
    "references": ["https://host.io/docs"],
    "input": "domain, hostname, ip-src, ip-dst MISP attribute.",
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
    limit = _limit(config, default=5)
    headers = {"Authorization": "Bearer " + config["apikey"], "Accept": "application/json"}
    if attribute["type"] in ("ip-src", "ip-dst"):
        page_size = next(size for size in (1, 5, 10, 25, 100) if size >= limit)
        data = _request(
            "GET",
            "https://host.io/api/domains/ip/" + quote(value, safe=""),
            headers=headers,
            params={"limit": page_size, "page": 0},
        )
        if data is None:
            return _results(event)
        if not isinstance(data, dict) or not isinstance(data.get("domains"), list):
            raise ModuleError("Host.io returned an unexpected domain page.")
        rows = data["domains"]
        more = int(data.get("total", len(rows))) > limit
        for domain in _cap(event, attribute, rows, limit, more):
            obj = MISPObject("domain-ip", strict=True)
            obj.add_attribute("domain", value=_domain(domain), to_ids=False)
            obj.add_attribute("ip", value=value, to_ids=False)
            obj.add_reference(attribute["uuid"], "related-to")
            event.add_object(obj)
    else:
        data = _request("GET", "https://host.io/api/full/" + quote(value, safe=""), headers=headers)
        if data is None:
            return _results(event)
        if not isinstance(data, dict) or not isinstance(data.get("dns"), dict):
            raise ModuleError("Host.io returned an unexpected domain report.")
        obj = MISPObject("dns-record", strict=True)
        obj.add_attribute("queried-domain", value=value, to_ids=False)
        for key, relation in (("a", "a-record"), ("aaaa", "aaaa-record"), ("mx", "mx-record"), ("ns", "ns-record")):
            rows = data["dns"].get(key, [])
            if not isinstance(rows, list):
                raise ModuleError("Host.io returned invalid DNS records.")
            for raw in _cap(event, attribute, rows, limit):
                if key in ("a", "aaaa"):
                    address = ip_address(raw)
                    if address.version != (4 if key == "a" else 6):
                        raise ModuleError("Host.io returned an invalid address family.")
                    record = str(address)
                else:
                    record = _domain(raw.split()[-1] if key == "mx" else raw)
                obj.add_attribute(relation, value=record, to_ids=False)
        obj.add_reference(attribute["uuid"], "related-to")
        event.add_object(obj)
        _annotation(
            event, attribute, "Host.io domain context", {k: data[k] for k in ("web", "ipinfo", "related") if k in data}
        )
    return _results(event)
