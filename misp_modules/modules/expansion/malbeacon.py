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
    "name": "MalBeacon",
    "description": "Retrieve MalBeacon C2 and actor infrastructure observations.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Uses GET /v1/c2/c2/{value} with X-Api-Key authentication. max_results defaults to 25 (1-100). Beacon records"
        " retain timestamps, provider context, tags and user agents in referenced annotations; actor IPs, hostnames and"
        " C2 domains become pivotable attributes."
    ),
    "references": ["https://malbeacon.com/"],
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
    limit = _limit(config)
    data = _request(
        "GET", "https://api.malbeacon.com/v1/c2/c2/" + quote(value, safe=""), headers={"X-Api-Key": config["apikey"]}
    )
    if data is None or data == []:
        return _results(event)
    if not isinstance(data, list) or not all((isinstance(row, dict) for row in data)):
        raise ModuleError("MalBeacon returned an unexpected response or rejected the lookup.")
    seen = set()
    for row in _cap(event, attribute, data, limit):
        _annotation(event, attribute, "MalBeacon C2 observation", row)
        for key, kind in (
            ("actorip", "ip-src"),
            ("actorhostname", "hostname"),
            ("c2domain", "domain"),
            ("c2hostname", "hostname"),
        ):
            raw = row.get(key)
            if not raw or raw == "NA":
                continue
            if not isinstance(raw, str):
                raise ModuleError("MalBeacon returned an invalid infrastructure value.")
            if key == "c2domain":
                try:
                    value, kind = str(ip_address(raw)), "ip-dst"
                except ValueError:
                    value = _domain(raw)
            else:
                value = str(ip_address(raw)) if kind == "ip-src" else _domain(raw)
            if (kind, value) not in seen:
                seen.add((kind, value))
                event.add_attribute(kind, value, to_ids=False, comment="MalBeacon " + key)
    return _results(event)
