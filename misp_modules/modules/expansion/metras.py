import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha1", "sha256", "ip-src", "ip-dst"], "format": "misp_standard"}
moduleconfig = ["apikey", "url", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Metras Enrichment",
    "description": "Enrich file hashes and IP addresses with Metras EDR inventory and fleet context.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "url defaults to https://api.metras.sa/api. Uses X-API-KEY authentication. Hash lookups query binary details"
        " (MD5) or binary inventory (SHA-1/SHA-256). IP lookups query EDR alerts and endpoint inventory. max_results"
        " defaults to 25 (1-100). Results retain binary metadata, alert context and fleet hostnames; additional pages"
        " are reported as truncated."
    ),
    "references": ["https://metras.sa/"],
    "input": "md5, sha1, sha256, ip-src, ip-dst MISP attribute.",
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
    value, kind = (_value(attribute), attribute["type"])
    base, limit = (_base(config, "https://api.metras.sa/api"), _limit(config))
    headers = {"X-API-KEY": config["apikey"]}
    if kind in HASH_LENGTHS:
        path = "/v1/edr/binary/details" if kind == "md5" else "/v1/edr/binary/list"
        params = (
            {"md5": value}
            if kind == "md5"
            else {"query": kind + ":" + value, "limit": limit, "skip": 0, "full": "true"}
        )
        data = _request("GET", base + path, params=params, headers=headers)
        if data is None:
            return _results(event)
        rows = [data] if isinstance(data, dict) and data.get("md5") else _rows(data, "data")
        total = data.get("totalCount", 0)
        for row in _cap(
            event, attribute, rows, limit, bool(data.get("more")) or (isinstance(total, int) and total > limit)
        ):
            if _hash(kind, row.get(kind, "")) != value:
                continue
            _annotation(event, attribute, "Metras binary inventory", row)
            _file(event, attribute, dict(row, filename=row.get("name")))
    else:
        endpoints = (
            ("/v1/edr/alerts", {"agent_ip": value, "limit": limit, "skip": 0}, "data"),
            ("/v1/endpoints", {"interface_ip": value}, "endpoints"),
        )
        for path, params, key in endpoints:
            data = _request("GET", base + path, params=params, headers=headers)
            if data is None:
                continue
            rows = _rows(data, key)
            for row in _cap(event, attribute, rows, limit, bool(data.get("more"))):
                _annotation(event, attribute, "Metras " + key, row)
                if key == "endpoints" and isinstance(row.get("name"), str) and row["name"]:
                    event.add_attribute("hostname", row["name"], to_ids=False, comment="Metras fleet endpoint")
    return _results(event)
