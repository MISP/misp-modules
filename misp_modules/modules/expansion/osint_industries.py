import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["email-src", "email-dst", "phone-number", "github-username", "btc"],
    "format": "misp_standard",
}
moduleconfig = ["apikey", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "OSINT Industries",
    "description": "Find OSINT Industries account and identity context for an email, phone, username or wallet.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Uses POST /v2/request with api-key header authentication, exact_match=true and premium lookups disabled."
        " Username attributes query the username selector; BTC addresses query wallet. max_results defaults to 25"
        " (1-100). Module-level results retain provenance in annotations; registered accounts become user-account"
        " objects and valid profile URLs become links. Lookups can consume API credits."
    ),
    "references": ["https://docs.osint.industries/"],
    "input": "email-src, email-dst, phone-number, github-username, btc MISP attribute.",
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


def _account_fields(row):
    spec, data = row.get("spec_format"), row.get("data")
    flat = {}
    if isinstance(spec, dict):
        flat.update({key: item.get("value") for key, item in spec.items() if isinstance(item, dict)})
    elif isinstance(spec, list):
        for item in spec:
            if not isinstance(item, dict):
                raise ModuleError("OSINT Industries returned an invalid typed field.")
            key = item.get("key") or item.get("id") or item.get("name") or item.get("proper_key")
            if isinstance(key, str):
                key = key.strip().lower().replace(" ", "_").replace("-", "_")
                flat[key] = item.get("value")
    elif not isinstance(data, dict):
        raise ModuleError("OSINT Industries returned an invalid account record.")
    if isinstance(data, dict):
        for key, item in data.items():
            value = item.get("value") if isinstance(item, dict) and "value" in item else item
            if value is not None and value != "":
                flat[key] = value
    if isinstance(flat.get("registered"), str) and flat["registered"].lower() in ("true", "false"):
        flat["registered"] = flat["registered"].lower() == "true"
    if flat.get("id") is None:
        flat["id"] = flat.get("user_id") or flat.get("account_id")
    return flat


def _expand(event, attribute, config):
    value, limit = (_value(attribute), _limit(config))
    selector = {
        "email-src": "email",
        "email-dst": "email",
        "phone-number": "phone",
        "github-username": "username",
        "btc": "wallet",
    }[attribute["type"]]
    if selector == "email" and (not re.fullmatch("[^@\\s]+@[^@\\s]+\\.[^@\\s]+", value)):
        raise ModuleError("Invalid email address.")
    if selector == "phone" and (not re.fullmatch("\\+?[0-9][0-9 ()-]{5,24}", value)):
        raise ModuleError("Invalid phone number.")
    data = _request(
        "POST",
        "https://api.osint.industries/v2/request",
        headers={"api-key": config["apikey"]},
        json={
            "type": selector,
            "query": value,
            "timeout": 25,
            "exact_match": True,
            "premium": False,
            "premium_modules_only": False,
        },
    )
    if data is None:
        return _results(event)
    if not isinstance(data, list) or not all((isinstance(row, dict) for row in data)):
        raise ModuleError("OSINT Industries returned an unexpected response or rejected the lookup.")
    for row in _cap(event, attribute, data, limit):
        flat = _account_fields(row)
        _annotation(event, attribute, "OSINT Industries " + str(row.get("module", row.get("name", "result"))), row)
        if flat.get("registered") is False:
            continue
        username = flat.get("username")
        if isinstance(username, str) and username and (username != "XXXXXXX"):
            obj = MISPObject("user-account")
            obj.add_attribute("username", value=username, to_ids=False)
            if flat.get("id") is not None:
                obj.add_attribute("user-id", value=str(flat["id"]), to_ids=False)
            obj.add_reference(attribute["uuid"], "related-to")
            event.add_object(obj)
        profile = flat.get("profile_url") or flat.get("url")
        if isinstance(profile, str) and urlsplit(profile).scheme in ("http", "https") and urlsplit(profile).hostname:
            event.add_attribute("link", profile, to_ids=False, comment="OSINT Industries profile")
    return _results(event)
