import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import urlsplit

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
    "name": "LastInfoSec",
    "description": "Retrieve LastInfoSec STIX 2.1 intelligence and convert it to MISP.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests", "misp-stix"],
    "features": (
        "Posts {value: observable} to /stix21/search/ at url (default https://api.client.lastinfosec.com/v2). The"
        " legacy API requires api_key in query parameters; configure proxy and access-log redaction accordingly. HTTP"
        " 422 means no match. Converts all returned message bundles up to max_results (default 25, 1-100), preserving"
        " relationships and markings with misp-stix and indicating partial conversions. Requires a working legacy"
        " LastInfoSec endpoint and subscription."
    ),
    "references": ["https://api.client.lastinfosec.com/v2/"],
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
    if response.status_code in (404, 204, 422):
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


def _convert(event, attribute, data):
    if data is None or data == {}:
        return _results(event)
    if not isinstance(data, dict) or data.get("type") != "bundle" or (not isinstance(data.get("objects"), list)):
        raise ModuleError("LastInfoSec returned an unexpected STIX bundle.")
    if not data["objects"]:
        return _results(event)
    try:
        from misp_stix_converter import ExternalSTIX2toMISPParser
        from stix2 import parse

        parser = ExternalSTIX2toMISPParser()
        parser.load_stix_bundle(parse(json.dumps(data), allow_custom=True))
        parser.parse_stix_bundle(single_event=True)
        converted = parser.misp_event
    except ImportError:
        raise ModuleError("The misp-stix package is required for LastInfoSec enrichment.") from None
    except Exception:
        raise ModuleError("The LastInfoSec STIX bundle could not be converted.") from None
    if parser.errors:
        if not converted.attributes and (not converted.objects):
            raise ModuleError("The LastInfoSec STIX bundle contains no usable converted intelligence.")
        event.add_attribute(
            "text",
            "Some LastInfoSec intelligence could not be converted; results are partial.",
            to_ids=False,
            disable_correlation=True,
            comment="LastInfoSec conversion notice",
        )
    for item in converted.attributes:
        item.to_ids = False
        event.add_attribute(**item)
    for obj in converted.objects:
        for item in obj.attributes:
            item.to_ids = False
        obj.add_reference(attribute["uuid"], "related-to")
        event.add_object(obj)
    for tag in converted.tags:
        event.add_tag(tag)
    data = json.loads(event.to_json())
    return {"results": {key: data.get(key, []) for key in ("Attribute", "Object", "Tag")}}


def _expand(event, attribute, config):
    value = _value(attribute)
    limit = _limit(config)
    data = _request(
        "POST",
        _base(config, "https://api.client.lastinfosec.com/v2") + "/stix21/search/",
        params={"api_key": config["apikey"], "platform": "misp"},
        json={"value": value},
    )
    if data is None:
        return _results(event)
    rows = _rows(data, "message")
    failures = 0
    usable = False
    for row in _cap(event, attribute, rows, limit):
        before = len(event.attributes) + len(event.objects)
        try:
            _convert(event, attribute, row)
        except ModuleError:
            failures += 1
        else:
            usable = usable or len(event.attributes) + len(event.objects) > before
    if failures:
        if not usable:
            raise ModuleError("The LastInfoSec bundles contain no usable converted intelligence.")
        _annotation(event, attribute, "LastInfoSec conversion notice", {"partial": True, "failed_bundles": failures})
    data = json.loads(event.to_json())
    return {"results": {key: data.get(key, []) for key in ("Attribute", "Object", "Tag")}}
