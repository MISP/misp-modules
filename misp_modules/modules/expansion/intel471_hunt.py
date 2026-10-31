import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["vulnerability", "text"], "format": "misp_standard"}
moduleconfig = ["apikey", "search_type", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Intel 471 Hunter",
    "description": "Retrieve Intel 471 Hunter hunt packages, Sigma rules and analyst guidance.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Uses GET /es/query with Authorization: API-Key and indexes=cyborg_usecases. CVEs use exploit_or_vulns; text"
        " uses search_type, default mitre_technique_ids, with actors, threat_names, mitre_technique_names and"
        " mitre_tactic_names also supported. max_results defaults to 25 (1-100). Sigma rules become sigma objects;"
        " package metadata and runbooks are preserved in annotations. Requires a Hunter subscription, separate from"
        " Titan IOC access."
    ),
    "references": ["https://hunter.cyborgsecurity.io/", "https://api.hunter.cyborgsecurity.io/docs"],
    "input": "vulnerability, text MISP attribute.",
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
    search = (
        "exploit_or_vulns"
        if attribute["type"] == "vulnerability"
        else config.get("search_type") or "mitre_technique_ids"
    )
    if search not in (
        "exploit_or_vulns",
        "actors",
        "threat_names",
        "mitre_technique_ids",
        "mitre_technique_names",
        "mitre_tactic_names",
    ):
        raise ModuleError("Invalid search_type configuration.")
    if search == "exploit_or_vulns" and (not re.fullmatch("CVE-\\d{4}-\\d{4,}", value, re.I)):
        raise ModuleError("A CVE identifier is required for exploit_or_vulns.")
    if search == "mitre_technique_ids" and (not re.fullmatch("T\\d{4}(?:\\.\\d{3})?", value, re.I)):
        raise ModuleError("An ATT&CK technique identifier is required.")
    if search in ("exploit_or_vulns", "mitre_technique_ids"):
        value = value.upper()
    data = _request(
        "GET",
        "https://api.hunter.cyborgsecurity.io/es/query",
        headers={
            "Authorization": "API-Key " + config["apikey"],
            "Accept": "application/json",
            "User-Agent": "MISP-modules/Intel471-Hunter",
        },
        params={"indexes": "cyborg_usecases", search: value, "size": limit},
    )
    if data is None:
        return _results(event)
    rows = _rows(data, "results")
    for row in _cap(event, attribute, rows, limit, int(data.get("total", len(rows))) > min(len(rows), limit)):
        _annotation(event, attribute, "Intel 471 Hunter hunt package", {k: v for k, v in row.items() if k != "sigma"})
        if row.get("sigma"):
            if not isinstance(row["sigma"], str):
                raise ModuleError("Hunter returned an invalid Sigma rule.")
            obj = MISPObject("sigma", strict=True)
            obj.add_attribute("sigma", value=row["sigma"], to_ids=False)
            if row.get("title"):
                obj.add_attribute("sigma-rule-name", value=row["title"], to_ids=False)
            obj.add_reference(attribute["uuid"], "related-to")
            event.add_object(obj)
    return _results(event)
