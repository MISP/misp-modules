import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["vulnerability"], "format": "misp_standard"}
moduleconfig = ["url", "username", "password", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Qualys CVE Enrichment",
    "description": "Retrieve Qualys KnowledgeBase vulnerability details for a CVE identifier.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Set url to the HTTPS API URL for your Qualys platform. Uses Basic authentication and GET"
        " /api/4.0/fo/knowledge_base/vuln/ with action=list, details=All and the cve filter. max_results defaults to 25"
        " (1-100). All matching QIDs retain title, diagnosis, solution, severity and CVSS data. Only entries explicitly"
        " containing the requested CVE are imported. Does not query customer host inventories."
    ),
    "references": ["https://docs.qualys.com/en/vm/api/"],
    "input": "vulnerability MISP attribute.",
    "output": "Referenced enrichment objects and pivotable attributes.",
}
TIMEOUT = 30


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
        for key in ["url", "username", "password"]:
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
    cve, base, limit = (attribute["value"].strip().upper(), _base(config), _limit(config))
    if not re.fullmatch("CVE-[0-9]{4}-[0-9]{4,}", cve):
        raise ModuleError("Invalid CVE identifier.")
    root = _request(
        "GET",
        base + "/api/4.0/fo/knowledge_base/vuln/",
        response_format="xml",
        auth=(config["username"], config["password"]),
        headers={"X-Requested-With": "MISP modules"},
        params={"action": "list", "details": "All", "cve": cve},
    )
    if root is None:
        return _results(event)
    if root.tag != "KNOWLEDGE_BASE_VULN_LIST_OUTPUT" or root.find(".//CODE") is not None:
        raise ModuleError("Qualys rejected the lookup or returned an unexpected XML response.")
    rows = [vuln for vuln in root.findall(".//VULN") if cve in [node.text for node in vuln.findall("CVE_LIST/CVE/ID")]]
    for vuln in _cap(event, attribute, rows, limit):
        obj = MISPObject("vulnerability")
        obj.comment = "Qualys QID " + vuln.findtext("QID", "unknown")
        obj.add_attribute("id", value=cve, to_ids=False)
        for relation, tag in (("summary", "TITLE"), ("description", "DIAGNOSIS")):
            text = vuln.findtext(tag)
            if text:
                obj.add_attribute(relation, type="text", value=text, to_ids=False)
        score = vuln.findtext("CVSS_V3/BASE") or vuln.findtext("CVSS/BASE")
        if score is not None:
            number = float(score)
            if not 0 <= number <= 10:
                raise ModuleError("Qualys returned an invalid CVSS score.")
            obj.add_attribute("cvss-score", value=number, to_ids=False)
        obj.add_reference(attribute["uuid"], "describes")
        event.add_object(obj)
        details = {
            key: vuln.findtext(key)
            for key in ("QID", "SEVERITY_LEVEL", "SOLUTION", "CONSEQUENCE", "PUBLISHED_DATETIME")
            if vuln.findtext(key) is not None
        }
        _annotation(event, attribute, "Qualys vulnerability context", details)
    if root.find(".//WARNING/URL") is not None:
        _annotation(event, attribute, "Qualys result limit", {"additional_page_available": True})
    return _results(event)
