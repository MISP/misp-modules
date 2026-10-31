import json
from ipaddress import ip_address
from urllib.parse import quote

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleconfig = []
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Shodan InternetDB",
    "description": "Look up exposed services, hostnames, CPEs and vulnerabilities in the free Shodan InternetDB API.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "No API key is required. Supports IPv4 and IPv6. A 404 means no information is available. Hostnames and"
        " vulnerabilities are pivotable attributes; ports are grouped in an ip-port object. Service tags are retained"
        " as context, without automatically tagging the source as malicious."
    ),
    "references": ["https://internetdb.shodan.io/"],
    "input": "ip-src, ip-dst MISP attribute.",
    "output": "An ip-port object and hostname, CPE and vulnerability attributes.",
}
TIMEOUT = 30


class ModuleError(ValueError):
    """An actionable module error safe to return to the caller."""


def _get(url, **kwargs):
    try:
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=False, **kwargs)
    except requests.RequestException:
        raise ModuleError("The service request failed or timed out.") from None
    if response.status_code == 404:
        return None
    if response.status_code == 204:
        return None
    if response.status_code != 200:
        raise ModuleError(f"The service returned HTTP {response.status_code}.")
    try:
        return response.json()
    except ValueError:
        raise ModuleError("The service returned invalid JSON.") from None


def _ip(value):
    return str(ip_address(value))


def _annotation(event, attribute, title, data):
    obj = MISPObject("annotation")
    obj.comment = title
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True, indent=2), to_ids=False, disable_correlation=True)
    obj.add_reference(attribute["uuid"], "describes")
    event.add_object(obj)


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
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        event = MISPEvent()
        event.add_attribute(**attribute)
        return _expand(event, attribute, config)
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, OverflowError, OSError):
        return {"error": "Invalid request or service response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)


def _expand(event, attribute, config):
    address = _ip(attribute["value"].strip())
    data = _get("https://internetdb.shodan.io/" + quote(address, safe=""))
    if data is None:
        return _results(event)
    if not isinstance(data, dict) or _ip(data.get("ip", "")) != address:
        raise ModuleError("InternetDB returned an unexpected IP address or response.")
    for key in ("ports", "hostnames", "cpes", "vulns", "tags"):
        if not isinstance(data.get(key, []), list):
            raise ModuleError("InternetDB returned an unexpected response.")
    if data.get("ports"):
        obj = MISPObject("ip-port")
        obj.add_attribute(attribute["type"], value=address, to_ids=False)
        relation = attribute["type"].replace("ip-", "") + "-port"
        for port in dict.fromkeys(data["ports"]):
            if isinstance(port, bool) or not isinstance(port, int) or (not 0 <= port <= 65535):
                raise ModuleError("InternetDB returned an invalid port.")
            obj.add_attribute(relation, value=port, to_ids=False)
        obj.add_reference(attribute["uuid"], "describes")
        event.add_object(obj)
    for key, kind in (("hostnames", "hostname"), ("cpes", "cpe"), ("vulns", "vulnerability")):
        for value in dict.fromkeys(data.get(key, [])):
            if not isinstance(value, str) or not value:
                raise ModuleError("InternetDB returned an invalid value.")
            event.add_attribute(kind, value, to_ids=False, comment="Shodan InternetDB")
    if data.get("tags"):
        _annotation(event, attribute, "Shodan InternetDB service tags", {"tags": data["tags"]})
    return _results(event)
