import ipaddress
import json
import re
import zipfile
from urllib.parse import quote
from uuid import UUID
import requests
from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError


class ModuleError(ValueError):
    """A diagnostic safe to show to the analyst."""


def _integer(config, key, default, maximum=100):
    value = config.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not str(value).isdigit() or (not 1 <= int(value) <= maximum):
        raise ModuleError(f"{key} must be an integer between 1 and {maximum}.")
    return int(value)


def _segment(value):
    return quote(str(value), safe="")


def _normalise(kind, value):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise ModuleError("A nonempty string value is required.")
    value = value.strip()
    if kind in ("md5", "sha1", "sha256", "x509-fingerprint-sha256"):
        length = {"md5": 32, "sha1": 40}.get(kind, 64)
        if not re.fullmatch("[a-fA-F0-9]{%d}" % length, value):
            raise ModuleError("Invalid hash.")
        return value.lower()
    if kind in ("ip-src", "ip-dst"):
        return str(ipaddress.ip_address(value))
    if kind in ("domain", "hostname"):
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
        if len(value) > 253 or not all(
            re.fullmatch("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")
        ):
            raise ModuleError("Invalid DNS name.")
    if kind == "vulnerability":
        value = value.upper()
        if not re.fullmatch("CVE-[0-9]{4}-[0-9]{4,}", value):
            raise ModuleError("A CVE identifier is required.")
    return value


def _call(method, url, **kwargs):
    try:
        response = requests.request(method, url, timeout=(5, 30), verify=True, allow_redirects=False, **kwargs)
    except requests.RequestException:
        raise ModuleError(
            "The service request failed or timed out; check the service before repeating a submission."
        ) from None
    if response.status_code in (204, 404) and method == "GET":
        return None
    if response.status_code not in (200, 201, 202):
        raise ModuleError(f"The service returned HTTP {response.status_code}.")
    try:
        return response.json()
    except ValueError:
        raise ModuleError("The service returned invalid JSON.") from None


def _object(event, attribute, name):
    obj = MISPObject(name)
    obj.add_reference(attribute["uuid"], "describes")
    event.add_object(obj)
    return obj


def _annotation(event, attribute, title, data):
    obj = _object(event, attribute, "annotation")
    obj.comment = title
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True), to_ids=False, disable_correlation=True)
    return obj


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("attribute"), dict):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        attribute = request["attribute"]
        UUID(attribute["uuid"])
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Unsupported attribute type.")
        value = _normalise(attribute["type"], attribute["value"])
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be an object.")
        for key in REQUIRED:
            if not isinstance(config.get(key), str) or not config[key].strip():
                raise ModuleError(f"Missing {key} configuration.")
        limit = _integer(config, "max_results", 25)
        event = MISPEvent()
        event.add_attribute(**attribute)
        _expand(event, attribute, value, config, limit)
        result = json.loads(event.to_json())
        return {"results": {key: result.get(key, []) for key in ("Attribute", "Object")}}
    except ModuleError as exc:
        return {"error": str(exc)}
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        IndexError,
        OSError,
        RuntimeError,
        zipfile.BadZipFile,
        PyMISPError,
    ):
        return {"error": "Invalid request or service response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)


moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Censys Enrichment APIs",
    "description": (
        "Retrieve Censys host enrichment, web properties on ports 80 and 443, or certificate metadata. Configure a"
        " platform API token and organization ID. Host service results are bounded; the annotation retains provider"
        " fields including scores and labels when present. Web property and certificate requests may consume standard"
        " credits under the account plan."
    ),
    "module-type": ["expansion"],
    "data-source": "external",
    "logo": "",
    "requirements": ["requests", "pymisp"],
    "features": (
        "Retrieve Censys host enrichment, web properties on ports 80 and 443, or certificate metadata. Configure a"
        " platform API token and organization ID. Host service results are bounded; the annotation retains provider"
        " fields including scores and labels when present. Web property and certificate requests may consume standard"
        " credits under the account plan."
    ),
    "references": ["https://docs.censys.com/reference/v3-globaldata-asset-host-enrichment"],
    "input": "ip-src, ip-dst, domain, hostname, x509-fingerprint-sha256",
    "output": "MISP objects linked to the original attribute.",
}
mispattributes = {
    "input": ["ip-src", "ip-dst", "domain", "hostname", "x509-fingerprint-sha256"],
    "format": "misp_standard",
}
moduleconfig = ["api_token", "organization_id", "max_results"]
REQUIRED = ["api_token", "organization_id"]


def _expand(event, attribute, value, config, limit):
    headers = {"Authorization": "Bearer " + config["api_token"], "Accept": "application/json"}
    params = {"organization_id": config["organization_id"]}
    root = "https://api.platform.censys.io/v3/global/asset/"
    kind = attribute["type"]
    if kind in ("ip-src", "ip-dst"):
        paths = ["enrichment/host/" + _segment(value)]
    elif kind == "x509-fingerprint-sha256":
        paths = ["certificate/" + value]
    else:
        paths = ["webproperty/" + _segment(value + ":" + str(port)) for port in (80, 443)]
    for path in paths:
        data = _call("GET", root + path, headers=headers, params=params)
        if data is None:
            continue
        resource = data["result"]["resource"]
        if not isinstance(resource, dict):
            raise ModuleError("Censys returned an invalid resource.")
        _annotation(event, attribute, moduleinfo["name"], resource)
        if kind in ("ip-src", "ip-dst"):
            for service in resource.get("services", [])[:limit]:
                obj = _object(event, attribute, "network-connection")
                obj.add_attribute("ip-dst", value=value, to_ids=False)
                if service.get("port") is not None:
                    obj.add_attribute("dst-port", value=int(service["port"]), to_ids=False)
                if service.get("transport_protocol"):
                    obj.add_attribute("layer4-protocol", value=service["transport_protocol"], to_ids=False)
            if len(resource.get("services", [])) > limit:
                _annotation(event, attribute, "Result limit", {"truncated": True, "max_results": limit})
        elif kind == "x509-fingerprint-sha256":
            obj = _object(event, attribute, "x509")
            obj.add_attribute("x509-fingerprint-sha256", value=value, to_ids=False)
            for key, relation in [("issuer_dn", "issuer"), ("subject_dn", "subject")]:
                if resource.get("parsed", {}).get(key):
                    obj.add_attribute(relation, value=resource["parsed"][key], to_ids=False)
