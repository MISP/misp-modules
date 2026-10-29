import ipaddress
import json
import re
import zipfile
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


def _enabled(config, key, default=False):
    value = config.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if str(value).lower() not in ("true", "false", "1", "0"):
        raise ModuleError(f"{key} must be true or false.")
    return str(value).lower() in ("true", "1")


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
    "name": "Criminal IP Enrichment",
    "description": (
        "Retrieve IPv4 risk and infrastructure reports, existing domain scan listings, or a completed domain scan by"
        " numeric text ID. Provider JSON retains risk scores, flags and available vulnerability data. submit_unknown"
        " defaults to false; true submits a domain only when its report listing is empty. Submission returns a scan"
        " receipt without polling. Use its scan_id as text input to retrieve the full report."
    ),
    "module-type": ["expansion"],
    "data-source": "external",
    "logo": "",
    "requirements": ["requests", "pymisp"],
    "features": (
        "Retrieve IPv4 risk and infrastructure reports, existing domain scan listings, or a completed domain scan by"
        " numeric text ID. Provider JSON retains risk scores, flags and available vulnerability data. submit_unknown"
        " defaults to false; true submits a domain only when its report listing is empty. Submission returns a scan"
        " receipt without polling. Use its scan_id as text input to retrieve the full report."
    ),
    "references": ["https://www.criminalip.io/developer/api"],
    "input": "ip-src, ip-dst, domain, hostname, text",
    "output": "MISP objects linked to the original attribute.",
}
mispattributes = {"input": ["ip-src", "ip-dst", "domain", "hostname", "text"], "format": "misp_standard"}
moduleconfig = ["api_key", "submit_unknown", "max_results"]
REQUIRED = ["api_key"]


def _response(method, path, config, **kwargs):
    data = _call(method, "https://api.criminalip.io" + path, headers={"x-api-key": config["api_key"]}, **kwargs)
    if data is None:
        return None
    if not isinstance(data, dict) or data.get("status", 200) != 200:
        raise ModuleError("Criminal IP rejected the request.")
    return data


def _expand(event, attribute, value, config, limit):
    kind = attribute["type"]
    if kind in ("ip-src", "ip-dst"):
        if ipaddress.ip_address(value).version != 4:
            raise ModuleError("Criminal IP IP reports require IPv4.")
        data = _response("GET", "/v1/asset/ip/report", config, params={"ip": value})
    elif kind == "text":
        if not re.fullmatch("[0-9]+", value):
            raise ModuleError("text input must contain a domain scan ID.")
        data = _response("GET", "/v2/domain/report/" + value, config)
    else:
        data = _response("GET", "/v1/domain/reports", config, params={"query": value, "offset": 0})
        rows = (data or {}).get("data", {}).get("reports", [])
        if not rows and _enabled(config, "submit_unknown"):
            receipt = _response("POST", "/v1/domain/scan", config, files={"query": (None, value)})
            if not (receipt or {}).get("data", {}).get("scan_id"):
                raise ModuleError("Criminal IP did not return a scan receipt; check the service before retrying.")
            _annotation(event, attribute, "Domain scan submitted", receipt)
            return
        if rows:
            scan_id = str(rows[0]["scan_id"])
            if not re.fullmatch(r"[0-9]+", scan_id):
                raise ModuleError("Criminal IP returned an invalid scan ID.")
            data = _response("GET", "/v2/domain/report/" + scan_id, config)
    if data and (kind in ("ip-src", "ip-dst") or data.get("data")):
        _annotation(event, attribute, moduleinfo["name"], data)
        if kind in ("ip-src", "ip-dst"):
            for row in data.get("port", {}).get("data", [])[:limit]:
                port = row.get("open_port_no")
                if port is not None:
                    obj = _object(event, attribute, "network-connection")
                    obj.add_attribute("ip-dst", value=value, to_ids=False)
                    obj.add_attribute("dst-port", value=int(port), to_ids=False)
