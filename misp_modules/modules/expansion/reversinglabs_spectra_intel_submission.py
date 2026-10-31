import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha1", "sha256", "url", "attachment"], "format": "misp_standard"}
moduleconfig = ["username", "password", "url", "platform", "mode", "max_size_mb"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "ReversingLabs Spectra Intelligence Submission",
    "description": "Submit a file hash, URL or attachment to ReversingLabs Spectra Intelligence dynamic analysis.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "url defaults to https://data.reversinglabs.com; platform defaults to windows10. Uses Basic authentication."
        " mode=submit (default) submits an existing cloud sample by hash or a URL; attachments are uploaded to"
        " /api/spex/upload/{sha1} before detonation. max_size_mb defaults to 25 (1-100). mode=report retrieves the"
        " latest completed report by hash or URL. The returned analysis receipt can be pending; no polling or retries"
        " create duplicate submissions. Submission may consume service credits."
    ),
    "references": ["https://docs.reversinglabs.com/SpectraIntelligence/API/"],
    "input": "md5, sha1, sha256, url, attachment MISP attribute.",
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


def _binary(attribute, config):
    maximum = _limit(config, "max_size_mb", 25, 100) * 1024 * 1024
    encoded = attribute.get("data")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((maximum + 2) // 3):
        raise ModuleError("The attachment needs base64 data within max_size_mb.")
    try:
        content = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise ModuleError("Invalid base64 attachment data.") from None
    if not content or len(content) > maximum:
        raise ModuleError("The attachment is empty or exceeds max_size_mb.")
    filename = attribute["value"].replace("\\", "/").rsplit("/", 1)[-1]
    if not filename or any((ord(c) < 32 for c in filename)):
        raise ModuleError("Invalid attachment filename.")
    return (filename, content)


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
        for key in ["username", "password"]:
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
    base = _base(config, "https://data.reversinglabs.com")
    auth = (config["username"], config["password"])
    mode = config.get("mode") or "submit"
    if mode not in ("submit", "report"):
        raise ModuleError("mode must be submit or report.")
    platform = config.get("platform") or "windows10"
    if platform not in ("windows7", "windows10", "windows11", "macos11", "linux", "android12"):
        raise ModuleError("Unsupported dynamic analysis platform.")
    kind = attribute["type"]
    if kind == "attachment":
        if mode != "submit":
            raise ModuleError("Report mode requires a hash or URL attribute.")
        filename, content = _binary(attribute, config)
        value, kind = (hashlib.sha1(content).hexdigest(), "sha1")
        uploaded = _request(
            "POST",
            base + "/api/spex/upload/" + value,
            response_format="bytes",
            auth=auth,
            headers={"Content-Type": "application/octet-stream"},
            data=content,
        )
        if uploaded is None:
            raise ModuleError("ReversingLabs returned no upload acknowledgement.")
        metadata = ET.Element("rl")
        properties = ET.SubElement(metadata, "properties")
        prop = ET.SubElement(properties, "property")
        ET.SubElement(prop, "name").text = "filename"
        ET.SubElement(prop, "value").text = filename
        ET.SubElement(metadata, "domain").text = ""
        acknowledged = _request(
            "POST",
            base + "/api/spex/upload/" + value + "/meta",
            response_format="bytes",
            auth=auth,
            headers={"Content-Type": "application/octet-stream"},
            data=ET.tostring(metadata, encoding="utf-8"),
        )
        if acknowledged is None:
            raise ModuleError("ReversingLabs returned no sample metadata acknowledgement.")
        _file(event, attribute, {"sha1": value, "sha256": hashlib.sha256(content).hexdigest(), "filename": filename})
    else:
        value = _value(attribute)
    if mode == "report":
        if kind == "url":
            identifier = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
            path = "/api/dynamic/analysis/report/v1/query/url/base64/" + identifier
        else:
            path = f"/api/dynamic/analysis/report/v1/query/{kind}/{value}"
        data = _request("GET", base + path + "/latest", params={"format": "json"}, auth=auth)
        if data is None:
            return _results(event)
    else:
        payload = {"rl": {"platform": platform, "response_format": "json", kind: value}}
        data = _request("POST", base + "/api/dynamic/analysis/analyze/v1/query/json", json=payload, auth=auth)
        if data is None:
            raise ModuleError("ReversingLabs returned no analysis submission acknowledgement.")
    if not isinstance(data, dict) or not isinstance(data.get("rl"), dict) or (not data["rl"]):
        raise ModuleError("ReversingLabs returned an unexpected analysis response.")
    context = data["rl"]
    if context.get("error") or context.get("errors"):
        raise ModuleError("ReversingLabs rejected the analysis request.")
    if mode == "submit" and (not context.get("analysis_id")):
        raise ModuleError("ReversingLabs returned no analysis identifier.")
    if mode == "report" and (not isinstance(context.get("report"), dict)):
        raise ModuleError("ReversingLabs returned no completed analysis report.")
    if context.get(kind) and kind in HASH_LENGTHS and (_hash(kind, context[kind]) != value):
        raise ModuleError("ReversingLabs returned a different sample hash.")
    _annotation(event, attribute, "ReversingLabs dynamic analysis " + mode, context)
    return _results(event)
