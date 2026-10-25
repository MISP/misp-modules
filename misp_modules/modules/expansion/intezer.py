import base64
import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import urlsplit
from uuid import UUID

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha1", "sha256", "attachment", "text"], "format": "misp_standard"}
moduleconfig = ["apikey", "max_size_mb"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Intezer Sandbox",
    "description": "Retrieve Intezer Analyze file reports or submit an attachment for analysis.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Exchanges the API key through POST /get-access-token, then authenticates with a Bearer token. Hashes retrieve"
        " an existing report via GET /files/{hash}; text accepts an analysis UUID for GET /analyses/{id}. Attachments"
        " use POST /analyze once and return the receipt, without polling. max_size_mb defaults to 25 (1-100). Report"
        " status, verdict, family and privacy remain in sandbox-report objects. Attachment submissions send content to"
        " your Intezer account."
    ),
    "references": ["https://intezer-python-sdk.readthedocs.io/"],
    "input": "md5, sha1, sha256, attachment, text MISP attribute.",
    "output": "Referenced enrichment objects and pivotable attributes.",
}
TIMEOUT = 30
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


class ModuleError(ValueError):
    """An actionable error that contains no request credentials."""


def _request(method, url, response_format="json", missing_statuses=(404, 204), **kwargs):
    try:
        response = requests.request(method, url, timeout=TIMEOUT, allow_redirects=False, verify=True, **kwargs)
    except requests.RequestException:
        raise ModuleError("The service request failed or timed out.") from None
    if response.status_code in missing_statuses:
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


def _sandbox(event, attribute, data, vendor, permalink=None):
    if not isinstance(data, dict):
        raise ModuleError("The sandbox returned an unexpected report.")
    obj = MISPObject("sandbox-report", strict=True)
    obj.add_attribute("sandbox-type", value="saas", to_ids=False)
    obj.add_attribute("saas-sandbox", value=vendor, to_ids=False)
    obj.add_attribute("raw-report", value=json.dumps(data, sort_keys=True), to_ids=False, disable_correlation=True)
    if permalink:
        obj.add_attribute("permalink", value=permalink, to_ids=False)
    if data.get("threat_score") is not None:
        obj.add_attribute("score", value=str(data["threat_score"]), to_ids=False)
    obj.add_reference(attribute["uuid"], "related-to")
    event.add_object(obj)
    _file(event, attribute, data)


def _expand(event, attribute, config):
    value = _value(attribute)
    kind = attribute["type"]
    base = "https://analyze.intezer.com/api/v2-0"
    if kind == "text":
        analysis_id = str(UUID(value))
    elif kind == "attachment":
        filename, content = _binary(attribute, config)
    token = _request("POST", base + "/get-access-token", json={"api_key": config["apikey"]})
    if not isinstance(token, dict) or not isinstance(token.get("result"), str) or (not token["result"]):
        raise ModuleError("Intezer did not return an access token.")
    headers = {"Authorization": "Bearer " + token["result"], "Accept": "application/json"}
    if kind in HASH_LENGTHS:
        data = _request("GET", base + "/files/" + value, headers=headers)
    elif kind == "text":
        data = _request("GET", base + "/analyses/" + analysis_id, headers=headers, missing_statuses=(404, 204, 410))
    else:
        data = _request("POST", base + "/analyze", files={"file": (filename, content)}, headers=headers)
    if data is None:
        if kind == "attachment":
            raise ModuleError("Intezer did not return a submission receipt.")
        return _results(event)
    if not isinstance(data, dict):
        raise ModuleError("Intezer returned an unexpected response.")
    report = data.get("result", {})
    if not isinstance(report, dict):
        raise ModuleError("Intezer returned an invalid analysis report.")
    if kind in HASH_LENGTHS and report.get(kind) and (_hash(kind, report[kind]) != value):
        raise ModuleError("Intezer returned a different file hash.")
    analysis_id = report.get("analysis_id")
    if data.get("result_url"):
        path = data["result_url"]
        if not isinstance(path, str) or not re.fullmatch("/analyses/[0-9a-fA-F-]{36}", path):
            raise ModuleError("Intezer returned an invalid analysis path.")
        analysis_id = str(UUID(path.rsplit("/", 1)[-1]))
    if kind == "attachment" and (not analysis_id):
        raise ModuleError("Intezer did not return an analysis identifier.")
    link = "https://analyze.intezer.com/analyses/" + str(UUID(analysis_id)) if analysis_id else None
    _sandbox(event, attribute, data, "Intezer Analyze", link)
    _file(event, attribute, dict(report, filename=report.get("file_name") or report.get("filename")))
    return _results(event)
