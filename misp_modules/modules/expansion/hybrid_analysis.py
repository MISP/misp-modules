import base64
import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha1", "sha256", "attachment", "url", "text"], "format": "misp_standard"}
moduleconfig = ["apikey", "environment_id", "max_results", "max_size_mb"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Hybrid Analysis Sandbox",
    "description": "Look up Hybrid Analysis reports or submit a file or URL for sandbox analysis.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Hashes use GET /search/hash; text accepts a report ID (job ID or SHA256:environment-ID) and uses GET"
        " /report/{id}/summary. Files and URLs use POST /submit/file and /submit/url, returning the receipt without"
        " polling or retrying a submission. environment_id defaults to 110. max_results defaults to 25 (1-100);"
        " max_size_mb defaults to 25 (1-100). Reports and receipts become sandbox-report objects with links."
        " Submissions send the supplied content to the service under your account sharing policy."
    ),
    "references": ["https://hybrid-analysis.com/docs/api/v2"],
    "input": "md5, sha1, sha256, attachment, url, text MISP attribute.",
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


def _cap(event, attribute, rows, limit, more=False):
    if len(rows) > limit or more:
        _annotation(
            event, attribute, moduleinfo["name"] + " result limit", {"limit": limit, "more_results_available": True}
        )
    return rows[:limit]


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
    obj.add_attribute("sandbox-type", value="web", to_ids=False)
    obj.add_attribute("web-sandbox", value=vendor, to_ids=False)
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
    limit = _limit(config)
    environment = _limit(config, "environment_id", 110, 1000)
    headers = {"api-key": config["apikey"], "Accept": "application/json", "User-Agent": "MISP-modules/HybridAnalysis"}
    base = "https://hybrid-analysis.com/api/v2"
    if kind in HASH_LENGTHS:
        data = _request("GET", base + "/search/hash", params={"hash": value}, headers=headers)
        if data is None:
            return _results(event)
        if not isinstance(data, list) or not all((isinstance(r, dict) for r in data)):
            raise ModuleError("Hybrid Analysis returned an unexpected search response.")
        rows = _cap(event, attribute, data, limit)
    elif kind == "text":
        if not re.fullmatch(r"(?:[0-9a-fA-F]{24}|[0-9a-fA-F]{64}:\d{1,4})", value):
            raise ModuleError("Text must contain a Hybrid Analysis job ID or SHA256:environment-ID report identifier.")
        data = _request("GET", base + "/report/" + value + "/summary", headers=headers)
        rows = [] if data is None else [data]
    elif kind == "url":
        data = _request(
            "POST", base + "/submit/url", data={"url": value, "environment_id": environment}, headers=headers
        )
        rows = [] if data is None else [data]
    else:
        filename, content = _binary(attribute, config)
        data = _request(
            "POST",
            base + "/submit/file",
            files={"file": (filename, content)},
            data={"environment_id": environment},
            headers=headers,
        )
        rows = [] if data is None else [data]
    if kind in ("url", "attachment") and (not rows):
        raise ModuleError("Hybrid Analysis did not return a submission receipt.")
    if kind in ("url", "attachment") and (not isinstance(rows[0], dict) or not rows[0].get("job_id")):
        raise ModuleError("Hybrid Analysis did not return a job identifier.")
    for row in rows:
        if not isinstance(row, dict):
            raise ModuleError("Hybrid Analysis returned an invalid report.")
        if kind in HASH_LENGTHS and row.get(kind) and (_hash(kind, row[kind]) != value):
            raise ModuleError("Hybrid Analysis returned a different file hash.")
        digest = row.get("sha256")
        link = "https://hybrid-analysis.com/sample/" + _hash("sha256", digest) if digest else None
        _sandbox(event, attribute, row, "hybrid-analysis", link)
    return _results(event)
