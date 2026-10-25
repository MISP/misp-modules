import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from functools import partial
from io import BytesIO
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha256", "attachment"], "format": "misp_standard"}
moduleconfig = ["apikey", "url", "max_size_mb", "ca_bundle"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Palo Alto WildFire",
    "description": "Retrieve WildFire verdicts and XML reports, or submit an attachment for analysis.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "url defaults to https://wildfire.paloaltonetworks.com/publicapi and can select a regional cloud or appliance."
        " Hashes query get/verdict and get/report; unknown (-102) and pending (-100) verdicts remain distinct from"
        " benign verdicts. Attachment inputs submit raw base64-decoded bytes to submit/file and return the sample hash"
        " for a subsequent lookup. max_size_mb defaults to 25 (1-100). No polling or automatic resubmission is"
        " performed."
    ),
    "references": ["https://docs.paloaltonetworks.com/wildfire/u-v/wildfire-api"],
    "input": "md5, sha256, attachment MISP attribute.",
    "output": "Referenced enrichment objects and pivotable attributes.",
}
TIMEOUT = 30
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


class ModuleError(ValueError):
    """An actionable error that contains no request credentials."""


def _request(method, url, response_format="json", ca_bundle=None, **kwargs):
    trust = True
    if ca_bundle is not None and ca_bundle != "":
        if not isinstance(ca_bundle, str) or not Path(ca_bundle).is_file():
            raise ModuleError("ca_bundle must be the path to an existing CA bundle file.")
        trust = ca_bundle
    try:
        response = requests.request(method, url, timeout=TIMEOUT, allow_redirects=False, verify=trust, **kwargs)
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
    request = partial(_request, ca_bundle=config.get("ca_bundle"))
    base = _base(config, "https://wildfire.paloaltonetworks.com/publicapi")
    if attribute["type"] == "attachment":
        filename, content = _binary(attribute, config)
        data = request(
            "POST",
            base + "/submit/file",
            response_format="xml",
            data={"apikey": config["apikey"]},
            files={"file": (filename, content)},
        )
        if data is None:
            raise ModuleError("WildFire returned no submission acknowledgement.")
        digest = _hash("sha256", data.findtext(".//sha256", ""))
        if digest != hashlib.sha256(content).hexdigest():
            raise ModuleError("WildFire returned a different submitted sample hash.")
        _file(event, attribute, {"sha256": digest, "filename": filename})
        _annotation(event, attribute, "WildFire submission", {"sha256": digest, "status": "submitted"})
        return _results(event)
    value = _value(attribute)
    data = request(
        "POST", base + "/get/verdict", response_format="xml", data={"apikey": config["apikey"], "hash": value}
    )
    if data is None:
        return _results(event)
    code = int(data.findtext(".//verdict", ""))
    meanings = {
        -102: "unknown",
        -100: "pending",
        0: "benign",
        1: "malware",
        2: "grayware",
        4: "phishing",
        5: "command-and-control",
    }
    if code not in meanings:
        raise ModuleError("WildFire returned an unknown verdict code.")
    _annotation(event, attribute, "WildFire verdict", {"code": code, "verdict": meanings[code]})
    if code < 0:
        return _results(event)
    report = request(
        "POST",
        base + "/get/report",
        response_format="xml",
        data={"apikey": config["apikey"], "hash": value, "format": "xml"},
    )
    if report is not None:
        info = report.find(".//file_info")
        if info is None:
            raise ModuleError("WildFire returned a report without file information.")
        details = {child.tag: child.text for child in info if child.text is not None}
        if details.get(attribute["type"]) and _hash(attribute["type"], details[attribute["type"]]) != value:
            raise ModuleError("WildFire returned a different sample hash.")
        _file(event, attribute, details)
        obj = MISPObject("annotation")
        obj.comment = "WildFire XML report"
        obj.add_attribute("text", value=json.dumps(details, sort_keys=True), to_ids=False, disable_correlation=True)
        obj.add_attribute("attachment", value=value + "-wildfire.xml", data=BytesIO(ET.tostring(report)), to_ids=False)
        obj.add_reference(attribute["uuid"], "describes")
        event.add_object(obj)
    return _results(event)
