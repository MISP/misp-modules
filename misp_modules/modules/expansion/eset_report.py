import hashlib
import io
import ipaddress
import json
import re
import zipfile
from urllib.parse import urlsplit
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


def _url(value):
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ModuleError("Invalid HTTPS URL.")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ModuleError("An HTTPS URL without credentials or fragment is required.")
    parsed.port
    return value.rstrip("/")


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


def _object(event, attribute, name):
    obj = MISPObject(name)
    obj.add_reference(attribute["uuid"], "describes")
    event.add_object(obj)
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
    "name": "ESET Threat Intelligence Report",
    "description": (
        "Download an ESET ETI PDF from a supported report download link and return a file object with its content and"
        " SHA-256. Only HTTPS report paths on eti.eset.com, www.eset.com or eset.com are accepted. The complete"
        " generated api_token is forwarded unchanged as the provider Bearer credential. Redirects are rejected to keep"
        " credentials on the selected host. max_size_mb defaults to 25 (1–100); streamed responses are capped before"
        " importing. The report content hash supports duplicate detection when reviewing enrichment results."
    ),
    "module-type": ["expansion"],
    "data-source": "external",
    "logo": "",
    "requirements": ["requests", "pymisp"],
    "features": (
        "Download an ESET ETI PDF from a supported report download link and return a file object with its content and"
        " SHA-256. Only HTTPS report paths on eti.eset.com, www.eset.com or eset.com are accepted. The complete"
        " generated api_token is forwarded unchanged as the provider Bearer credential. Redirects are rejected to keep"
        " credentials on the selected host. max_size_mb defaults to 25 (1–100); streamed responses are capped before"
        " importing. The report content hash supports duplicate detection when reviewing enrichment results."
    ),
    "references": ["https://help.eset.com/eti_portal/en-US/"],
    "input": "link",
    "output": "MISP objects linked to the original attribute.",
}
mispattributes = {"input": ["link"], "format": "misp_standard"}
moduleconfig = ["api_token", "max_size_mb", "max_results"]
REQUIRED = ["api_token"]


def _expand(event, attribute, value, config, limit):
    parsed = urlsplit(_url(value))
    if (
        parsed.hostname not in ("eti.eset.com", "www.eset.com", "eset.com")
        or parsed.port not in (None, 443)
        or parsed.query
    ):
        raise ModuleError("A supported ESET ETI report link is required.")
    match = re.fullmatch("/reports/apt/([a-zA-Z0-9-]+)(?:/download)?", parsed.path)
    if match is None:
        match = re.fullmatch(r"/reports/apt/download/([a-zA-Z0-9-]+)", parsed.path)
    if parsed.hostname == "eti.eset.com" and match is None:
        match = re.fullmatch("/api/v2/apt-reports/([a-zA-Z0-9-]+)/download/pdf", parsed.path)
    if match is None:
        raise ModuleError("A supported ESET ETI APT report link is required.")
    report_id = str(UUID(match.group(1)))
    download = "https://eti.eset.com/api/v2/apt-reports/" + report_id + "/download/pdf"
    max_bytes = _integer(config, "max_size_mb", 25, 100) * 1024 * 1024
    try:
        with requests.get(
            download,
            headers={"Authorization": "Bearer " + config["api_token"]},
            timeout=(5, 30),
            verify=True,
            allow_redirects=False,
            stream=True,
        ) as response:
            if response.status_code != 200:
                raise ModuleError(f"ESET returned HTTP {response.status_code}.")
            content = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                content.extend(chunk)
                if len(content) > max_bytes:
                    raise ModuleError("The report exceeds max_size_mb.")
    except requests.RequestException:
        raise ModuleError("ESET report retrieval failed or timed out.") from None
    if not content.startswith(b"%PDF-"):
        raise ModuleError("ESET did not return a PDF report.")
    digest = hashlib.sha256(content).hexdigest()
    obj = _object(event, attribute, "file")
    obj.add_attribute("filename", value=report_id + ".pdf", to_ids=False)
    obj.add_attribute("sha256", value=digest, to_ids=False)
    obj.add_attribute("attachment", value=report_id + ".pdf", data=io.BytesIO(content), to_ids=False)
