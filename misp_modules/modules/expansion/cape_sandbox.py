import base64
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


def _enabled(config, key, default=False):
    value = config.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if str(value).lower() not in ("true", "false", "1", "0"):
        raise ModuleError(f"{key} must be true or false.")
    return str(value).lower() in ("true", "1")


def _url(value):
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ModuleError("Invalid HTTPS URL.")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ModuleError("An HTTPS URL without credentials or fragment is required.")
    parsed.port
    return value.rstrip("/")


def _origin(config):
    value = _url(config.get("api_url", ""))
    if urlsplit(value).query:
        raise ModuleError("api_url cannot contain a query string.")
    return value


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


def _pivot(event, attribute, kind, value):
    value = _normalise(kind, value)
    if kind == attribute["type"] and value == _normalise(attribute["type"], attribute["value"]):
        return
    obj = _object(
        event, attribute, "file" if kind in ("md5", "sha1", "sha256") else ("url" if kind == "url" else "domain-ip")
    )
    relation = "ip" if kind in ("ip-src", "ip-dst") else kind
    obj.add_attribute(relation, value=value, to_ids=False)


def _sandbox(event, attribute, payload, link=None):
    obj = _object(event, attribute, "sandbox-report")
    obj.add_attribute("sandbox-type", value="on-premise", to_ids=False)
    obj.add_attribute("on-premise-sandbox", value="cape", to_ids=False)
    obj.add_attribute("results", value=json.dumps(payload, sort_keys=True), to_ids=False, disable_correlation=True)
    if link:
        obj.add_attribute("permalink", value=link, to_ids=False)
    return obj


def _binary(attribute, config):
    limit = _integer(config, "max_size_mb", 25, 100) * 1024 * 1024
    encoded = attribute.get("data")
    if not isinstance(encoded, str) or len(encoded) > 2 * limit:
        raise ModuleError("Missing or oversized base64 sample data.")
    content = base64.b64decode(encoded, validate=True)
    filename = attribute["value"]
    if attribute["type"] == "malware-sample":
        filename, separator, digest = filename.rpartition("|")
        if not separator or not re.fullmatch(r"[a-fA-F0-9]{32}", digest):
            raise ModuleError("A malware-sample value must contain filename|md5.")
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = [
                e for e in archive.infolist() if not e.is_dir() and e.filename != digest.lower() + ".filename.txt"
            ]
            if len(entries) != 1 or entries[0].file_size > limit:
                raise ModuleError("A malware-sample archive must contain one payload within max_size_mb.")
            content = archive.read(entries[0], pwd=b"infected")
        if hashlib.md5(content).hexdigest() != digest.lower():
            raise ModuleError("The unpacked sample does not match the declared MD5.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if not filename or not content or len(content) > limit:
        raise ModuleError("The sample is empty or exceeds max_size_mb.")
    return filename, content, hashlib.sha256(content).hexdigest()


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
    "name": "CAPE Sandbox Enrichment",
    "description": (
        "Submit supplied samples to CAPEv2 or retrieve a completed JSON report by numeric task ID. Set api_url to the"
        " API v2 base, for example https://cape.example/apiv2. api_key is optional when the server permits"
        " unauthenticated requests. submit_samples defaults to false. max_size_mb defaults to 25 (1–100). Submission"
        " returns task IDs; use a text attribute containing a task ID for a later report lookup. Completed reports"
        " yield file hashes, network pivots and extracted configurations."
    ),
    "module-type": ["expansion"],
    "data-source": "external",
    "logo": "",
    "requirements": ["requests", "pymisp"],
    "features": (
        "Submit supplied samples to CAPEv2 or retrieve a completed JSON report by numeric task ID. Set api_url to the"
        " API v2 base, for example https://cape.example/apiv2. api_key is optional when the server permits"
        " unauthenticated requests. submit_samples defaults to false. max_size_mb defaults to 25 (1–100). Submission"
        " returns task IDs; use a text attribute containing a task ID for a later report lookup. Completed reports"
        " yield file hashes, network pivots and extracted configurations."
    ),
    "references": ["https://capev2.readthedocs.io/en/latest/usage/api.html"],
    "input": "text, attachment, malware-sample",
    "output": "MISP objects linked to the original attribute.",
}
mispattributes = {"input": ["text", "attachment", "malware-sample"], "format": "misp_standard"}
moduleconfig = ["api_url", "api_key", "submit_samples", "max_size_mb", "max_results"]
REQUIRED = ["api_url"]


def _expand(event, attribute, value, config, limit):
    base = _origin(config)
    headers = {"Authorization": "Token " + config["api_key"]} if config.get("api_key") else {}
    if attribute["type"] in ("attachment", "malware-sample"):
        if not _enabled(config, "submit_samples"):
            raise ModuleError("Set submit_samples=true to submit a sample to CAPE.")
        filename, content, digest = _binary(attribute, config)
        data = _call("POST", base + "/tasks/create/file/", headers=headers, files={"file": (filename, content)})
        if not isinstance(data, dict) or data.get("error") or (not data.get("data", {}).get("task_ids")):
            raise ModuleError("CAPE did not acknowledge a submission; check the service before retrying.")
        _annotation(
            event, attribute, "CAPE submission receipt", {"task_ids": data["data"]["task_ids"], "sha256": digest}
        )
        return
    if not re.fullmatch("[0-9]+", value):
        raise ModuleError("text input must contain a numeric CAPE task ID.")
    data = _call("GET", base + "/tasks/get/report/" + value + "/json/", headers=headers)
    if data is None:
        return
    if not isinstance(data, dict) or data.get("error"):
        raise ModuleError("CAPE report is unavailable or the task is not complete.")
    _sandbox(event, attribute, data)
    file_data = data.get("target", {}).get("file", {})
    for kind in ("md5", "sha1", "sha256"):
        if file_data.get(kind):
            _pivot(event, attribute, kind, file_data[kind])
    network = data.get("network", {})
    for host in network.get("hosts", [])[:limit]:
        _pivot(event, attribute, "ip-dst", host["ip"] if isinstance(host, dict) else host)
    for record in network.get("dns", [])[:limit]:
        if record.get("request"):
            _pivot(event, attribute, "domain", record["request"])
    if data.get("CAPE", {}).get("configs"):
        _annotation(event, attribute, "CAPE extracted configurations", data["CAPE"]["configs"][:limit])
