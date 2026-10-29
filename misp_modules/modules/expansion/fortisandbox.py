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


def _sandbox(event, attribute, payload, link=None):
    obj = _object(event, attribute, "sandbox-report")
    obj.add_attribute("sandbox-type", value=moduleinfo["name"], to_ids=False)
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
    filename = attribute["value"].split("|", 1)[0].replace("\\", "/").rsplit("/", 1)[-1]
    if attribute["type"] == "malware-sample":
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = [entry for entry in archive.infolist() if not entry.is_dir()]
            if len(entries) != 1 or entries[0].file_size > limit:
                raise ModuleError("A malware-sample archive must contain one file within max_size_mb.")
            content = archive.read(entries[0], pwd=b"infected")
    if not filename or not content or len(content) > limit:
        raise ModuleError("The sample is empty or exceeds max_size_mb.")
    return (filename, content, hashlib.sha256(content).hexdigest())


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
    "name": "FortiSandbox Enrichment",
    "description": (
        "Authenticate to a FortiSandbox appliance and retrieve an existing rating by MD5, SHA-1 or SHA-256. Set api_url"
        " to the appliance HTTPS origin, without /jsonrpc. For supplied files, calculate SHA-256 and look up the rating"
        " first. submit_samples defaults to false; true permits submission when the rating is unknown. max_size_mb"
        " defaults to 25 (1–100). A submission receipt is returned without polling. Provider ratings remain in their"
        " original vocabulary."
    ),
    "module-type": ["expansion"],
    "data-source": "external",
    "logo": "",
    "requirements": ["requests", "pymisp"],
    "features": (
        "Authenticate to a FortiSandbox appliance and retrieve an existing rating by MD5, SHA-1 or SHA-256. Set api_url"
        " to the appliance HTTPS origin, without /jsonrpc. For supplied files, calculate SHA-256 and look up the rating"
        " first. submit_samples defaults to false; true permits submission when the rating is unknown. max_size_mb"
        " defaults to 25 (1–100). A submission receipt is returned without polling. Provider ratings remain in their"
        " original vocabulary."
    ),
    "references": ["https://www.fortinet.com/products/sandbox/fortisandbox"],
    "input": "md5, sha1, sha256, attachment, malware-sample",
    "output": "MISP objects linked to the original attribute.",
}
mispattributes = {"input": ["md5", "sha1", "sha256", "attachment", "malware-sample"], "format": "misp_standard"}
moduleconfig = ["api_url", "username", "password", "submit_samples", "max_size_mb", "max_results"]
REQUIRED = ["api_url", "username", "password"]


def _rpc(base, method, path, session=None, **params):
    body = {"method": method, "params": [{"url": path, **params}], "id": 1, "ver": "2.1"}
    if session:
        body["session"] = session
    data = _call("POST", base + "/jsonrpc", json=body)
    if not isinstance(data, dict):
        raise ModuleError("FortiSandbox returned invalid JSON-RPC data.")
    result = data.get("result", {})
    if isinstance(result, list):
        result = result[0] if result else {}
    if not isinstance(result, dict) or result.get("status", {}).get("code", 0) != 0:
        raise ModuleError("FortiSandbox rejected the JSON-RPC operation.")
    return (data, result)


def _expand(event, attribute, value, config, limit):
    base = _origin(config)
    if urlsplit(base).path not in ("", "/"):
        raise ModuleError("api_url must be a FortiSandbox HTTPS origin without a path.")
    login, _ = _rpc(base, "exec", "/sys/login/user", data=[{"user": config["username"], "passwd": config["password"]}])
    session = login.get("session")
    if not isinstance(session, str) or not session:
        raise ModuleError("FortiSandbox authentication failed.")
    try:
        kind = attribute["type"]
        sample = None
        if kind in ("attachment", "malware-sample"):
            sample = _binary(attribute, config)
            kind, value = ("sha256", sample[2])
        _, report = _rpc(base, "get", "/scan/result/filerating", session, checksum=value, ctype=kind)
        payload = report.get("data", report)
        if isinstance(payload, list):
            payload = payload[0] if payload else {}
        rating = payload.get("rating") if isinstance(payload, dict) else None
        if rating is not None and str(rating).lower() not in ("unknown", ""):
            _sandbox(event, attribute, payload)
        elif sample and _enabled(config, "submit_samples"):
            _, receipt = _rpc(
                base,
                "set",
                "/alert/ondemand/submit-file",
                session,
                type="file",
                filename=sample[0],
                file=base64.b64encode(sample[1]).decode(),
            )
            _annotation(event, attribute, "FortiSandbox submission receipt", receipt)
        else:
            _annotation(event, attribute, "FortiSandbox lookup", {"hash": value, "rating": "unknown"})
    finally:
        try:
            _rpc(base, "exec", "/sys/logout", session)
        except ModuleError:
            pass
