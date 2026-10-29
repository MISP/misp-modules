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
    obj.add_attribute("sandbox-type", value="saas", to_ids=False)
    obj.add_attribute("saas-sandbox", value="hatching-triage", to_ids=False)
    obj.add_attribute("results", value=json.dumps(payload, sort_keys=True), to_ids=False, disable_correlation=True)
    if link:
        obj.add_attribute("permalink", value=link, to_ids=False)
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
    "name": "Triage Report Enrichment",
    "description": (
        "Retrieve Triage overview reports by trusted report link or search existing analyses by file hash. api_url"
        " defaults to https://tria.ge/api; configure https://private.tria.ge/api for private accounts. Overview reports"
        " preserve verdicts, signatures, extracted configuration and available analysis metadata. This module performs"
        " lookups only. It does not submit samples or poll unfinished tasks."
    ),
    "module-type": ["expansion"],
    "data-source": "external",
    "logo": "",
    "requirements": ["requests", "pymisp"],
    "features": (
        "Retrieve Triage overview reports by trusted report link or search existing analyses by file hash. api_url"
        " defaults to https://tria.ge/api; configure https://private.tria.ge/api for private accounts. Overview reports"
        " preserve verdicts, signatures, extracted configuration and available analysis metadata. This module performs"
        " lookups only. It does not submit samples or poll unfinished tasks."
    ),
    "references": ["https://tria.ge/docs/"],
    "input": "link, md5, sha1, sha256",
    "output": "MISP objects linked to the original attribute.",
}
mispattributes = {"input": ["link", "md5", "sha1", "sha256"], "format": "misp_standard"}
moduleconfig = ["api_key", "api_url", "max_results"]
REQUIRED = ["api_key"]


def _expand(event, attribute, value, config, limit):
    base = _origin(config) if config.get("api_url") else "https://tria.ge/api"
    headers = {"Authorization": "Bearer " + config["api_key"]}
    web = base.removesuffix("/api")
    if attribute["type"] == "link":
        parsed = urlsplit(_url(value))
        if parsed.netloc != urlsplit(web).netloc or not re.fullmatch("/[a-zA-Z0-9-]+/?", parsed.path) or parsed.query:
            raise ModuleError("A report link on the configured Triage server is required.")
        ids = [parsed.path.strip("/")]
    else:
        data = _call(
            "GET",
            base + "/v0/search",
            headers=headers,
            params={"query": attribute["type"] + ":" + value, "limit": limit},
        )
        if data is None:
            return
        ids = [row["id"] for row in data.get("data", [])[:limit]]
        if data.get("next"):
            _annotation(event, attribute, "Search limit", {"more_results_available": True, "max_results": limit})
    for sample_id in ids:
        if not re.fullmatch("[a-zA-Z0-9-]+", sample_id):
            raise ModuleError("Triage returned an invalid sample ID.")
        data = _call("GET", base + "/v1/samples/" + sample_id + "/overview.json", headers=headers)
        if data is None:
            continue
        _sandbox(event, attribute, data, web + "/" + sample_id)
        for target in data.get("targets", [])[:limit]:
            for kind in ("md5", "sha1", "sha256"):
                if target.get(kind):
                    _pivot(event, attribute, kind, target[kind])
        for row in data.get("extracted", [])[:limit]:
            _annotation(event, attribute, "Triage extracted configuration", row)
