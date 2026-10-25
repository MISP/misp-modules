import json
import re
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha1", "sha256"], "format": "misp_standard"}
moduleconfig = ["apikey", "url", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "VMRay Analyzer Lookup",
    "description": "Retrieve existing VMRay sample and analysis context by file hash.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Set url to the HTTPS VMRay server URL and apikey to its API key. Queries /rest/sample/{hash-type}/{hash},"
        " followed by /rest/analysis/sample/{sample_id}. Returns sample hashes, names, classifications, threat names,"
        " score, analysis status and report links. max_results defaults to 25 (1-100) for samples and analyses;"
        " continuation pages are reported as truncated. This lookup does not submit samples or wait for pending"
        " analyses. For full artifact import, use the VMRay import module."
    ),
    "references": ["https://www.vmray.com/"],
    "input": "md5, sha1, sha256 MISP attribute.",
    "output": "File objects, report links and referenced analysis annotations.",
}
TIMEOUT = 30


class ModuleError(ValueError):
    """An actionable module error safe to return to the caller."""


def _get(url, **kwargs):
    try:
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=False, **kwargs)
    except requests.RequestException:
        raise ModuleError("The service request failed or timed out.") from None
    if response.status_code == 404:
        return None
    if response.status_code == 204:
        return None
    if response.status_code != 200:
        raise ModuleError(f"The service returned HTTP {response.status_code}.")
    try:
        return response.json()
    except ValueError:
        raise ModuleError("The service returned invalid JSON.") from None


def _hash(kind, value):
    if not isinstance(value, str) or not re.fullmatch(
        "[0-9a-fA-F]{%d}" % {"md5": 32, "sha1": 40, "sha256": 64}[kind], value
    ):
        raise ModuleError(f"Invalid {kind} hash.")
    return value.lower()


def _limit(config, key="max_results", default=25, maximum=100):
    raw = config.get(key)
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool) or not str(raw).isdigit() or (not 1 <= int(raw) <= maximum):
        raise ModuleError(f"{key} must be an integer between 1 and {maximum}.")
    return int(raw)


def _annotation(event, attribute, title, data):
    obj = MISPObject("annotation")
    obj.comment = title
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True, indent=2), to_ids=False, disable_correlation=True)
    obj.add_reference(attribute["uuid"], "describes")
    event.add_object(obj)


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
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        for key in ["apikey", "url"]:
            if not isinstance(config.get(key), str) or not config[key].strip():
                raise ModuleError(f"Missing {key} configuration.")
        event = MISPEvent()
        event.add_attribute(**attribute)
        return _expand(event, attribute, config)
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, OverflowError, OSError):
        return {"error": "Invalid request or service response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)


def _expand(event, attribute, config):
    value = _hash(attribute["type"], attribute["value"].strip())
    limit = _limit(config)
    parsed = urlsplit(config["url"].strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ModuleError("url must be an HTTPS server URL without credentials, a query or a fragment.")
    base = config["url"].strip().rstrip("/")
    headers = {"Authorization": "api_key " + config["apikey"]}
    data = _get(f"{base}/rest/sample/{attribute['type']}/{value}", headers=headers)
    if data is None:
        return _results(event)
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise ModuleError("VMRay returned an unexpected sample response.")
    for sample in data["data"][:limit]:
        if not isinstance(sample, dict) or not str(sample.get("sample_id", "")).isdigit():
            raise ModuleError("VMRay returned an invalid sample.")
        sample_id = sample["sample_id"]
        if _hash(attribute["type"], sample.get("sample_" + attribute["type"] + "hash", "")) != value:
            raise ModuleError("VMRay returned a different sample hash.")
        obj = MISPObject("file")
        obj.comment = "VMRay sample"
        for kind in ("md5", "sha1", "sha256"):
            digest = sample.get("sample_" + kind + "hash")
            if digest:
                obj.add_attribute(kind, value=_hash(kind, digest), to_ids=False)
        if sample.get("sample_filename"):
            obj.add_attribute("filename", value=sample["sample_filename"], to_ids=False)
        obj.add_reference(attribute["uuid"], "related-to")
        event.add_object(obj)
        _annotation(
            event,
            attribute,
            "VMRay sample context",
            {
                key: sample[key]
                for key in ("sample_id", "sample_score", "sample_classifications", "sample_threat_names")
                if key in sample
            },
        )
        if isinstance(sample.get("sample_webif_url"), str) and urlsplit(sample["sample_webif_url"]).scheme in (
            "http",
            "https",
        ):
            event.add_attribute("link", sample["sample_webif_url"], to_ids=False, comment="VMRay sample report")
        analyses = _get(f"{base}/rest/analysis/sample/{sample_id}", headers=headers)
        if analyses is not None:
            if not isinstance(analyses, dict) or not isinstance(analyses.get("data"), list):
                raise ModuleError("VMRay returned an unexpected analysis response.")
            for analysis in analyses["data"][:limit]:
                if not isinstance(analysis, dict):
                    raise ModuleError("VMRay returned an invalid analysis record.")
                _annotation(event, attribute, "VMRay analysis", analysis)
            if analyses.get("continuation_id") or len(analyses["data"]) > limit:
                _annotation(
                    event, attribute, "VMRay result limit", {"sample_id": sample_id, "analyses_truncated": True}
                )
    if data.get("continuation_id") or len(data["data"]) > limit:
        _annotation(event, attribute, "VMRay result limit", {"samples_truncated": True})
    return _results(event)
