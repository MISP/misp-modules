import json
import re

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["sha256"], "format": "misp_standard"}
moduleconfig = ["apikey", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "UnpacMe Lookup",
    "description": "Find existing UnpacMe unpacking results for a SHA-256 hash.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Queries /api/v1/private/search/hash using Key authentication. max_results defaults to 25 (1-100). Each"
        " matching submission becomes a referenced annotation with its status, submission ID and timestamps. Unpacked"
        " child hashes become file objects linked to the original hash. Does not upload or download samples or wait for"
        " incomplete jobs. Result truncation is explicitly reported."
    ),
    "references": ["https://api.unpac.me/"],
    "input": "sha256 MISP attribute.",
    "output": "Submission annotations and unpacked-child file objects.",
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
        for key in ["apikey"]:
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
    value = _hash("sha256", attribute["value"].strip())
    limit = _limit(config)
    data = _get(
        "https://api.unpac.me/api/v1/private/search/hash/" + value, headers={"Authorization": "Key " + config["apikey"]}
    )
    if data is None:
        return _results(event)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ModuleError("UnpacMe returned an unexpected response.")
    seen = set()
    for row in data["results"][:limit]:
        if not isinstance(row, dict) or _hash("sha256", row.get("sha256", "")) != value:
            raise ModuleError("UnpacMe returned an unexpected sample.")
        context = {key: row[key] for key in ("id", "submission_id", "sha256", "status", "created") if key in row}
        children = row.get("children", 0)
        if children is None:
            children = 0
        if isinstance(children, list):
            hashes = children
            context["children"] = len(children)
        elif isinstance(children, int) and not isinstance(children, bool) and children >= 0:
            context["children"] = children
            hashes = []
            if children:
                submission_id = row.get("id") or row.get("submission_id")
                if not isinstance(submission_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", submission_id):
                    raise ModuleError("UnpacMe returned an invalid submission ID.")
                report = _get(
                    "https://api.unpac.me/api/v1/private/results/" + submission_id,
                    headers={"Authorization": "Key " + config["apikey"]},
                )
                context["results_available"] = report is not None
                if report is not None:
                    if not isinstance(report, dict) or _hash("sha256", report.get("sha256", "")) != value:
                        raise ModuleError("UnpacMe returned results for a different sample.")
                    if report.get("id") is not None and report["id"] != submission_id:
                        raise ModuleError("UnpacMe returned results for a different submission.")
                    results = report.get("results")
                    if isinstance(results, list):
                        for result in results:
                            if not isinstance(result, dict):
                                raise ModuleError("UnpacMe returned an invalid unpacked result.")
                            child_hashes = result.get("hashes", {})
                            if not isinstance(child_hashes, dict):
                                raise ModuleError("UnpacMe returned invalid result hashes.")
                            hashes.append(child_hashes.get("sha256") or result.get("sha256"))
                    elif not isinstance(results, dict):
                        raise ModuleError("UnpacMe returned an invalid result collection.")
        else:
            raise ModuleError("UnpacMe returned an invalid unpacked child count.")
        _annotation(event, attribute, "UnpacMe submission", context)
        candidates = []
        for child in hashes:
            digest = _hash("sha256", child)
            if digest == value or digest in seen:
                continue
            seen.add(digest)
            candidates.append(digest)
        for digest in candidates[:limit]:
            obj = MISPObject("file")
            obj.comment = "UnpacMe unpacked child"
            obj.add_attribute("sha256", value=digest, to_ids=False)
            obj.add_reference(attribute["uuid"], "derived-from")
            event.add_object(obj)
        if len(candidates) > limit:
            _annotation(
                event,
                attribute,
                "UnpacMe result limit",
                {"returned_children": limit, "total_children": len(candidates)},
            )
    if len(data["results"]) > limit:
        _annotation(
            event,
            attribute,
            "UnpacMe result limit",
            {"returned_submissions": limit, "total_submissions": len(data["results"])},
        )
    return _results(event)
