"""Add MISP indicators to an explicitly selected QRadar reference set and domain."""

import json
import os
import re
import time
from urllib.parse import urlsplit

import requests

from misp_modules.lib.qradar_reference_set import ENTRY_TYPES, boolean, collect, indicator_type

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "QRadar Reference Set Publish",
    "description": "Publish typed MISP indicators to an existing QRadar reference set and explicit domain.",
    "module-type": ["action"],
    "logo": "",
    "requirements": ["requests", "QRadar API 20.0 and an authorized service token with reference-data access"],
    "features": (
        "Adds or refreshes IDS-marked event and object indicators through reference_data_collections/set_entries."
        " Requires an existing reference-set ID and explicit domain ID, validates the target entry type and checks"
        " each write acknowledgement. Supports credential-free dry runs and reports partial failures. Set expiry"
        " remains controlled by QRadar. Credentials come from the module server environment. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/qradar_reference_set_publish.md)."
    ),
    "references": [
        "https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--reference_data_collections-set_entries-POST.html",
        "https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--reference_data_collections-sets-id-GET.html",
    ],
    "input": "Selected MISP events and object attributes in workflow data.",
    "output": "Counts and per-value created, updated, planned or failed outcomes with MISP provenance.",
}
moduleconfig = {
    "params": {
        "reference_set_id": {"type": "string", "description": "Required: existing QRadar reference-set numeric ID"},
        "domain_id": {
            "type": "string",
            "description": "Required: numeric domain ID (0 is Default Domain), or SHARED",
        },
        "indicator_type": {
            "type": "string",
            "description": "ipv4, ipv6, domain, url, md5, sha1, sha256 or sha512",
            "value": "ipv4",
        },
        "source": {"type": "string", "description": "QRadar entry source label", "value": "misp-modules"},
        "dry_run": {
            "type": "string",
            "description": "true previews entry payloads without network access",
            "value": "false",
        },
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"
API_PATH = "/api/reference_data_collections"
API_VERSION = "20.0"
MAX_VALUES = 100
DEADLINE_SECONDS = 240


class PublishError(Exception):
    """A sanitized error suitable for a workflow result."""


def _identifier(value, name, minimum):
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not re.fullmatch(r"[0-9]{1,19}", str(value)):
        raise ValueError(f"{name} must be an explicit integer ID.")
    number = int(value)
    if not minimum <= number <= 9223372036854775807:
        raise ValueError(f"{name} is outside its supported range.")
    return number


def _settings(params):
    if not isinstance(params, dict):
        raise ValueError("params must be an object.")
    source = params.get("source")
    if source is None or source == "":
        source = "misp-modules"
    if not isinstance(source, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9 ._:/-]{0,63}", source):
        raise ValueError("source must be 1-64 ASCII letters, digits, spaces or ._:/- and start with a letter or digit.")
    return {
        "collection_id": _identifier(params.get("reference_set_id"), "reference_set_id", 1),
        "domain_id": (
            None if params.get("domain_id") == "SHARED" else _identifier(params.get("domain_id"), "domain_id", 0)
        ),
        "indicator_type": indicator_type(params.get("indicator_type")),
        "source": source,
        "dry_run": boolean(params.get("dry_run"), "dry_run"),
    }


def _connection():
    origin = os.getenv("QRADAR_URL", "")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or any(ord(char) <= 32 or ord(char) == 127 for char in origin)
    ):
        raise ValueError("Invalid QRADAR_URL.")
    parsed.port
    token = os.getenv("QRADAR_API_TOKEN", "")
    if not token or any(not 33 <= ord(char) <= 126 for char in token):
        raise ValueError("Invalid QRADAR_API_TOKEN.")
    ca_bundle = os.getenv("QRADAR_CA_BUNDLE") or True
    return origin.rstrip("/") + API_PATH, token, ca_bundle


def _request(session, method, endpoint, verify, **kwargs):
    try:
        response = session.request(method, endpoint, timeout=15, verify=verify, allow_redirects=False, **kwargs)
    except (requests.RequestException, OSError):
        raise PublishError(f"{method} failed; remote outcome may be unknown. Check QRadar before retrying.") from None
    expected = (200,) if method == "GET" else (200, 201)
    if response.status_code not in expected:
        raise PublishError(f"{method}: QRadar HTTP {response.status_code}; remote outcome may be unknown.")
    try:
        body = response.json()
    except ValueError:
        raise PublishError(f"{method}: invalid JSON acknowledgement; remote outcome may be unknown.") from None
    if not isinstance(body, dict) or body.get("errors") or body.get("warnings") or body.get("http_response"):
        raise PublishError(f"{method}: invalid response or API error; remote outcome may be unknown.")
    return response.status_code, body


def _check_target(session, endpoint, verify, settings):
    _, target = _request(session, "GET", f"{endpoint}/sets/{settings['collection_id']}", verify)
    if type(target.get("id")) is not int or target["id"] != settings["collection_id"]:
        raise PublishError("Reference-set identity could not be confirmed; no values submitted.")
    if (
        not isinstance(target.get("entry_type"), str)
        or target["entry_type"] not in ENTRY_TYPES[settings["indicator_type"]]
    ):
        allowed = ", ".join(sorted(ENTRY_TYPES[settings["indicator_type"]]))
        raise PublishError(f"Reference-set entry_type must be {allowed} for this indicator type; no values submitted.")
    return target


def _publish(session, endpoint, verify, payload):
    status, record = _request(session, "POST", f"{endpoint}/set_entries", verify, json=payload)
    if (
        type(record.get("id")) is not int
        or record["id"] <= 0
        or type(record.get("collection_id")) is not int
        or (payload["domain_id"] is not None and type(record.get("domain_id")) is not int)
        or any(key not in record or record[key] != value for key, value in payload.items())
        or record.get("delete_entry") not in (None, False)
    ):
        raise PublishError("POST: no matching set/domain/value acknowledgement; remote outcome may be unknown.")
    return "created" if status == 201 else "updated", record["id"]


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        if "filteredItems" in request or "matchingData" in request:
            raise ValueError("Workflow filters/extracted data are unsupported; supply selected events in data.")
        settings = _settings(request.get("params", {}))
        values, skipped = collect(request.get("data"), settings["indicator_type"], limit=MAX_VALUES)
    except (ValueError, TypeError) as exc:
        return {"error": f"QRadar reference set publish: {exc}"}
    summary = {
        "success": True,
        **settings,
        "created": 0,
        "updated": 0,
        "planned": 0,
        "failed": 0,
        "skipped": skipped,
        "items": [],
    }
    result = {"result_key": "qradar_reference_set_publish", "data": summary}
    if not values:
        return result
    deadline = time.monotonic() + DEADLINE_SECONDS
    session = None
    try:
        if not settings["dry_run"]:
            try:
                endpoint, token, verify = _connection()
            except ValueError:
                return {
                    "error": (
                        "Configure QRADAR_URL as an HTTPS console origin and QRADAR_API_TOKEN on the module server."
                    )
                }
            session = requests.Session()
            session.headers.update({"SEC": token, "Version": API_VERSION, "Accept": "application/json"})
            try:
                target = _check_target(session, endpoint, verify, settings)
            except PublishError as exc:
                summary["success"] = False
                result["error"] = f"QRadar reference set publish: {exc}"
                return result
            summary["reference_set_name"] = target.get("name")
        for value, refs in values.items():
            payload = {
                "collection_id": settings["collection_id"],
                "domain_id": settings["domain_id"],
                "source": settings["source"],
                "value": value,
            }
            outcome = {"value": value, "sources": refs}
            if settings["dry_run"]:
                outcome.update(status="planned", payload=payload)
                summary["planned"] += 1
            else:
                try:
                    if time.monotonic() >= deadline:
                        raise PublishError("Publication time budget exceeded; value not attempted.")
                    status, identifier = _publish(session, endpoint, verify, payload)
                    outcome.update(status=status, id=identifier)
                    summary[status] += 1
                except PublishError as exc:
                    outcome.update(status="failed", error=str(exc))
                    summary["failed"] += 1
                except Exception:
                    outcome.update(
                        status="failed",
                        error="QRadar request failed; remote outcome may be unknown. Check QRadar before retrying.",
                    )
                    summary["failed"] += 1
            summary["items"].append(outcome)
    finally:
        if session is not None:
            session.close()
    if summary["failed"]:
        summary["success"] = False
        result["error"] = (
            f"QRadar reference set publish: {summary['failed']} failed; {summary['created']} created and"
            f" {summary['updated']} updated. Publication may be partial."
        )
    return result


def introspection():
    return {"config": moduleconfig}


def version():
    return dict(moduleinfo, config=moduleconfig)
