import json
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["sha256", "text"], "format": "misp_standard"}
moduleconfig = ["apikey", "community", "mode", "provider", "vm"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "PolySwarm Sandbox",
    "description": "Retrieve PolySwarm sandbox tasks or submit an existing PolySwarm sample for sandbox analysis.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "mode defaults to lookup: SHA-256 inputs retrieve the latest sandbox task; text inputs retrieve a task by ID."
        " provider defaults to triage. mode=submit submits a SHA-256 already present in PolySwarm using its scan"
        " instance ID and requires provider and vm. community defaults to default. Task status, report and provenance"
        " are returned without polling. Submission can consume service credits; no file is downloaded or uploaded."
    ),
    "references": ["https://docs.polyswarm.io/"],
    "input": "sha256, text MISP attribute.",
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


def _poly(data):
    if (
        not isinstance(data, dict)
        or data.get("errors")
        or str(data.get("status", "OK")).lower() not in ("ok", "success", "200")
    ):
        raise ModuleError("PolySwarm returned an unexpected response or rejected the request.")
    if "result" in data:
        return data["result"]
    if "results" in data:
        return data["results"]
    raise ModuleError("PolySwarm returned a response without results.")


def _expand(event, attribute, config):
    value = _value(attribute)
    mode = config.get("mode") or "lookup"
    if mode not in ("lookup", "submit"):
        raise ModuleError("mode must be lookup or submit.")
    community = config.get("community") or "default"
    provider = config.get("provider") or "triage"
    if not isinstance(community, str) or not isinstance(provider, str):
        raise ModuleError("Invalid community or provider configuration.")
    base, headers = ("https://api.polyswarm.network/v3", {"Authorization": config["apikey"]})
    if mode == "submit":
        if (
            attribute["type"] != "sha256"
            or not isinstance(config.get("vm"), str)
            or (not config["vm"].strip())
            or (not config.get("provider"))
        ):
            raise ModuleError("Submission requires a SHA-256 attribute, provider and vm.")
        data = _request(
            "GET", base + "/search/hash/sha256", params={"hash": value, "community": community}, headers=headers
        )
        if data is None:
            raise ModuleError("The sample must already exist in PolySwarm before sandbox submission.")
        rows = _poly(data)
        if not isinstance(rows, list) or not rows or (not isinstance(rows[0], dict)):
            raise ModuleError("The sample must already exist in PolySwarm before sandbox submission.")
        row = rows[0]
        if _hash("sha256", row.get("sha256", "")) != value or not row.get("id"):
            raise ModuleError("PolySwarm returned an invalid sample artifact.")
        data = _request(
            "POST",
            base + "/sandbox/sandboxtask",
            headers=headers,
            json={
                "artifact_id": row["id"],
                "provider_slug": provider,
                "vm_slug": config["vm"],
                "network_enabled": 1,
                "community": community,
            },
        )
        if data is None:
            raise ModuleError("PolySwarm returned no sandbox submission acknowledgement.")
    else:
        if attribute["type"] == "sha256":
            path, params = (
                "/sandbox/sandboxtask/latest",
                {"sha256": value, "sandbox": provider, "community": community},
            )
        else:
            if not re.fullmatch("[A-Za-z0-9-]{1,128}", value):
                raise ModuleError("Invalid sandbox task ID.")
            path, params = ("/sandbox/sandboxtask", {"sandbox_task_id": value, "community": community})
        data = _request("GET", base + path, params=params, headers=headers)
        if data is None:
            return _results(event)
    task = _poly(data)
    if not isinstance(task, dict) or not task.get("id") or (not isinstance(task.get("status"), str)):
        raise ModuleError("PolySwarm returned an invalid sandbox task.")
    if attribute["type"] == "sha256" and task.get("sha256") and (_hash("sha256", task["sha256"]) != value):
        raise ModuleError("PolySwarm returned a different sandbox sample.")
    _annotation(event, attribute, "PolySwarm sandbox task", task)
    return _results(event)
