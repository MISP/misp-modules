"""Publish MISP indicators through Falcon's custom IOC API."""

import ipaddress
import json
import os
import re
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from falconpy import IOC

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "CrowdStrike IOC Publish",
    "description": "Create and renew module-owned Falcon custom IOCs from MISP event and object attributes.",
    "module-type": ["action"],
    "logo": "crowdstrike.png",
    "requirements": ["crowdstrike-falconpy", "Falcon IOC Management Read/Write API scopes"],
    "features": (
        "Publishes to_ids MD5, SHA-256, domain and IP attributes, including attributes in objects. Requires explicit"
        " host-group or global scope. Existing IOCs are updated only when both their source and module ownership tag"
        " match; foreign IOCs are left unchanged. Credentials come from server-side CROWDSTRIKE_CLIENT_ID and"
        " CROWDSTRIKE_CLIENT_SECRET environment variables. Supports expiration, dry runs and per-indicator outcomes."
        " See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/crowdstrike_ioc_publish.md)."
    ),
    "references": ["https://www.falconpy.io/Service-Collections/IOC.html"],
    "input": "MISP events in standard, bare or legacy format, supplied in workflow data.",
    "output": "Publishing summary and per-indicator outcomes; an error signals incomplete publication.",
}
moduleconfig = {
    "params": {
        "region": {"type": "string", "description": "Falcon region: us1, us2 or eu1", "value": "us1"},
        "source": {
            "type": "string",
            "description": "Stable ownership namespace, unique to this MISP publisher",
            "value": "misp-modules",
        },
        "action": {
            "type": "string",
            "description": "detect or prevent (prevent is restricted to file hashes)",
            "value": "detect",
        },
        "severity": {
            "type": "string",
            "description": "INFORMATIONAL, LOW, MEDIUM, HIGH or CRITICAL",
            "value": "MEDIUM",
        },
        "platforms": {
            "type": "string",
            "description": "Comma-separated windows, mac and/or linux",
            "value": "windows,mac,linux",
        },
        "host_groups": {
            "type": "string",
            "description": "Comma-separated Falcon host-group IDs (32 hexadecimal characters)",
        },
        "apply_globally": {
            "type": "string",
            "description": "true applies across the tenant; otherwise host_groups is required",
            "value": "false",
        },
        "expiration_days": {
            "type": "string",
            "description": "Days from this publication until expiration (1-365)",
            "value": "30",
        },
        "dry_run": {
            "type": "string",
            "description": "true returns planned payloads without authenticating or publishing",
            "value": "false",
        },
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"
REGIONS = {
    "us1": "https://api.crowdstrike.com",
    "us2": "https://api.us-2.crowdstrike.com",
    "eu1": "https://api.eu-1.crowdstrike.com",
}
OWNER_TAG = "misp-ioc-publish"
MAX_INDICATORS = 100
MAX_DOMAIN_LENGTH = 200  # Falcon custom IOC limit, applied after IDNA normalization.
DEADLINE_SECONDS = 240
HASH_LENGTHS = {"md5": 32, "sha256": 64}
SUPPORTED_TYPES = {
    "md5",
    "sha256",
    "domain",
    "hostname",
    "ip-src",
    "ip-dst",
    "domain|ip",
    "filename|md5",
    "filename|sha256",
    "malware-sample",
}


class PublishError(Exception):
    """An API failure with a deliberately sanitized message."""


def _boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError(f"{name} must be true, false, 1 or 0.")


def _list(value, name):
    if isinstance(value, str):
        value = [item.strip() for item in value.split(",") if item.strip()]
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{name} must be a comma-separated string or list of strings.")
    return sorted(set(value))


def _default(params, key, default):
    value = params.get(key)
    return default if value is None or value == "" else value


def _settings(params):
    if not isinstance(params, dict):
        raise ValueError("params must be an object.")
    region = _default(params, "region", "us1")
    if not isinstance(region, str) or region not in REGIONS:
        raise ValueError("region must be us1, us2 or eu1.")
    source = _default(params, "source", "misp-modules")
    if not isinstance(source, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9 ._:/-]{0,63}", source):
        raise ValueError("source must be 1-64 ASCII letters, digits, spaces or ._:/- and start with a letter or digit.")
    action = _default(params, "action", "detect")
    if action not in ("detect", "prevent"):
        raise ValueError("action must be detect or prevent.")
    severity = _default(params, "severity", "MEDIUM")
    if not isinstance(severity, str) or severity.upper() not in ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError("Invalid severity.")
    platforms = _list(_default(params, "platforms", "windows,mac,linux"), "platforms")
    if not platforms or set(platforms) - {"windows", "mac", "linux"}:
        raise ValueError("platforms must contain windows, mac and/or linux.")
    groups = _list(_default(params, "host_groups", []), "host_groups")
    if any(not re.fullmatch(r"[0-9a-fA-F]{32}", group) for group in groups):
        raise ValueError("host_groups must contain 32-character hexadecimal Falcon group IDs.")
    globally = _boolean(params.get("apply_globally"), "apply_globally")
    if globally == bool(groups):
        raise ValueError("Choose either non-empty host_groups or apply_globally=true, not both.")
    days = params.get("expiration_days")
    if days is None or days == "":
        days = 30
    if isinstance(days, bool) or not re.fullmatch(r"[0-9]{1,3}", str(days)) or not 1 <= int(days) <= 365:
        raise ValueError("expiration_days must be an integer from 1 to 365.")
    return {
        "region": region,
        "source": source,
        "action": action,
        "severity": severity.upper(),
        "platforms": platforms,
        "host_groups": groups,
        "applied_globally": globally,
        "expiration": (
            (datetime.now(timezone.utc) + timedelta(days=int(days)))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        ),
        "dry_run": _boolean(params.get("dry_run"), "dry_run"),
    }


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _atomic(kind, value):
    if kind in HASH_LENGTHS:
        if not re.fullmatch(rf"[0-9a-fA-F]{{{HASH_LENGTHS[kind]}}}", value):
            raise ValueError("Invalid file hash.")
        return kind, value.lower()
    if kind in ("ip-src", "ip-dst"):
        if "%" in value:
            raise ValueError("Scoped IP addresses are unsupported.")
        address = ipaddress.ip_address(value)
        return f"ipv{address.version}", str(address)
    domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(domain) > MAX_DOMAIN_LENGTH or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")
    ):
        raise ValueError("Invalid domain.")
    return "domain", domain


def _indicators(kind, value):
    if "|" not in kind and kind != "malware-sample":
        return [_atomic(kind, value)]
    first, separator, second = value.rpartition("|")
    if not separator or not first.strip() or not second.strip():
        raise ValueError("Invalid composite attribute.")
    if kind == "domain|ip":
        return [_atomic("domain", first), _atomic("ip-dst", second)]
    return [_atomic("md5" if kind == "malware-sample" else kind.split("|")[1], second)]


def _collect(data, skipped):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(event, dict) for event in data):
        raise ValueError("data must contain a MISP event or list of events.")
    indicators = {}
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if _boolean(event.get("deleted"), "deleted"):
            continue
        collections = dict(event, **envelope)
        attributes = [(attribute, {}) for attribute in _records(collections, "Attribute")]
        for obj in _records(collections, "Object"):
            if not _boolean(obj.get("deleted"), "deleted"):
                attributes.extend((attribute, obj) for attribute in _records(obj, "Attribute"))
        for attribute, obj in attributes:
            if _boolean(attribute.get("deleted"), "deleted") or not _boolean(attribute.get("to_ids"), "to_ids"):
                skipped["deleted or non-IDS"] += 1
                continue
            kind, value = attribute.get("type"), attribute.get("value")
            if not isinstance(kind, str) or kind not in SUPPORTED_TYPES:
                skipped["unsupported"] += 1
                continue
            try:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("Empty value.")
                atoms = _indicators(kind, value)
            except ValueError:
                skipped["malformed"] += 1
                continue
            source = {
                "event": str(event.get("uuid") or event.get("id") or "unknown"),
                "attribute": str(attribute.get("uuid") or attribute.get("id") or "unknown"),
                "misp_type": kind,
            }
            if obj:
                source["object"] = str(obj.get("uuid") or obj.get("id") or obj.get("name") or "unknown")
            for key in atoms:
                sources = indicators.setdefault(key, [])
                if source not in sources:
                    sources.append(source)
                if len(indicators) > MAX_INDICATORS:
                    raise ValueError(
                        f"At most {MAX_INDICATORS} unique indicators may be published per invocation; split the input."
                    )
    return indicators


def _response(response, operation):
    if not isinstance(response, dict):
        raise PublishError(f"{operation}: invalid Falcon response.")
    status = response.get("status_code")
    body = response.get("body")
    if not isinstance(status, int) or not 200 <= status < 300:
        code = str(status) if isinstance(status, int) else "unknown"
        raise PublishError(f"{operation}: Falcon HTTP {code}.")
    if not isinstance(body, dict) or body.get("errors") or body.get("warnings"):
        raise PublishError(f"{operation}: Falcon returned errors, warnings or an invalid body.")
    resources = body.get("resources")
    if not isinstance(resources, list):
        raise PublishError(f"{operation}: missing Falcon resources.")
    return resources


def _publish(client, item, source, deadline):
    kind, value = item["type"], item["value"]
    response = client.indicator_combined_v1(filter=f"type:'{kind}'+value:'{value}'", limit=2, from_parent=False)
    resources = _response(response, "lookup")
    total = response["body"].get("meta", {}).get("pagination", {}).get("total", len(resources))
    if len(resources) > 1 or not isinstance(total, int) or total > len(resources):
        raise PublishError("lookup: ambiguous or incomplete matches; no IOC changed.")
    if time.monotonic() >= deadline:
        raise PublishError("publication time budget exceeded after lookup; no IOC changed.")
    if resources:
        existing = resources[0]
        if not isinstance(existing, dict) or existing.get("type") != kind or existing.get("value") != value:
            raise PublishError("lookup: unexpected indicator identity; no IOC changed.")
        tags = existing.get("tags", [])
        if (
            existing.get("from_parent")
            or existing.get("source") != source
            or not isinstance(tags, list)
            or OWNER_TAG not in tags
        ):
            raise PublishError("ownership conflict: existing IOC is not owned by this publisher.")
        identifier = existing.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise PublishError("lookup: existing IOC has no ID; no IOC changed.")
        update = {key: value for key, value in item.items() if key not in ("type", "value")}
        update.update(id=identifier, tags=sorted({tag for tag in tags if isinstance(tag, str)} | {OWNER_TAG}))
        result = client.indicator_update_v1(
            body={"comment": "MISP IOC renewal", "indicators": [update]}, ignore_warnings=False, retrodetects=False
        )
        status = "updated"
    else:
        result = client.indicator_create_v1(
            body={"comment": "MISP IOC publication", "indicators": [item]}, ignore_warnings=False, retrodetects=False
        )
        status = "created"
    acknowledged = _response(result, "write")
    if (
        len(acknowledged) != 1
        or not isinstance(acknowledged[0], dict)
        or not isinstance(acknowledged[0].get("id"), str)
        or not acknowledged[0]["id"]
    ):
        raise PublishError("write: no unambiguous acknowledgement; remote outcome may be unknown.")
    if resources and acknowledged[0]["id"] != identifier:
        raise PublishError("write: unexpected acknowledgement ID; remote outcome may be unknown.")
    return status, acknowledged[0]["id"]


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        if "filteredItems" in request or "matchingData" in request:
            raise ValueError(
                "This action does not support workflow filters or extracted data; supply selected events in data."
            )
        settings = _settings(request.get("params", {}))
        skipped = Counter()
        indicators = _collect(request.get("data"), skipped)
        if settings["action"] == "prevent" and any(kind not in HASH_LENGTHS for kind, _ in indicators):
            raise ValueError("prevent supports MD5 and SHA-256 only; use detect for domain/IP indicators.")
    except (ValueError, TypeError) as exc:
        return {"error": f"CrowdStrike IOC publish: {exc}"}
    summary = {
        "success": True,
        "dry_run": settings["dry_run"],
        "created": 0,
        "updated": 0,
        "failed": 0,
        "planned": 0,
        "skipped": dict(skipped),
        "items": [],
    }
    response = {"result_key": "crowdstrike_ioc_publish", "data": summary}
    if not indicators:
        return response
    if not settings["dry_run"]:
        client_id, client_secret = os.getenv("CROWDSTRIKE_CLIENT_ID"), os.getenv("CROWDSTRIKE_CLIENT_SECRET")
        if not client_id or not client_secret:
            return {
                "error": (
                    "CrowdStrike IOC publish: CROWDSTRIKE_CLIENT_ID and CROWDSTRIKE_CLIENT_SECRET must be configured on"
                    " the module server."
                )
            }
        try:
            client = IOC(
                client_id=client_id,
                client_secret=client_secret,
                base_url=REGIONS[settings["region"]],
                timeout=15,
                ssl_verify=True,
            )
        except Exception:
            return {"error": "CrowdStrike IOC publish: unable to initialize Falcon client."}
    deadline = time.monotonic() + DEADLINE_SECONDS
    for (kind, value), sources in indicators.items():
        item = {
            key: settings[key]
            for key in ("source", "action", "severity", "platforms", "host_groups", "applied_globally", "expiration")
        }
        item.update(
            type=kind,
            value=value,
            tags=[OWNER_TAG],
            description=("MISP sources: " + "; ".join(f"{ref['event']}/{ref['attribute']}" for ref in sources))[:500],
        )
        outcome = {"type": kind, "value": value, "sources": sources}
        if settings["dry_run"]:
            outcome.update(status="planned", payload=item)
            summary["planned"] += 1
        else:
            try:
                if time.monotonic() >= deadline:
                    raise PublishError("publication time budget exceeded; indicator not attempted.")
                status, identifier = _publish(client, item, settings["source"], deadline)
                outcome.update(status=status, id=identifier)
                summary[status] += 1
            except PublishError as exc:
                outcome.update(status="failed", error=str(exc))
                summary["failed"] += 1
            except Exception:
                outcome.update(
                    status="failed",
                    error="Falcon request failed; remote outcome may be unknown. Check Falcon before retrying.",
                )
                summary["failed"] += 1
        summary["items"].append(outcome)
    if summary["failed"]:
        summary["success"] = False
        response["error"] = (
            f"CrowdStrike IOC publish: {summary['failed']} indicator(s) failed; {summary['created']} created and"
            f" {summary['updated']} updated. Publication may be partial."
        )
    return response


def introspection():
    return {"config": moduleconfig}


def version():
    return dict(moduleinfo, config=moduleconfig)
