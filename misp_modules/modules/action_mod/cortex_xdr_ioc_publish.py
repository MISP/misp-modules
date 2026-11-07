"""Publish IDS-marked MISP observables as Cortex XDR IOC rules."""

import json
import os
import re
import time
from collections import Counter
from uuid import UUID

from misp_modules.lib import cortex_xdr as xdr

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Cortex XDR IOC Publish",
    "description": "Upload missing Cortex XDR IOC rules from IDS-marked MISP event and object attributes.",
    "module-type": ["action"],
    "logo": "",
    "requirements": ["Cortex XDR Pro and API credentials with IOC lookup and upload permissions on the module server."],
    "features": (
        "Publishes MD5/SHA-256, domain and IP indicators through indicators/insert_jsons with validation."
        " Skips observed existing rules, supports Standard/Advanced API keys and defaults to a credential-free dry"
        " run. Explicit expiry and per-indicator outcomes are reported. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/cortex_xdr_ioc_publish.md."
    ),
    "references": [
        xdr.AUTH_REFERENCE,
        xdr.IOC_REFERENCE,
        "https://cortex-docs.paloaltonetworks.com/xdr-api/cortex-platform/indicator-rules",
    ],
    "input": "Selected MISP events in workflow data; only non-deleted IDS-marked supported attributes are eligible.",
    "output": "Publication summary and per-indicator outcomes; an error signals incomplete or uncertain publication.",
}
moduleconfig = {
    "params": {
        "source": {
            "type": "string",
            "description": "Stable publisher label included in the IOC comment",
            "value": "misp-modules",
        },
        "severity": {"type": "string", "description": "INFO, LOW, MEDIUM, HIGH or CRITICAL", "value": "MEDIUM"},
        "reputation": {"type": "string", "description": "SUSPICIOUS or BAD", "value": "SUSPICIOUS"},
        "expiration_days": {
            "type": "string",
            "description": "Explicit IOC lifetime: 7, 30, 90 or 180 days",
            "value": "30",
        },
        "dry_run": {
            "type": "string",
            "description": "true previews payloads without any network requests; false publishes",
            "value": "true",
        },
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"
MAX_INDICATORS = 50
DEADLINE_SECONDS = 120


def _default(params, key, default):
    value = params.get(key)
    return default if value is None or value == "" else value


def _settings(params):
    if not isinstance(params, dict) or set(params) - set(moduleconfig["params"]):
        raise xdr.XdrError("Unsupported publication parameters; connection settings belong on the module server.")
    source = _default(params, "source", "misp-modules")
    if not isinstance(source, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,63}", source):
        raise xdr.XdrError("source must be a 1-64 character ASCII publisher label.")
    severity, reputation = _default(params, "severity", "MEDIUM"), _default(params, "reputation", "SUSPICIOUS")
    if severity not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") or reputation not in ("SUSPICIOUS", "BAD"):
        raise xdr.XdrError("Invalid publication severity or reputation.")
    days = xdr.integer(params.get("expiration_days"), "expiration_days", 30, 180)
    if days not in (7, 30, 90, 180):
        raise xdr.XdrError("expiration_days must be 7, 30, 90 or 180.")
    return {
        "source": source,
        "severity": severity,
        "reputation": reputation,
        "expiration_days": days,
        "dry_run": xdr.boolean(_default(params, "dry_run", True), "dry_run"),
    }


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise xdr.XdrError(f"{key} must be a list of objects.")
    return records


def _uuid(value):
    if value is None:
        return None
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise xdr.XdrError("Invalid MISP provenance UUID.") from None


def _collect(data):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(envelope, dict) for envelope in data):
        raise xdr.XdrError("data must contain selected MISP events.")
    values, skipped = {}, Counter()
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise xdr.XdrError("Event must be an object.")
        if xdr.boolean(event.get("deleted"), "deleted"):
            skipped["deleted_container"] += 1
            continue
        collections = dict(event, **envelope)
        attributes = [(attribute, {}) for attribute in _records(collections, "Attribute")]
        for obj in _records(collections, "Object"):
            if xdr.boolean(obj.get("deleted"), "deleted"):
                skipped["deleted_container"] += 1
            else:
                attributes.extend((attribute, obj) for attribute in _records(obj, "Attribute"))
        for attribute, obj in attributes:
            if xdr.boolean(attribute.get("deleted"), "deleted") or not xdr.boolean(attribute.get("to_ids"), "to_ids"):
                skipped["deleted_or_non_ids"] += 1
                continue
            if attribute.get("type") not in xdr.INPUT_TYPES:
                skipped["unsupported"] += 1
                continue
            try:
                key = xdr.indicator(attribute["type"], attribute.get("value"))
                ref = {"attribute_uuid": _uuid(attribute.get("uuid"))}
                if ref["attribute_uuid"] is None:
                    raise xdr.XdrError("A source UUID is required.")
                for name, value in (("event_uuid", event.get("uuid")), ("object_uuid", obj.get("uuid"))):
                    if value is not None:
                        ref[name] = _uuid(value)
            except (ValueError, TypeError):
                skipped["malformed"] += 1
                continue
            refs = values.setdefault(key, [])
            if ref not in refs:
                refs.append(ref)
            if len(values) > MAX_INDICATORS:
                raise xdr.XdrError(f"At most {MAX_INDICATORS} unique indicators may be published per invocation.")
    return dict(sorted(values.items())), dict(skipped)


def _connection():
    return {
        "url": os.getenv("CORTEX_XDR_URL"),
        "api_key": os.getenv("CORTEX_XDR_API_KEY"),
        "api_key_id": os.getenv("CORTEX_XDR_API_KEY_ID"),
        "auth_type": os.getenv("CORTEX_XDR_AUTH_TYPE", "advanced"),
    }


def _payload(kind, value, refs, settings, expiry):
    uuids = ",".join(sorted({ref["attribute_uuid"] for ref in refs}))
    return {
        "indicator": value,
        "type": kind.upper(),
        "severity": settings["severity"],
        "reputation": settings["reputation"],
        "expiration_date": expiry,
        "comment": (settings["source"] + "; MISP attribute UUIDs: " + uuids)[:500],
    }


def _upload(client, payload):
    body = client.post("insert_jsons", {"request_data": [payload], "validate": True})
    reply = body.get("reply")
    if not isinstance(reply, dict) or reply.get("success") is not True:
        raise xdr.XdrError("Cortex XDR did not confirm this IOC upload; remote outcome may be unknown.")
    errors = reply.get("validation_errors", [])
    if not isinstance(errors, list) or errors:
        raise xdr.XdrError("Cortex XDR reported IOC validation errors; check the tenant before retrying.")


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise xdr.XdrError("A JSON object is required.")
        if "filteredItems" in request or "matchingData" in request:
            raise xdr.XdrError("Workflow filters are unsupported; supply selected events in data.")
        settings = _settings(request.get("params", {}))
        values, skipped = _collect(request.get("data"))
    except xdr.XdrError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError):
        return {"error": "Invalid Cortex XDR publication request."}
    summary = {
        "success": True,
        **settings,
        "uploaded": 0,
        "existing": 0,
        "planned": 0,
        "failed": 0,
        "not_attempted": 0,
        "skipped": skipped,
        "items": [],
    }
    result = {"result_key": "cortex_xdr_ioc_publish", "data": summary}
    if not values:
        return result
    expiry = int((time.time() + settings["expiration_days"] * 86400) * 1000)
    deadline = time.monotonic() + DEADLINE_SECONDS
    client, failed = None, False
    try:
        if not settings["dry_run"]:
            client = xdr.Client(_connection())
        for (kind, value), refs in values.items():
            item = {"type": kind, "value": value, "sources": refs}
            payload = _payload(kind, value, refs, settings, expiry)
            if failed or time.monotonic() >= deadline:
                item["status"] = "not_attempted"
                summary["not_attempted"] += 1
                summary["success"] = False
            elif settings["dry_run"]:
                item.update(status="planned", payload=payload)
                summary["planned"] += 1
            else:
                try:
                    rows, _, _ = client.lookup(kind, value, limit=2)
                    if rows:
                        item.update(
                            status="existing",
                            rule_ids=[row["rule_id"] for row in rows],
                            rules=[xdr.metadata(row) for row in rows],
                        )
                        summary["existing"] += 1
                    elif time.monotonic() >= deadline:
                        item.update(
                            status="not_attempted",
                            error="Publication deadline reached after lookup; no upload attempted.",
                        )
                        summary["not_attempted"] += 1
                        summary["success"], failed = False, True
                    else:
                        _upload(client, payload)
                        item["status"] = "uploaded"
                        summary["uploaded"] += 1
                except (xdr.XdrError, ValueError, TypeError, KeyError) as exc:
                    item.update(
                        status="failed",
                        error=(
                            str(exc)
                            if isinstance(exc, xdr.XdrError)
                            else "Cortex XDR lookup/upload failed; check tenant state before retrying."
                        ),
                    )
                    summary["failed"] += 1
                    summary["success"], failed = False, True
            summary["items"].append(item)
    except (xdr.XdrError, ValueError, TypeError):
        summary["success"] = False
        summary["not_attempted"] = len(values)
        result["error"] = (
            "Configure CORTEX_XDR_URL, CORTEX_XDR_API_KEY, CORTEX_XDR_API_KEY_ID and CORTEX_XDR_AUTH_TYPE on the module"
            " server."
        )
        return result
    finally:
        if client is not None:
            client.session.close()
    if not summary["success"]:
        result["error"] = "Cortex XDR publication is incomplete or uncertain; inspect the per-indicator outcomes."
    return result


def introspection():
    return {}


def version():
    return dict(moduleinfo, config=moduleconfig)
