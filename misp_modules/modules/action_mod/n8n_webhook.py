"""Deliver selected MISP event attributes to an authenticated n8n Webhook trigger."""

import hashlib
import json
import os
from collections import Counter
from uuid import UUID

from misp_modules.lib import n8n

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "n8n Webhook",
    "description": "Send selected MISP event attributes to an authenticated n8n Webhook trigger.",
    "module-type": ["action"],
    "logo": "",
    "requirements": ["Published n8n workflow with a POST Webhook trigger using Header authentication."],
    "features": (
        "Delivers one selected MISP event as bounded JSON to a server-configured webhook. Includes a credential-free"
        " dry run, optional IDS-only selection, source UUIDs and a deterministic payload digest. Excludes deleted"
        " data and binary attachments. HTTP delivery does not confirm downstream workflow execution. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/n8n_webhook.md."
    ),
    "references": [n8n.API_REFERENCE, n8n.WEBHOOK_REFERENCE],
    "input": "One selected MISP event with event, object and attribute UUIDs in workflow data.",
    "output": "Preview payload or HTTP delivery status, payload SHA-256 and selected/skipped counts.",
}
moduleconfig = {
    "params": {
        "dry_run": {"type": "string", "description": "true previews; false delivers once to n8n", "value": "true"},
        "to_ids_only": {"type": "string", "description": "Only include IDS attributes when true", "value": "false"},
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"


def _rows(container, key):
    rows = container.get(key, [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise n8n.N8nError(f"{key} must be a list of objects.")
    return rows


def _uuid(value):
    return str(UUID(value))


def _payload(data, ids_only):
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    if not isinstance(data, dict):
        raise n8n.N8nError("Select exactly one MISP event in data.")
    event = data.get("Event", data)
    if not isinstance(event, dict) or n8n.boolean(event.get("deleted"), "deleted"):
        raise n8n.N8nError("A non-deleted MISP event is required.")
    selected = {"uuid": _uuid(event["uuid"]), "Attribute": [], "Object": []}
    if "info" in event:
        if not isinstance(event["info"], str):
            raise n8n.N8nError("Event info must be a string.")
        selected["info"] = event["info"]
    skipped, count = Counter(), 0

    def attributes(container):
        nonlocal count
        output = []
        for attr in _rows(container, "Attribute"):
            if n8n.boolean(attr.get("deleted"), "deleted"):
                skipped["deleted_attribute"] += 1
                continue
            if attr.get("type") in ("attachment", "malware-sample"):
                skipped["binary_attribute"] += 1
                continue
            to_ids = n8n.boolean(attr.get("to_ids"), "to_ids")
            if ids_only and not to_ids:
                skipped["non_ids_attribute"] += 1
                continue
            if (
                not isinstance(attr.get("type"), str)
                or not attr["type"]
                or not isinstance(attr.get("value"), str)
                or not attr["value"]
            ):
                raise n8n.N8nError("Selected attributes require string type/value and a valid UUID.")
            item = {"uuid": _uuid(attr["uuid"]), "type": attr["type"], "value": attr["value"], "to_ids": to_ids}
            for key in ("category", "object_relation"):
                if key in attr:
                    if not isinstance(attr[key], str):
                        raise n8n.N8nError(f"Attribute {key} must be a string.")
                    item[key] = attr[key]
            output.append(item)
            count += 1
            if count > 1000:
                raise n8n.N8nError("At most 1000 selected attributes may be delivered.")
        return output

    # Core-format selections may place the collections beside Event.
    collections = dict(event, **data)
    selected["Attribute"] = attributes(collections)
    for obj in _rows(collections, "Object"):
        if n8n.boolean(obj.get("deleted"), "deleted"):
            skipped["deleted_object"] += 1
            continue
        rows = attributes(obj)
        if rows:
            if not isinstance(obj.get("name"), str) or not obj["name"]:
                raise n8n.N8nError("Selected objects require a name and valid UUID.")
            selected["Object"].append({"uuid": _uuid(obj["uuid"]), "name": obj["name"], "Attribute": rows})
    payload = {"source": "misp-modules", "version": 1, "Event": selected}
    encoded = n8n.encode(payload)
    if len(encoded) > 1024 * 1024:
        raise n8n.N8nError("The selected payload exceeds the 1 MiB limit.")
    return payload, encoded, count, dict(skipped)


def _connection():
    url = n8n.https_url(os.getenv("N8N_WEBHOOK_URL"))
    name = os.getenv("N8N_WEBHOOK_HEADER_NAME", "X-MISP-Token")
    if name.lower() in ("x-n8n-api-key", "x-misp-payload-sha256"):
        raise n8n.N8nError("Use a dedicated webhook authentication header, not the public API key or digest header.")
    auth = n8n.HeaderAuth(name, os.getenv("N8N_WEBHOOK_HEADER_VALUE"))
    timeout = n8n.integer(os.getenv("N8N_WEBHOOK_TIMEOUT"), "timeout", 20, 120)
    return url, auth, timeout


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("params", {}), dict):
            raise n8n.N8nError("A JSON object with object params is required.")
        if request.get("filters") or any(key in request for key in ("filteredItems", "matchingData")):
            raise n8n.N8nError(
                "Workflow filters and extracted data are unsupported; pass one explicit selected event in data."
            )
        params = request.get("params", {})
        dry_run = n8n.boolean(params.get("dry_run"), "dry_run", default=True)
        ids_only = n8n.boolean(params.get("to_ids_only"), "to_ids_only")
        payload, encoded, count, skipped = _payload(request.get("data"), ids_only)
    except n8n.N8nError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return {"error": "Invalid n8n webhook request."}
    digest = hashlib.sha256(encoded).hexdigest()
    data = {
        "success": True,
        "dry_run": dry_run,
        "status": "planned",
        "event_uuid": payload["Event"]["uuid"],
        "attributes": count,
        "objects": len(payload["Event"]["Object"]),
        "skipped": skipped,
        "payload_sha256": digest,
        "execution_confirmed": False,
    }
    result = {"result_key": "n8n_webhook", "data": data}
    if dry_run:
        data["payload"] = payload
        return result
    attempted = False
    try:
        url, auth, timeout = _connection()
        attempted = True
        status = n8n.request("POST", url, auth, timeout, payload=encoded, headers={"X-MISP-Payload-SHA256": digest})
        data.update(status="delivered", http_status=status)
    except (n8n.N8nError, ValueError, TypeError, AttributeError) as exc:
        data.update(success=False, status="uncertain" if attempted else "not_attempted")
        result["error"] = (
            str(exc) if isinstance(exc, n8n.N8nError) else "Invalid n8n webhook configuration or response."
        )
        if attempted:
            result["error"] += " Check n8n executions before retrying; the workflow may already have started."
    return result


def introspection():
    return {}


def version():
    return dict(moduleinfo, config=moduleconfig)
