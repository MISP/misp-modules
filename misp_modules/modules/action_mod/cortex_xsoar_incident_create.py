"""Create a Cortex XSOAR 8 incident referencing an explicitly selected MISP event."""

import json
import math
import os
import re
from urllib.parse import urlsplit
from uuid import UUID

from misp_modules.lib import cortex_xsoar as xsoar

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Cortex XSOAR Incident Create",
    "logo": "",
    "description": "Create a Cortex XSOAR 8 incident with a MISP event reference and selected-data counts.",
    "module-type": ["action"],
    "requirements": ["Cortex XSOAR 8 API credentials with incident creation permissions."],
    "features": (
        "Creates a new incident through /xsoar/public/v1/incident, with dry run enabled by default. Distinguishes"
        " HTTP 201 creation from HTTP 200 processing without creation. Supports Standard/Advanced keys and"
        " an explicit investigation opt-in. Sends source UUID/counts rather than event contents. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/cortex_xsoar_incident_create.md."
    ),
    "references": [xsoar.OVERVIEW, xsoar.AUTH_REFERENCE, xsoar.INCIDENT_REFERENCE],
    "input": "Exactly one selected, non-deleted MISP event with a valid UUID in workflow data.",
    "output": "Preview or created/not-created/uncertain incident outcome, source UUID and selected-data counts.",
}
moduleconfig = {
    "params": {
        "incident_type": {"type": "string", "description": "Existing XSOAR incident type", "value": "Unclassified"},
        "name_prefix": {
            "type": "string",
            "description": "1–64 ASCII letters, digits, spaces, ._-",
            "value": "MISP event",
        },
        "severity": {"type": "string", "description": "Numeric XSOAR severity from 0 to 4", "value": "2"},
        "create_investigation": {
            "type": "string",
            "description": "true starts the incident type's investigation/playbook",
            "value": "false",
        },
        "dry_run": {"type": "string", "description": "true previews; false requests a new incident", "value": "true"},
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"


def _rows(container, key):
    rows = container.get(key, [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise xsoar.XsoarError(f"{key} must be a list of objects.")
    return rows


def _source(data):
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    if not isinstance(data, dict):
        raise xsoar.XsoarError("Select exactly one MISP event in data.")
    event = data.get("Event", data)
    if not isinstance(event, dict) or xsoar.boolean(event.get("deleted"), "deleted"):
        raise xsoar.XsoarError("A non-deleted MISP event is required.")
    event_uuid = UUID(event["uuid"])
    if not event_uuid.int:
        raise xsoar.XsoarError("A non-empty event UUID is required.")
    collections = dict(event, **data)
    attributes = list(_rows(collections, "Attribute"))
    objects = 0
    for obj in _rows(collections, "Object"):
        if not xsoar.boolean(obj.get("deleted"), "deleted"):
            objects += 1
            attributes.extend(_rows(obj, "Attribute"))
    active = [attr for attr in attributes if not xsoar.boolean(attr.get("deleted"), "deleted")]
    return {
        "event_uuid": str(event_uuid),
        "attributes": len(active),
        "objects": objects,
        "ids_attributes": sum(xsoar.boolean(attr.get("to_ids"), "to_ids") for attr in active),
    }


def _severity(value):
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise xsoar.XsoarError("severity must be a finite number from 0 to 4.")
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= 4:
        raise xsoar.XsoarError("severity must be a finite number from 0 to 4.")
    return number


def _source_url(event_uuid):
    value = os.getenv("CORTEX_XSOAR_MISP_URL")
    if not value:
        return None
    parsed = urlsplit(value)
    if (
        len(value) > 2048
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(ord(char) <= 32 or ord(char) == 127 or char in "<>\\" for char in value)
    ):
        raise xsoar.XsoarError("CORTEX_XSOAR_MISP_URL must be an HTTPS base without credentials, query or fragment.")
    return value.rstrip("/") + "/events/view/" + event_uuid


def _plan(request):
    if request.get("filters") or any(key in request for key in ("filteredItems", "matchingData")):
        raise xsoar.XsoarError("Workflow filters and extracted data are unsupported; pass an explicit event in data.")
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise xsoar.XsoarError("params must be an object.")
    prefix, incident_type = params.get("name_prefix", "MISP event"), params.get("incident_type", "Unclassified")
    if not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,64}", prefix) or not prefix.strip():
        raise xsoar.XsoarError("name_prefix must contain 1–64 ASCII letters, digits, spaces, ._-.")
    if (
        not isinstance(incident_type, str)
        or not 1 <= len(incident_type) <= 128
        or incident_type != incident_type.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in incident_type)
    ):
        raise xsoar.XsoarError(
            "incident_type must be an existing type name of 1–128 characters without surrounding whitespace or"
            " controls."
        )
    incident_type.encode("utf-8")
    severity = _severity(params.get("severity", "2"))
    investigate = xsoar.boolean(params.get("create_investigation"), "create_investigation")
    source = _source(request.get("data"))
    details = (
        f'MISP event UUID: {source["event_uuid"]}'
        + f'\nSelected active attributes: {source["attributes"]}'
        + f'\nSelected active objects: {source["objects"]}'
        + f'\nSelected IDS attributes: {source["ids_attributes"]}'
        + "\nCounts describe the workflow selection. Consult MISP for event contents."
    )
    labels = [
        {"type": "misp_source", "value": "misp-modules"},
        {"type": "misp_event_uuid", "value": source["event_uuid"]},
    ]
    source_url = _source_url(source["event_uuid"])
    if source_url:
        details += "\nMISP event: " + source_url
        labels.append({"type": "misp_event_url", "value": source_url})
    payload = {
        "name": prefix.strip() + " " + source["event_uuid"],
        "type": incident_type,
        "severity": severity,
        "details": details,
        "labels": labels,
        "createInvestigation": investigate,
    }
    return xsoar.boolean(params.get("dry_run"), "dry_run", default=True), source, payload


def _acknowledgement(body, event_uuid):
    identifier = body.get("id")
    labels = body.get("labels")
    if (
        not isinstance(identifier, str)
        or not 1 <= len(identifier) <= 128
        or any(not 33 <= ord(c) <= 126 for c in identifier)
        or not isinstance(body.get("name"), str)
        or not body["name"].strip()
        or not isinstance(body.get("type"), str)
        or not body["type"].strip()
        or isinstance(body.get("severity"), bool)
        or not isinstance(body.get("severity"), (int, float))
        or not isinstance(labels, list)
        or not any(
            isinstance(label, dict) and label.get("type") == "misp_event_uuid" and label.get("value") == event_uuid
            for label in labels
        )
    ):
        raise xsoar.XsoarError("Cortex XSOAR did not confirm the incident identity and source event label.")
    _severity(body.get("severity"))
    return body


def _connection():
    return {
        key: os.getenv("CORTEX_XSOAR_" + key.upper())
        for key in ("url", "api_key", "api_key_id", "auth_type", "timeout")
    }


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise xsoar.XsoarError("A JSON object is required.")
        dry_run, source, payload = _plan(request)
    except xsoar.XsoarError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        return {"error": "Invalid Cortex XSOAR incident creation request."}
    data = {"success": True, "dry_run": dry_run, "status": "planned", **source}
    result = {"result_key": "cortex_xsoar_incident_create", "data": data}
    if dry_run:
        data["payload"] = payload
        return result
    attempted = False
    try:
        with xsoar.Client(_connection()) as client:
            attempted = True
            status, body = client.post("incident", payload)
        if status == 200:
            data.update(success=False, status="not_created")
            result["error"] = (
                "XSOAR processed the request without creating an incident; review preprocessing rules and incident"
                " settings before retrying."
            )
            return result
        incident = _acknowledgement(body, source["event_uuid"])
        data.update(
            status="created",
            incident_id=incident["id"],
            name=incident["name"],
            incident_type=incident["type"],
            severity=incident["severity"],
            create_investigation=payload["createInvestigation"],
        )
        if isinstance(incident.get("investigationId"), str) and incident["investigationId"]:
            data["investigation_id"] = incident["investigationId"]
        if any(incident[key] != payload[key] for key in ("name", "type", "severity")):
            result["warnings"] = [
                "XSOAR returned modified name/type/severity; the result reports the actual created incident fields."
            ]
    except (xsoar.XsoarError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        data.update(success=False, status="uncertain" if attempted else "not_attempted")
        result["error"] = (
            str(exc) if isinstance(exc, xsoar.XsoarError) else "Invalid Cortex XSOAR connection or response."
        )
        if attempted:
            result["error"] += " Check XSOAR before retrying: an incident may already exist."
    return result


def introspection():
    return {}


def version():
    return dict(moduleinfo, config=moduleconfig)
