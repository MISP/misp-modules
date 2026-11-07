"""Create a Tines Cases v2 case referencing one selected MISP event."""

import json
import os
import re
from uuid import UUID

from misp_modules.lib import tines

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Tines Case Create",
    "description": "Create a Tines Cases v2 case with a MISP event reference and selected-data counts.",
    "module-type": ["action"],
    "logo": "",
    "requirements": ["Tines API key permitted to create cases in the configured team."],
    "features": (
        "Creates one OPEN case with POST /api/v2/cases. Sends the selected event UUID, active attribute/object"
        " counts and an optional MISP link, without copying observable values or attachments. Supports a"
        " credential-free dry run (default), explicit team/priority and server-side connection settings."
        " Each live invocation creates a new case; no automatic retries or duplicate suppression. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/tines_case_create.md."
    ),
    "references": [tines.AUTH_REFERENCE, tines.CASE_REFERENCE],
    "input": "Exactly one selected MISP event in workflow data, with a valid event UUID.",
    "output": "Planned case payload or acknowledged case ID, team, priority and event reference.",
}
moduleconfig = {
    "params": {
        "team_id": {"type": "string", "description": "Required positive numeric Tines team ID"},
        "name_prefix": {
            "type": "string",
            "description": "Case name prefix (1–64 ASCII letters, digits, spaces, ._-)",
            "value": "MISP event",
        },
        "priority": {"type": "string", "description": "info, low, medium, high or critical", "value": "medium"},
        "dry_run": {
            "type": "string",
            "description": "true previews without network access; false creates a new case",
            "value": "true",
        },
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"


def _rows(container, name):
    rows = container.get(name, [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise tines.TinesError(f"{name} must be a list of objects.")
    return rows


def _source(data):
    if isinstance(data, list):
        if len(data) != 1:
            raise tines.TinesError("Select exactly one MISP event per case creation.")
        data = data[0]
    if not isinstance(data, dict):
        raise tines.TinesError("data must contain one MISP event.")
    event = data.get("Event", data)
    if not isinstance(event, dict) or tines.boolean(event.get("deleted"), "deleted"):
        raise tines.TinesError("A non-deleted MISP event is required.")
    event_uuid = str(UUID(event["uuid"]))
    # Legacy core-format envelopes carry the selected collections beside Event.
    collections = dict(event, **data)
    attributes = list(_rows(collections, "Attribute"))
    objects = 0
    for obj in _rows(collections, "Object"):
        if not tines.boolean(obj.get("deleted"), "deleted"):
            objects += 1
            attributes.extend(_rows(obj, "Attribute"))
    active = [attr for attr in attributes if not tines.boolean(attr.get("deleted"), "deleted")]
    return {
        "misp_source": "misp-modules",
        "misp_event_uuid": event_uuid,
        "misp_attribute_count": len(active),
        "misp_object_count": objects,
        "misp_ids_attribute_count": sum(tines.boolean(attr.get("to_ids"), "to_ids") for attr in active),
    }


def _plan(request):
    if request.get("filters"):
        raise tines.TinesError("Workflow filters are unsupported; pass one selected event in data.")
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise tines.TinesError("params must be an object.")
    team_id = tines.positive_id(params.get("team_id"), "team_id")
    prefix = params.get("name_prefix", "MISP event")
    if not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,64}", prefix) or not prefix.strip():
        raise tines.TinesError("name_prefix must contain 1–64 ASCII letters, digits, spaces, ._-.")
    priority = params.get("priority", "medium")
    if not isinstance(priority, str) or priority.lower() not in ("info", "low", "medium", "high", "critical"):
        raise tines.TinesError("priority must be info, low, medium, high or critical.")
    dry_run_value = params.get("dry_run")
    dry_run = True if dry_run_value in (None, "") else tines.boolean(dry_run_value, "dry_run")
    metadata = _source(request.get("data"))
    misp_url = os.getenv("TINES_MISP_URL")
    if misp_url:
        metadata["misp_event_url"] = (
            tines.https_url(misp_url, allow_path=True) + "/events/view/" + metadata["misp_event_uuid"]
        )
    return dry_run, {
        "team_id": team_id,
        "name": prefix.strip() + " " + metadata["misp_event_uuid"],
        "status": "OPEN",
        "priority": priority.lower(),
        "description": (
            "MISP event UUID: "
            + metadata["misp_event_uuid"]
            + f'\nSelected active attributes: {metadata["misp_attribute_count"]}'
            + f'\nSelected active objects: {metadata["misp_object_count"]}'
            + f'\nSelected IDS attributes: {metadata["misp_ids_attribute_count"]}'
            + "\nCounts describe the workflow selection. Consult MISP for the event contents."
        ),
        "metadata": metadata,
    }


def _acknowledgement(body, payload):
    team, metadata = body.get("team"), body.get("metadata")
    if (
        type(body.get("case_id")) is not int
        or body["case_id"] <= 0
        or not isinstance(team, dict)
        or type(team.get("id")) is not int
        or team["id"] != payload["team_id"]
        or body.get("name") != payload["name"]
        or not isinstance(body.get("status"), str)
        or body["status"].upper() != "OPEN"
        or not isinstance(body.get("priority"), str)
        or body["priority"].lower() != payload["priority"]
        or not isinstance(metadata, dict)
        or any(metadata.get(key) != payload["metadata"][key] for key in ("misp_source", "misp_event_uuid"))
    ):
        raise tines.TinesError("Tines did not confirm the requested case identity, team and settings.")
    return body["case_id"]


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise tines.TinesError("A JSON object is required.")
        dry_run, payload = _plan(request)
    except tines.TinesError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"error": "Invalid Tines case creation request."}
    data = {
        "success": True,
        "dry_run": dry_run,
        "status": "planned",
        "team_id": payload["team_id"],
        **payload["metadata"],
    }
    result = {"result_key": "tines_case_create", "data": data}
    if dry_run:
        data["payload"] = payload
        return result
    attempted = False
    try:
        with tines.Client({"url": os.getenv("TINES_URL"), "api_key": os.getenv("TINES_API_KEY")}) as client:
            attempted = True
            body = client.post("/api/v2/cases", payload)
            case_id = _acknowledgement(body, payload)
            data.update(
                status="created",
                case_id=case_id,
                priority=payload["priority"],
                case_status="OPEN",
                url=f'{client.origin}/team/{payload["team_id"]}/cases/{case_id}',
            )
    except (tines.TinesError, ValueError, TypeError, KeyError, AttributeError) as exc:
        data.update(success=False, status="uncertain" if attempted else "not_attempted")
        result["error"] = str(exc) if isinstance(exc, tines.TinesError) else "Invalid Tines connection or response."
        if attempted:
            result["error"] += " Check Tines before retrying: a case may already exist."
    return result


def introspection():
    return {}


def version():
    return dict(moduleinfo, config=moduleconfig)
