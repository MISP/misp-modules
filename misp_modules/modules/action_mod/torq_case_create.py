"""Create a Torq case referencing one explicitly selected MISP event."""

import json
import os
import re
from urllib.parse import urlsplit
from uuid import UUID

from misp_modules.lib import torq

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Torq Case Create",
    "logo": "",
    "description": "Create a Torq case with a MISP event reference, provenance tags and selected-data counts.",
    "module-type": ["action"],
    "requirements": ["Torq API credentials permitted to create cases and a valid case reporter email."],
    "features": (
        "Creates one new case using POST /public/v1alpha/cases. Includes a credential-free dry run by default,"
        " explicit reporter/severity and server-side credentials. Sends source UUID and counts rather than event"
        " contents. Repeated live invocations create new cases; no automatic retries. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/torq_case_create.md."
    ),
    "references": [torq.OVERVIEW, torq.AUTH_REFERENCE, torq.CASE_REFERENCE],
    "input": "Exactly one explicitly selected MISP event in workflow data, with a valid event UUID.",
    "output": "Planned case payload or confirmed Torq case ID, state, severity and source event UUID.",
}
moduleconfig = {
    "params": {
        "reporter_email": {"type": "string", "description": "Required email of the Torq case reporter"},
        "title_prefix": {
            "type": "string",
            "description": "1–64 ASCII letters, digits, spaces, ._-",
            "value": "MISP event",
        },
        "severity": {
            "type": "string",
            "description": "informational, low, medium, high or critical",
            "value": "medium",
        },
        "dry_run": {"type": "string", "description": "true previews; false creates a new case", "value": "true"},
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"


def _rows(container, key):
    rows = container.get(key, [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise torq.TorqError(f"{key} must be a list of objects.")
    return rows


def _source(data):
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    if not isinstance(data, dict):
        raise torq.TorqError("Select exactly one MISP event in data.")
    event = data.get("Event", data)
    if not isinstance(event, dict) or torq.boolean(event.get("deleted"), "deleted"):
        raise torq.TorqError("A non-deleted MISP event is required.")
    event_uuid = str(UUID(event["uuid"]))
    collections = dict(event, **data)
    attrs = list(_rows(collections, "Attribute"))
    objects = 0
    for obj in _rows(collections, "Object"):
        if not torq.boolean(obj.get("deleted"), "deleted"):
            objects += 1
            attrs.extend(_rows(obj, "Attribute"))
    active = [attr for attr in attrs if not torq.boolean(attr.get("deleted"), "deleted")]
    return {
        "event_uuid": event_uuid,
        "attributes": len(active),
        "objects": objects,
        "ids_attributes": sum(torq.boolean(attr.get("to_ids"), "to_ids") for attr in active),
    }


def _misp_url(event_uuid):
    value = os.getenv("TORQ_MISP_URL")
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
        raise torq.TorqError("TORQ_MISP_URL must be an HTTPS base URL without credentials, query or fragment.")
    return value.rstrip("/") + "/events/view/" + event_uuid


def _plan(request):
    if request.get("filters") or any(key in request for key in ("filteredItems", "matchingData")):
        raise torq.TorqError("Workflow filters and extracted data are unsupported; pass an explicit event in data.")
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise torq.TorqError("params must be an object.")
    reporter = params.get("reporter_email")
    if (
        not isinstance(reporter, str)
        or len(reporter) > 254
        or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", reporter)
    ):
        raise torq.TorqError("A valid ASCII reporter_email is required.")
    prefix = params.get("title_prefix", "MISP event")
    if not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,64}", prefix) or not prefix.strip():
        raise torq.TorqError("title_prefix must contain 1–64 ASCII letters, digits, spaces, ._-.")
    severity = params.get("severity", "medium")
    if not isinstance(severity, str) or severity.lower() not in ("informational", "low", "medium", "high", "critical"):
        raise torq.TorqError("severity must be informational, low, medium, high or critical.")
    source = _source(request.get("data"))
    description = (
        f'MISP event UUID: {source["event_uuid"]}'
        + f'\nSelected active attributes: {source["attributes"]}'
        + f'\nSelected active objects: {source["objects"]}'
        + f'\nSelected IDS attributes: {source["ids_attributes"]}'
        + "\nCounts describe the workflow selection. Consult MISP for event contents."
    )
    source_url = _misp_url(source["event_uuid"])
    if source_url:
        description += "\nMISP event: " + source_url
    payload = {
        "title": prefix.strip() + " " + source["event_uuid"],
        "description": description,
        "state": {"value": "new"},
        "severity": {"value": severity.lower()},
        "reporter": {"user": {"email": reporter}},
        "tags": ["misp", "misp-event:" + source["event_uuid"]],
    }
    return torq.boolean(params.get("dry_run"), "dry_run", default=True), source, payload


def _acknowledgement(body, payload):
    case = body.get("case")
    if not isinstance(case, dict):
        raise torq.TorqError("Torq did not return a created case.")
    reporter, state, severity = case.get("reporter"), case.get("state"), case.get("severity")
    user = reporter.get("user") if isinstance(reporter, dict) else None
    if (
        type(case.get("id")) is not int
        or case["id"] <= 0
        or case.get("title") != payload["title"]
        or not isinstance(case.get("description"), str)
        or payload["tags"][1].removeprefix("misp-event:") not in case["description"]
        or not isinstance(state, dict)
        or state.get("value") != "new"
        or not isinstance(severity, dict)
        or severity.get("value") != payload["severity"]["value"]
        or not isinstance(user, dict)
        or not isinstance(user.get("email"), str)
        or user["email"].lower() != payload["reporter"]["user"]["email"].lower()
        or not isinstance(case.get("tags"), list)
        or any(not isinstance(tag, str) for tag in case["tags"])
        or not set(payload["tags"]).issubset(case["tags"])
    ):
        raise torq.TorqError("Torq did not confirm the requested case identity, reporter and settings.")
    return case


def _connection():
    return {
        key: os.getenv("TORQ_" + key.upper())
        for key in ("region", "client_id", "client_secret", "access_token", "timeout")
    }


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise torq.TorqError("A JSON object is required.")
        dry_run, source, payload = _plan(request)
    except torq.TorqError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return {"error": "Invalid Torq case creation request."}
    data = {"success": True, "dry_run": dry_run, "status": "planned", **source}
    result = {"result_key": "torq_case_create", "data": data}
    if dry_run:
        data["payload"] = payload
        return result
    attempted = False
    try:
        with torq.Client(_connection()) as client:
            client.authenticate()
            attempted = True
            case = _acknowledgement(client.post("/v1alpha/cases", payload), payload)
            data.update(
                status="created",
                case_id=case["id"],
                region=client.region,
                state="new",
                severity=payload["severity"]["value"],
            )
            if isinstance(case.get("pretty_id"), str):
                data["pretty_id"] = case["pretty_id"]
    except (torq.TorqError, ValueError, TypeError, KeyError, AttributeError) as exc:
        data.update(success=False, status="uncertain" if attempted else "not_attempted")
        result["error"] = str(exc) if isinstance(exc, torq.TorqError) else "Invalid Torq configuration or response."
        if attempted:
            result["error"] += " Check Torq before retrying: a case may already exist."
    return result


def introspection():
    return {}


def version():
    return dict(moduleinfo, config=moduleconfig)
