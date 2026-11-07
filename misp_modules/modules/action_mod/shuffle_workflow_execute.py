"""Submit selected MISP event data as a Shuffle workflow execution argument."""

import hashlib
import json
import os
from collections import Counter

from misp_modules.lib import shuffle

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Shuffle Workflow Execute",
    "logo": "",
    "description": (
        "Start a Shuffle workflow with selected MISP event and object attributes as its JSON execution argument."
    ),
    "module-type": ["action"],
    "requirements": ["Shuffle API key permitted to execute the selected workflow in the configured organization."],
    "features": (
        "Submits one selected event to the documented workflow execution API. Supports a credential-free dry run"
        " by default and optional IDS-only selection. Excludes deleted data and binary attachments, validates"
        " the execution acknowledgement, and returns the execution ID without its authorization token. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/shuffle_workflow_execute.md."
    ),
    "references": [shuffle.API_REFERENCE, shuffle.SOURCE_REFERENCE + "#execute-workflow"],
    "input": "One explicitly selected MISP event with event, object and attribute UUIDs in workflow data.",
    "output": "Preview request or submitted execution ID, source UUID, payload digest and selected/skipped counts.",
}
moduleconfig = {
    "params": {
        "workflow_id": {"type": "string", "description": "Required UUID of the Shuffle workflow to execute"},
        "dry_run": {
            "type": "string",
            "description": "true previews; false submits a new workflow execution",
            "value": "true",
        },
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
        raise shuffle.ShuffleError(f"{key} must be a list of objects.")
    return rows


def _payload(data, ids_only):
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    if not isinstance(data, dict):
        raise shuffle.ShuffleError("Select exactly one MISP event in data.")
    event = data.get("Event", data)
    if not isinstance(event, dict) or shuffle.boolean(event.get("deleted"), "deleted"):
        raise shuffle.ShuffleError("A non-deleted MISP event is required.")
    selected = {"uuid": shuffle.uuid(event["uuid"], "event UUID"), "Attribute": [], "Object": []}
    if "info" in event:
        if not isinstance(event["info"], str):
            raise shuffle.ShuffleError("Event info must be a string.")
        event["info"].encode("utf-8")
        selected["info"] = event["info"]
    skipped, count = Counter(), 0

    def attributes(container):
        nonlocal count
        output = []
        for attr in _rows(container, "Attribute"):
            if shuffle.boolean(attr.get("deleted"), "deleted"):
                skipped["deleted_attribute"] += 1
                continue
            if attr.get("type") in ("attachment", "malware-sample"):
                skipped["binary_attribute"] += 1
                continue
            to_ids = shuffle.boolean(attr.get("to_ids"), "to_ids")
            if ids_only and not to_ids:
                skipped["non_ids_attribute"] += 1
                continue
            if (
                not isinstance(attr.get("type"), str)
                or not attr["type"]
                or not isinstance(attr.get("value"), str)
                or not attr["value"]
            ):
                raise shuffle.ShuffleError("Selected attributes require string type/value and a valid UUID.")
            attr["type"].encode("utf-8")
            attr["value"].encode("utf-8")
            item = {
                "uuid": shuffle.uuid(attr["uuid"], "attribute UUID"),
                "type": attr["type"],
                "value": attr["value"],
                "to_ids": to_ids,
            }
            for key in ("category", "object_relation"):
                if key in attr:
                    if not isinstance(attr[key], str):
                        raise shuffle.ShuffleError(f"Attribute {key} must be a string.")
                    attr[key].encode("utf-8")
                    item[key] = attr[key]
            output.append(item)
            count += 1
            if count > 1000:
                raise shuffle.ShuffleError("At most 1000 selected attributes may be submitted.")
        return output

    # Legacy core-format selections may place collections beside Event.
    collections = dict(event, **data)
    selected["Attribute"] = attributes(collections)
    for obj in _rows(collections, "Object"):
        if shuffle.boolean(obj.get("deleted"), "deleted"):
            skipped["deleted_object"] += 1
            continue
        rows = attributes(obj)
        if rows:
            if not isinstance(obj.get("name"), str) or not obj["name"]:
                raise shuffle.ShuffleError("Selected objects require a name and valid UUID.")
            obj["name"].encode("utf-8")
            selected["Object"].append(
                {"uuid": shuffle.uuid(obj["uuid"], "object UUID"), "name": obj["name"], "Attribute": rows}
            )
    payload = {"source": "misp-modules", "version": 1, "Event": selected}
    encoded = shuffle.encode(payload)
    if len(encoded) > 1024 * 1024:
        raise shuffle.ShuffleError("The encoded execution argument exceeds the 1 MiB limit.")
    return payload, encoded, count, dict(skipped)


def _connection():
    return {key: os.getenv("SHUFFLE_" + key.upper()) for key in ("url", "api_key", "org_id", "timeout")}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("params", {}), dict):
            raise shuffle.ShuffleError("A JSON object with object params is required.")
        if request.get("filters") or any(key in request for key in ("filteredItems", "matchingData")):
            raise shuffle.ShuffleError(
                "Workflow filters and extracted data are unsupported; pass an explicit selected event in data."
            )
        params = request.get("params", {})
        workflow_id = shuffle.uuid(params.get("workflow_id"), "workflow_id")
        dry_run = shuffle.boolean(params.get("dry_run"), "dry_run", default=True)
        ids_only = shuffle.boolean(params.get("to_ids_only"), "to_ids_only")
        payload, encoded, count, skipped = _payload(request.get("data"), ids_only)
    except shuffle.ShuffleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return {"error": "Invalid Shuffle workflow execution request."}
    argument = encoded.decode("ascii")
    data = {
        "success": True,
        "dry_run": dry_run,
        "status": "planned",
        "workflow_id": workflow_id,
        "event_uuid": payload["Event"]["uuid"],
        "attributes": count,
        "objects": len(payload["Event"]["Object"]),
        "skipped": skipped,
        "payload_sha256": hashlib.sha256(encoded).hexdigest(),
        "execution_complete": False,
    }
    result = {"result_key": "shuffle_workflow_execute", "data": data}
    if dry_run:
        data["payload"] = {"execution_argument": argument, "start": ""}
        return result
    attempted = False
    try:
        with shuffle.Client(_connection()) as client:
            attempted = True
            body = client.execute(workflow_id, argument)
            execution_id = shuffle.uuid(body.get("execution_id"), "returned execution_id")
            if (
                body.get("workflow_id") not in (None, "")
                and shuffle.uuid(body["workflow_id"], "returned workflow_id") != workflow_id
            ):
                raise shuffle.ShuffleError("Shuffle acknowledged a different workflow.")
            data.update(status="submitted", execution_id=execution_id, org_id=client.org_id)
    except (shuffle.ShuffleError, ValueError, TypeError, KeyError, AttributeError) as exc:
        data.update(success=False, status="uncertain" if attempted else "not_attempted")
        result["error"] = (
            str(exc) if isinstance(exc, shuffle.ShuffleError) else "Invalid Shuffle connection or response."
        )
        if attempted:
            result["error"] += " Check Shuffle executions before retrying; a run may already exist."
    return result


def introspection():
    return {}


def version():
    return dict(moduleinfo, config=moduleconfig)
