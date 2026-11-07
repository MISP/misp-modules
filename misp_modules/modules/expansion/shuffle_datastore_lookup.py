"""Read a Shuffle Datastore record by an observable's literal key."""

import json

from pymisp import MISPEvent, MISPObject

from misp_modules.lib import shuffle

INPUT_TYPES = [
    "text",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "domain",
    "hostname",
    "ip-src",
    "ip-dst",
    "url",
    "email",
    "email-src",
    "email-dst",
    "vulnerability",
    "filename",
]
mispattributes = {"input": INPUT_TYPES, "format": "misp_standard"}
moduleconfig = ["url", "api_key", "org_id", "category", "key_prefix", "timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Shuffle Datastore Lookup",
    "logo": "",
    "description": "Look up a MISP observable's key in a selected Shuffle organization and Datastore category.",
    "module-type": ["expansion", "hover"],
    "data-source": "external",
    "requirements": ["Shuffle API key with read access to the selected organization, Datastore category and key."],
    "features": (
        "Uses the read-only get_cache API, validates returned key/category identity and preserves native record values."
        " Returns a referenced non-IDS annotation with only selected metadata, excluding Datastore authorization"
        " tokens. Missing/inaccessible keys are errors, not benign verdicts. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/expansion/shuffle_datastore_lookup.md."
    ),
    "references": [shuffle.API_REFERENCE, shuffle.SOURCE_REFERENCE + "#get-a-key"],
    "input": "A supported observable or text attribute with a UUID and a literal Datastore key value.",
    "output": "Original attribute and referenced annotation with the Datastore value and selected metadata.",
}


def _record(body, key, selected_category, org_id):
    if body.get("key") != key or shuffle.category(body.get("category", "")) != selected_category:
        raise shuffle.ShuffleError("Shuffle returned a different key or Datastore category.")
    # Current Shuffle clears org_id in replies; older versions may echo it.
    if body.get("org_id") not in (None, "") and shuffle.uuid(body["org_id"], "returned org_id") != org_id:
        raise shuffle.ShuffleError("Shuffle returned a record from another organization.")
    if "value" not in body:
        raise shuffle.ShuffleError("Shuffle omitted the Datastore value.")
    return {
        field: body[field]
        for field in (
            "key",
            "value",
            "category",
            "created",
            "edited",
            "changed",
            "encrypted",
            "revision_id",
            "workflow_id",
        )
        if field in body
    }


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise shuffle.ShuffleError("A JSON object is required.")
        source, config = request.get("attribute"), request.get("config")
        if not isinstance(source, dict) or source.get("type") not in INPUT_TYPES:
            raise shuffle.ShuffleError("A supported attribute with a UUID is required.")
        shuffle.uuid(source["uuid"], "attribute UUID")
        value = source.get("value")
        if not isinstance(value, str) or not value or value != value.strip():
            raise shuffle.ShuffleError("The lookup value must be a non-empty string without surrounding whitespace.")
        if not isinstance(config, dict):
            raise shuffle.ShuffleError("Shuffle configuration is required.")
        prefix = config.get("key_prefix", "")
        if not isinstance(prefix, str) or len(prefix) > 128:
            raise shuffle.ShuffleError("key_prefix must be a string of at most 128 characters.")
        key = prefix + value
        if (
            len(key.encode("utf-8")) > 1024
            or key != key.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in key)
        ):
            raise shuffle.ShuffleError(
                "The complete key must be at most 1024 UTF-8 bytes without surrounding whitespace or controls."
            )
        selected_category = shuffle.category(config.get("category", ""))
        with shuffle.Client(config) as client:
            body = client.datastore(key, selected_category)
            record = _record(body, key, selected_category, client.org_id)
            org_id = client.org_id
        report = {
            "provider": "Shuffle",
            "status": "found",
            "org_id": org_id,
            "category": selected_category,
            "key": key,
            "record": record,
        }
        obj = MISPObject("annotation")
        obj.comment = "Shuffle Datastore lookup"
        obj.add_attribute("text", value=json.dumps(report, sort_keys=True), to_ids=False, disable_correlation=True)
        obj.add_reference(source["uuid"], "describes")
        event = MISPEvent()
        event.add_object(obj)
        return {"results": {"Attribute": [source], "Object": json.loads(event.to_json())["Object"]}}
    except shuffle.ShuffleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return {"error": "Invalid Shuffle Datastore lookup request or response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
