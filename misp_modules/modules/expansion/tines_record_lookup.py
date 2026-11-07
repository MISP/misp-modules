"""Search an explicitly selected Tines record field for a MISP observable."""

import json
from uuid import UUID

from pymisp import MISPEvent, MISPObject

from misp_modules.lib import tines

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
]
mispattributes = {"input": INPUT_TYPES, "format": "misp_standard"}
moduleconfig = ["url", "api_key", "record_type_id", "field_id", "limit", "test_mode", "timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Tines Record Lookup",
    "description": "Find a MISP observable in a selected Tines record type and field using Records v2 search.",
    "module-type": ["expansion", "hover"],
    "data-source": "external",
    "logo": "",
    "requirements": ["Tines API access to the selected record type and its search field."],
    "features": (
        "Uses a literal EQUAL filter against an explicit numeric field ID. Queries the read-only Records v2 search"
        " API, preserves source attributes and returns a referenced annotation with records and completeness."
        " Artifact handles and pagination links are not fetched. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/expansion/tines_record_lookup.md."
    ),
    "references": [tines.AUTH_REFERENCE, tines.SEARCH_REFERENCE],
    "input": "A supported observable or text attribute with a UUID and a non-empty string value.",
    "output": "Original attribute and a non-IDS annotation of Tines record matches and pagination completeness.",
}


def _response(body, record_type_id, field_id, value, limit):
    rows, fields, page = body.get("data"), body.get("field_ids"), body.get("page")
    applied = body.get("applied")
    applied_filter = applied.get("filter") if isinstance(applied, dict) else None
    # The API may normalize a condition into an AND group. Accept only equivalent
    # single-condition groups; an extra condition would narrow the requested search.
    for _ in range(4):
        if not isinstance(applied_filter, dict) or applied_filter.get("op") != "AND":
            break
        nodes = applied_filter.get("nodes")
        if not isinstance(nodes, list) or len(nodes) != 1:
            break
        applied_filter = nodes[0]
    if (
        not isinstance(applied_filter, dict)
        or type(applied_filter.get("field_id")) is not int
        or applied_filter != {
            "field_id": field_id,
            "operator": "EQUAL",
            "value": value,
        }
    ):
        raise tines.TinesError("Tines did not confirm the requested field filter.")
    if not isinstance(rows, list) or len(rows) > limit or not isinstance(fields, dict) or not isinstance(page, dict):
        raise tines.TinesError("Tines returned an invalid record search response.")
    if any(
        not isinstance(key, str) or type(identifier) is not int or identifier <= 0 for key, identifier in fields.items()
    ):
        raise tines.TinesError("Tines returned an invalid field ID map.")
    if rows and field_id not in fields.values():
        raise tines.TinesError("Tines omitted the requested search field from its field ID map.")
    records, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or type(row.get("id")) is not int or row["id"] <= 0 or row["id"] in seen:
            raise tines.TinesError("Tines returned an invalid or duplicate record ID.")
        relationships = row.get("relationships")
        if not isinstance(relationships, dict) or not isinstance(relationships.get("record_type"), dict):
            raise tines.TinesError("Tines omitted the record type identity.")
        returned_type = relationships["record_type"].get("id")
        if type(returned_type) is not int or returned_type != record_type_id or not isinstance(row.get("fields"), dict):
            raise tines.TinesError("Tines returned records for a different type or invalid fields.")
        seen.add(row["id"])
        records.append(
            {key: row[key] for key in ("id", "fields", "relationships", "created_at", "updated_at") if key in row}
        )
    total, cursor = page.get("total"), page.get("next_page_token")
    if type(total) is not int or total < len(records) or (total > 0 and not records):
        raise tines.TinesError("Tines returned an invalid or incomplete record count.")
    if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 16384 or not records):
        raise tines.TinesError("Tines returned an invalid pagination cursor.")
    return {
        "status": "found" if records else "not_found",
        "records": records,
        "field_ids": fields,
        "returned": len(records),
        "total": total,
        "truncated": bool(cursor) or total > len(records),
    }


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise tines.TinesError("A JSON object is required.")
        source, config = request.get("attribute"), request.get("config")
        if not isinstance(source, dict) or source.get("type") not in INPUT_TYPES:
            raise tines.TinesError("A supported attribute with a UUID is required.")
        UUID(source["uuid"])
        value = source.get("value")
        if not isinstance(value, str) or not value.strip() or len(value) > 4096:
            raise tines.TinesError("The lookup value must be a non-empty string of at most 4096 characters.")
        value.encode("utf-8")
        if not isinstance(config, dict):
            raise tines.TinesError("Tines configuration is required.")
        record_type_id = tines.positive_id(config.get("record_type_id"), "record_type_id")
        field_id = tines.positive_id(config.get("field_id"), "field_id")
        limit = tines.integer(config.get("limit"), "limit", 20, 100)
        test_mode = tines.boolean(config.get("test_mode"), "test_mode")
        payload = {
            "record_type_id": record_type_id,
            "filter": {"field_id": field_id, "operator": "EQUAL", "value": value},
            "include_total": True,
            "limit": limit,
            "test_mode": test_mode,
        }
        with tines.Client(config) as client:
            body = client.post("/api/v2/records/search", payload)
        report = {
            "provider": "Tines",
            "query": value,
            "record_type_id": record_type_id,
            "field_id": field_id,
            "test_mode": test_mode,
            **_response(body, record_type_id, field_id, value, limit),
        }
        obj = MISPObject("annotation")
        obj.comment = "Tines record search"
        obj.add_attribute("text", value=json.dumps(report, sort_keys=True), to_ids=False, disable_correlation=True)
        obj.add_reference(source["uuid"], "describes")
        event = MISPEvent()
        event.add_object(obj)
        result = {"results": {"Attribute": [source], "Object": json.loads(event.to_json())["Object"]}}
        if report["truncated"]:
            result["warnings"] = ["More Tines records match; this lookup returns one bounded result page."]
        return result
    except tines.TinesError as exc:
        return {"error": str(exc)}
    except (ValueError, KeyError, TypeError, AttributeError):
        return {"error": "Invalid Tines record lookup request or response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
