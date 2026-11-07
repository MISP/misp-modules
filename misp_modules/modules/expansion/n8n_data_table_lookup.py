"""Look up a literal observable in an n8n Data Table string column."""

import json
import re
from uuid import UUID

from pymisp import MISPEvent, MISPObject

from misp_modules.lib import n8n

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
moduleconfig = ["url", "api_key", "data_table_id", "column", "limit", "timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "n8n Data Table Lookup",
    "logo": "",
    "description": "Find an observable in a selected n8n Data Table string column using the public REST API.",
    "module-type": ["expansion", "hover"],
    "data-source": "external",
    "requirements": ["n8n public API with Data Tables endpoints; dataTableColumn:read and dataTableRow:read access."],
    "features": (
        "Validates the configured column and queries one bounded row page with a literal equality filter."
        " Preserves the source attribute and attaches matched rows in a referenced non-IDS annotation."
        " Reports cursor truncation without following provider links or running any workflow. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/expansion/n8n_data_table_lookup.md."
    ),
    "references": [n8n.API_REFERENCE, n8n.AUTH_REFERENCE, n8n.TABLE_REFERENCE],
    "input": "A supported observable or text attribute with a UUID and non-empty string value.",
    "output": "Original attribute and a non-IDS annotation with matching Data Table rows and completeness.",
}


def _column(body, table_id, name):
    if not isinstance(body, list) or any(not isinstance(item, dict) for item in body):
        raise n8n.N8nError("n8n returned an invalid column list.")
    matches = [item for item in body if item.get("name") == name]
    if len(matches) != 1 or matches[0].get("type") != "string" or matches[0].get("dataTableId") != table_id:
        raise n8n.N8nError(
            "The selected table column is missing, ambiguous, belongs to another table or is not a string."
        )


def _rows(body, name, value, limit):
    if not isinstance(body, dict) or not isinstance(body.get("data"), list) or "nextCursor" not in body:
        raise n8n.N8nError("n8n returned an invalid row page.")
    rows, cursor = body["data"], body["nextCursor"]
    if len(rows) > limit:
        raise n8n.N8nError("n8n returned more rows than requested.")
    if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 16384 or not rows):
        raise n8n.N8nError("n8n returned an invalid or incomplete pagination cursor.")
    seen = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or type(row.get("id")) is not int
            or row["id"] <= 0
            or row["id"] in seen
            or not isinstance(row.get(name), str)
            or row[name] != value
        ):
            raise n8n.N8nError("n8n returned invalid, duplicate or non-matching rows.")
        seen.add(row["id"])
    return {
        "status": "found" if rows else "not_found",
        "rows": rows,
        "returned": len(rows),
        "truncated": cursor is not None,
    }


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise n8n.N8nError("A JSON object is required.")
        source, config = request.get("attribute"), request.get("config")
        if not isinstance(source, dict) or source.get("type") not in INPUT_TYPES:
            raise n8n.N8nError("A supported attribute with a UUID is required.")
        UUID(source["uuid"])
        value = source.get("value")
        if not isinstance(value, str) or not value.strip() or len(value) > 4096:
            raise n8n.N8nError("The lookup value must be a non-empty string of at most 4096 characters.")
        value.encode("utf-8")
        if not isinstance(config, dict):
            raise n8n.N8nError("n8n configuration is required.")
        table_id, column = config.get("data_table_id"), config.get("column")
        if not isinstance(table_id, str) or not re.fullmatch(r"[A-Za-z0-9]{16}", table_id):
            raise n8n.N8nError("data_table_id must be the 16-character alphanumeric n8n table ID.")
        if (
            not isinstance(column, str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,62}", column)
            or column in ("id", "createdAt", "updatedAt")
        ):
            raise n8n.N8nError("column must be a user-defined n8n string column name.")
        base = n8n.https_url(config.get("url"), api=True)
        auth = n8n.HeaderAuth("X-N8N-API-KEY", config.get("api_key"))
        limit = n8n.integer(config.get("limit"), "limit", 20, 100)
        timeout = n8n.integer(config.get("timeout"), "timeout", 20, 120)
        endpoint = base + "/data-tables/" + table_id
        _column(n8n.request("GET", endpoint + "/columns", auth, timeout, read_json=True), table_id, column)
        params = {
            "limit": limit,
            "filter": json.dumps(
                {"type": "and", "filters": [{"columnName": column, "condition": "eq", "value": value}]},
                separators=(",", ":"),
            ),
            "sortBy": "id:asc",
        }
        body = n8n.request("GET", endpoint + "/rows", auth, timeout, params=params, read_json=True)
        report = {
            "provider": "n8n",
            "data_table_id": table_id,
            "column": column,
            "query": value,
            **_rows(body, column, value, limit),
        }
        obj = MISPObject("annotation")
        obj.comment = "n8n Data Table lookup"
        obj.add_attribute("text", value=json.dumps(report, sort_keys=True), to_ids=False, disable_correlation=True)
        obj.add_reference(source["uuid"], "describes")
        event = MISPEvent()
        event.add_object(obj)
        result = {"results": {"Attribute": [source], "Object": json.loads(event.to_json())["Object"]}}
        if report["truncated"]:
            result["warnings"] = ["More n8n rows match; this lookup returns one bounded result page."]
        return result
    except n8n.N8nError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return {"error": "Invalid n8n Data Table lookup request or response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
