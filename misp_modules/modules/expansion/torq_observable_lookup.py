"""Search Torq observable intelligence and verify exact typed matches locally."""

import ipaddress
import json
import re
from uuid import UUID

import idna
from pymisp import MISPEvent, MISPObject

from misp_modules.lib import torq

TYPE_MAP = {
    "domain": ("TYPE_ID_HOSTNAME", "hostname"),
    "hostname": ("TYPE_ID_HOSTNAME", "hostname"),
    "ip-src": ("TYPE_ID_IP_ADDRESS", "ip"),
    "ip-dst": ("TYPE_ID_IP_ADDRESS", "ip"),
    "md5": ("TYPE_ID_FILE_HASH", "file_hash"),
    "sha1": ("TYPE_ID_FILE_HASH", "file_hash"),
    "sha256": ("TYPE_ID_FILE_HASH", "file_hash"),
    "email": ("TYPE_ID_EMAIL_ADDRESS", "email_address"),
    "email-src": ("TYPE_ID_EMAIL_ADDRESS", "email_address"),
    "email-dst": ("TYPE_ID_EMAIL_ADDRESS", "email_address"),
    "url": ("TYPE_ID_URL", "url"),
    "filename": ("TYPE_ID_FILE_NAME", "file_name"),
}
mispattributes = {"input": list(TYPE_MAP), "format": "misp_standard"}
moduleconfig = ["region", "client_id", "client_secret", "access_token", "limit", "timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Torq Observable Lookup",
    "logo": "",
    "description": (
        "Look up a MISP observable in Torq and return verified matches with reputation and threat intelligence."
    ),
    "module-type": ["expansion", "hover"],
    "data-source": "external",
    "requirements": ["Torq API credentials for the workspace with permission to query observables."],
    "features": (
        "Uses the read-only observable query API and verifies typed values locally because search may be broader"
        " than equality. Returns a referenced non-IDS annotation with reputation, enrichment and completeness."
        " Supports regional API bases, OAuth client credentials and existing bearer tokens. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/expansion/torq_observable_lookup.md."
    ),
    "references": [torq.OVERVIEW, torq.AUTH_REFERENCE, torq.LOOKUP_REFERENCE],
    "input": "Domain/hostname, IP, MD5/SHA1/SHA256, URL, email or filename attribute with a valid UUID.",
    "output": "Original attribute and referenced annotation with exact typed matches and search completeness.",
}


def _normalize(kind, value):
    if not isinstance(value, str) or not value or len(value) > 4096 or value != value.strip():
        raise ValueError("Invalid observable value")
    value.encode("utf-8")
    if kind in ("ip-src", "ip-dst"):
        address = ipaddress.ip_address(value)
        if getattr(address, "scope_id", None):
            raise ValueError("Scoped IP addresses are unsupported")
        return str(address)
    if kind in ("md5", "sha1", "sha256"):
        if not re.fullmatch(r"[0-9a-fA-F]{%d}" % {"md5": 32, "sha1": 40, "sha256": 64}[kind], value):
            raise ValueError("Invalid hash")
        return value.lower()
    if kind in ("domain", "hostname"):
        return idna.encode(value.rstrip("."), uts46=True, transitional=False, std3_rules=True).decode("ascii").lower()
    return value


def _matches(body, kind, value, limit):
    rows = body.get("observables")
    if not isinstance(rows, list) or len(rows) > limit:
        raise torq.TorqError("Torq returned an invalid observable page.")
    cursor = body.get("next_page_token")
    if cursor is not None and (not isinstance(cursor, str) or len(cursor) > 16384):
        raise torq.TorqError("Torq returned an invalid pagination token.")
    if cursor and not rows:
        raise torq.TorqError("Torq returned an incomplete observable page.")
    matches, seen = [], set()
    type_id, field = TYPE_MAP[kind]
    for row in rows:
        if (
            not isinstance(row, dict)
            or type(row.get("id")) is not int
            or row["id"] <= 0
            or row["id"] in seen
            or not isinstance(row.get("type"), dict)
            or not isinstance(row.get("value"), dict)
        ):
            raise torq.TorqError("Torq returned an invalid or duplicate observable.")
        seen.add(row["id"])
        if row["type"].get("id") != type_id:
            raise torq.TorqError("Torq returned observables outside the requested type filter.")
        if not isinstance(row["value"].get(field), str) or not row["value"][field]:
            raise torq.TorqError("Torq omitted the typed observable value.")
        if row.get("deleted_at"):
            continue
        try:
            if _normalize(kind, row["value"].get(field)) != value:
                continue
        except (ValueError, TypeError, UnicodeError):
            continue
        matches.append(row)
    return {
        "status": "found" if matches else "inconclusive" if cursor else "not_found",
        "matches": matches,
        "returned": len(matches),
        "candidates": len(rows),
        "discarded": len(rows) - len(matches),
        "truncated": bool(cursor),
    }


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise torq.TorqError("A JSON object is required.")
        source, config = request.get("attribute"), request.get("config")
        if not isinstance(source, dict) or source.get("type") not in TYPE_MAP:
            raise torq.TorqError("A supported observable attribute with a UUID is required.")
        UUID(source["uuid"])
        kind = source["type"]
        value = _normalize(kind, source.get("value"))
        if not isinstance(config, dict):
            raise torq.TorqError("Torq configuration is required.")
        limit = torq.integer(config.get("limit"), "limit", 20, 100)
        payload = {
            "filter": {"types": [{"id": TYPE_MAP[kind][0]}], "search": value},
            "page_size": limit,
            "order": "desc",
            "order_by": "last_seen",
        }
        with torq.Client(config) as client:
            body = client.post("/v1alpha/observables/query", payload)
            region = client.region
        report = {
            "provider": "Torq",
            "region": region,
            "query": value,
            "type": TYPE_MAP[kind][0],
            **_matches(body, kind, value, limit),
        }
        obj = MISPObject("annotation")
        obj.comment = "Torq observable lookup"
        obj.add_attribute("text", value=json.dumps(report, sort_keys=True), to_ids=False, disable_correlation=True)
        obj.add_reference(source["uuid"], "describes")
        event = MISPEvent()
        event.add_object(obj)
        result = {"results": {"Attribute": [source], "Object": json.loads(event.to_json())["Object"]}}
        if report["truncated"]:
            result["warnings"] = ["Torq search is incomplete; additional candidates may contain exact matches."]
        return result
    except torq.TorqError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return {"error": "Invalid Torq observable lookup request or response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
