"""Read verified indicator values and merged File hashes from Cortex XSOAR 8."""

import ipaddress
import json
import re
from uuid import UUID

import idna
from pymisp import MISPEvent, MISPObject

from misp_modules.lib import cortex_xsoar as xsoar

TYPE_MAP = {
    "domain": "Domain",
    "hostname": "Domain",
    "md5": "File",
    "sha1": "File",
    "sha256": "File",
    "sha512": "File",
    "url": "URL",
    "email": "Email",
    "email-src": "Email",
    "email-dst": "Email",
    "vulnerability": "CVE",
    "ip-src": "IP",
    "ip-dst": "IP",
}
HASH_TYPES = {"md5": "File MD5", "sha1": "File SHA-1", "sha256": "File SHA-256", "sha512": "File SHA-512"}
mispattributes = {"input": list(TYPE_MAP), "format": "misp_standard"}
moduleconfig = ["url", "api_key", "api_key_id", "auth_type", "limit", "timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Cortex XSOAR Indicator Lookup",
    "logo": "",
    "description": (
        "Look up a MISP observable in Cortex XSOAR 8's indicator store with reputation and expiration metadata."
    ),
    "module-type": ["expansion", "hover"],
    "data-source": "external",
    "requirements": ["Cortex XSOAR 8 API credentials with permission to search indicators."],
    "features": (
        "Uses /xsoar/public/v1/indicators/search with escaped value/type queries and local identity checks,"
        " including merged File hash fields and legacy hash indicator types."
        " Supports Standard/Advanced API keys, bounded results, multi-account error checks and a referenced"
        " non-IDS annotation. This searches XSOAR indicators rather than XDR IOC rules. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/expansion/cortex_xsoar_indicator_lookup.md."
    ),
    "references": [xsoar.OVERVIEW, xsoar.AUTH_REFERENCE, xsoar.INDICATOR_REFERENCE],
    "input": "Hash, domain/hostname, IP, URL, email or CVE attribute with a UUID.",
    "output": "Original attribute and referenced non-IDS annotation with verified indicators and completeness.",
}


def _normalize(kind, value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or value != value.strip()
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("Invalid observable value")
    value.encode("utf-8")
    if kind in ("ip-src", "ip-dst"):
        address = ipaddress.ip_address(value)
        if getattr(address, "scope_id", None):
            raise ValueError("Scoped IP addresses are unsupported")
        return str(address), "IPv6" if address.version == 6 else "IP"
    if kind in ("md5", "sha1", "sha256", "sha512"):
        if not re.fullmatch(r"[0-9a-fA-F]{%d}" % {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}[kind], value):
            raise ValueError("Invalid hash")
        value = value.lower()
    elif kind in ("domain", "hostname"):
        value = idna.encode(value.rstrip("."), uts46=True, transitional=False, std3_rules=True).decode("ascii").lower()
    elif kind == "vulnerability":
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value, re.I):
            raise ValueError("A CVE identifier is required")
        value = value.upper()
    return value, TYPE_MAP[kind]


def _literal(value):
    return '"' + re.sub(r'([+\-=&|><!(){}\[\]^"~*?:\\/])', r"\\\1", value) + '"'


def _query(kind, value, native_type):
    if kind in HASH_TYPES:
        types = "(type:" + _literal("File") + " OR type:" + _literal(HASH_TYPES[kind]) + ")"
        return types + " AND (value:" + _literal(value) + " OR " + kind + ":" + _literal(value) + ")"
    return "value:" + _literal(value) + " AND type:" + _literal(native_type)


def _matches(body, kind, value, native_type, limit):
    rows, total = body.get("iocObjects"), body.get("total")
    account_errors = body.get("accountErrors", [])
    if account_errors is None:
        account_errors = []
    if not isinstance(account_errors, list) or account_errors:
        raise xsoar.XsoarError("Cortex XSOAR reported account search errors; results are incomplete.")
    if "iocObjects" in body and rows is None and type(total) is int and total == 0:
        rows = []
    if (
        not isinstance(rows, list)
        or len(rows) > limit
        or type(total) is not int
        or total < len(rows)
        or (total > 0 and not rows)
    ):
        raise xsoar.XsoarError("Cortex XSOAR returned an invalid or incomplete indicator page.")
    matches, seen = [], set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("id"), str)
            or not row["id"]
            or not isinstance(row.get("value"), str)
            or not isinstance(row.get("indicator_type"), str)
            or not isinstance(row.get("account", ""), str)
        ):
            raise xsoar.XsoarError("Cortex XSOAR returned an invalid indicator identity.")
        identity = (row.get("account", ""), row["id"])
        if identity in seen:
            raise xsoar.XsoarError("Cortex XSOAR returned duplicate indicator identities.")
        seen.add(identity)
        allowed_types = {native_type, HASH_TYPES[kind]} if kind in HASH_TYPES else {native_type}
        if row["indicator_type"] not in allowed_types:
            continue
        values = [("value", row["value"])]
        if kind in HASH_TYPES:
            fields = row.get("CustomFields")
            if fields is None:
                fields = {}
            if not isinstance(fields, dict):
                raise xsoar.XsoarError("Cortex XSOAR returned invalid File fields.")
            hashes = fields.get(kind)
            if hashes is not None:
                hashes = hashes if isinstance(hashes, list) else [hashes]
                if any(not isinstance(item, str) for item in hashes):
                    raise xsoar.XsoarError("Cortex XSOAR returned an invalid File hash field.")
                values.extend(("CustomFields." + kind, item) for item in hashes)
        matched_fields = []
        for field, candidate in values:
            try:
                if _normalize(kind, candidate) == (value, native_type):
                    matched_fields.append(field)
            except (ValueError, TypeError, UnicodeError):
                continue
        if not matched_fields:
            continue
        matches.append(
            {
                "matched_fields": sorted(set(matched_fields)),
                **{
                    key: row[key]
                    for key in (
                        "id",
                        "account",
                        "value",
                        "indicator_type",
                        "score",
                        "source",
                        "sourceBrands",
                        "firstSeen",
                        "lastSeen",
                        "expiration",
                        "expirationStatus",
                        "isDetectable",
                        "isPreventable",
                        "investigationIDs",
                        "CustomFields",
                    )
                    if key in row
                },
            }
        )
    truncated = total > len(rows)
    return {
        "status": "found" if matches else "inconclusive" if truncated else "not_found",
        "matches": matches,
        "returned": len(matches),
        "candidates": len(rows),
        "total_candidates": total,
        "discarded": len(rows) - len(matches),
        "truncated": truncated,
    }


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise xsoar.XsoarError("A JSON object is required.")
        source, config = request.get("attribute"), request.get("config")
        if not isinstance(source, dict) or source.get("type") not in TYPE_MAP:
            raise xsoar.XsoarError("A supported attribute with a UUID is required.")
        UUID(source["uuid"])
        value, native_type = _normalize(source["type"], source.get("value"))
        if not isinstance(config, dict):
            raise xsoar.XsoarError("Cortex XSOAR configuration is required.")
        limit = xsoar.integer(config.get("limit"), "limit", 20, 100)
        query = _query(source["type"], value, native_type)
        with xsoar.Client(config) as client:
            _, body = client.post("search", {"query": query, "size": limit})
        report = {
            "provider": "Cortex XSOAR",
            "query": value,
            "indicator_type": native_type,
            **_matches(body, source["type"], value, native_type, limit),
        }
        obj = MISPObject("annotation")
        obj.comment = "Cortex XSOAR indicator lookup"
        obj.add_attribute("text", value=json.dumps(report, sort_keys=True), to_ids=False, disable_correlation=True)
        obj.add_reference(source["uuid"], "describes")
        event = MISPEvent()
        event.add_object(obj)
        result = {"results": {"Attribute": [source], "Object": json.loads(event.to_json())["Object"]}}
        if report["truncated"]:
            result["warnings"] = [
                "XSOAR indicator search is incomplete; additional candidates may contain exact matches."
            ]
        return result
    except xsoar.XsoarError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return {"error": "Invalid Cortex XSOAR indicator lookup request or response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
