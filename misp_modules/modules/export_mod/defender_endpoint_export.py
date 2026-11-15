"""Export bounded, independently executable Microsoft Defender hunting queries."""

import base64
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

import idna

from misp_modules.lib.indicator_list import boolean

types_to_use = ["sha256", "sha1", "md5", "domain", "ip-src", "ip-dst", "url"]
moduleconfig = ["Period", "start_time", "end_time", "domain_mode", "tables", "batch_size"]
userConfig = {}
inputSource = ["event"]
outputFileExtension = "kql"
responseType = "application/txt"
moduleinfo = {
    "version": "2.0",
    "author": "Julien Bachmann, Hacknowledge, Maik Wuerth",
    "description": "Validated, table-specific Defender hunting queries with bounded indicator batches",
    "module-type": ["export"],
    "name": "Microsoft Defender for Endpoint KQL Export",
    "logo": "defender_endpoing.png",
    "requirements": [],
    "features": (
        "Exports active event and object indicators as independently executable KQL batches. Validates and escapes"
        " literals, applies a time range to every table, and distinguishes exact URL matches from domain host matches."
        " Defaults: 7d, exact domains, Endpoint and AlertEvidence tables, 100 indicators per batch. See the module"
        " guide for table selection, subdomains and absolute time ranges."
    ),
    "references": [
        "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables",
        "https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/defender_endpoint_export.md",
    ],
    "input": "MISP event and object attributes",
    "output": "One independently executable KQL query per line in a .kql file",
}

MAX_INDICATORS = 10000
MAX_QUERY_BYTES = 65536
MAX_VALUE_BYTES = 8192
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
# Only fields documented in each table's Advanced Hunting schema are queried.
FILE_HASHES = {kind: (kind.upper(), f"InitiatingProcess{kind.upper()}") for kind in HASH_LENGTHS}
PROCESS_HASHES = {kind: (f"InitiatingProcess{kind.upper()}",) for kind in HASH_LENGTHS}
TABLE_FIELDS = {
    "DeviceEvents": {
        **FILE_HASHES,
        "url": ("RemoteUrl", "FileOriginUrl"),
        "ip-src": ("LocalIP",),
        "ip-dst": ("RemoteIP", "FileOriginIP"),
    },
    "DeviceFileEvents": {**FILE_HASHES, "url": ("FileOriginUrl", "FileOriginReferrerUrl"), "ip-dst": ("FileOriginIP",)},
    "DeviceImageLoadEvents": FILE_HASHES,
    "DeviceProcessEvents": FILE_HASHES,
    "DeviceNetworkEvents": {**PROCESS_HASHES, "url": ("RemoteUrl",), "ip-src": ("LocalIP",), "ip-dst": ("RemoteIP",)},
    "AlertEvidence": {
        "sha1": ("SHA1",),
        "sha256": ("SHA256",),
        "url": ("RemoteUrl",),
        "ip-src": ("LocalIP",),
        "ip-dst": ("RemoteIP",),
    },
    "EmailUrlInfo": {"url": ("Url",)},
    "UrlClickEvents": {"url": ("Url",), "ip-src": ("IPAddress",)},
}
DEFAULT_TABLES = tuple(TABLE_FIELDS)[:6]


def _literal(value):
    """KQL regular string literals escape both backslashes and single quotes."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _domain(value):
    return idna.encode(value.removesuffix("."), uts46=True, std3_rules=True).decode("ascii").lower()


def _indicator(kind, value):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_VALUE_BYTES:
        raise ValueError("Indicator must be a nonempty string of at most 8192 UTF-8 bytes.")
    if any(ord(char) < 32 or ord(char) == 127 or char in "\u2028\u2029" for char in value):
        raise ValueError("Control characters and line separators are unsupported.")
    if kind in HASH_LENGTHS:
        if not re.fullmatch(rf"[a-fA-F0-9]{{{HASH_LENGTHS[kind]}}}", value):
            raise ValueError("Invalid hash.")
        return value.lower()
    if kind in ("ip-src", "ip-dst"):
        if "%" in value:
            raise ValueError("Scoped IP addresses are unsupported.")
        return str(ipaddress.ip_address(value))
    if kind == "domain":
        return _domain(value)
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname or any(char.isspace() for char in value):
        raise ValueError("URL must be absolute, have a host, and contain no whitespace.")
    parsed.port  # Validate the port without rewriting the exact URL indicator.
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        _domain(parsed.hostname)
    return value


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _collect(data):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ValueError("data must be an event or list of events.")
    indicators, skipped = set(), Counter()
    for envelope in data:
        if boolean(envelope.get("deleted"), "deleted"):
            skipped["deleted events"] += 1
            continue
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if boolean(event.get("deleted"), "deleted"):
            skipped["deleted events"] += 1
            continue
        # Accept nested MISP JSON and legacy exports with sibling collections.
        for container in [event] if event is envelope else [event, envelope]:
            attributes = list(_records(container, "Attribute"))
            for obj in _records(container, "Object"):
                if boolean(obj.get("deleted"), "deleted"):
                    skipped["deleted objects"] += 1
                else:
                    attributes.extend(_records(obj, "Attribute"))
            for attribute in attributes:
                if boolean(attribute.get("deleted"), "deleted"):
                    skipped["deleted attributes"] += 1
                    continue
                kind = attribute.get("type")
                if not isinstance(kind, str) or kind not in types_to_use:
                    skipped["unsupported attributes"] += 1
                    continue
                try:
                    value = _indicator(kind, attribute.get("value"))
                except (ValueError, UnicodeError):
                    skipped["invalid indicators"] += 1
                    continue
                indicators.add((kind, value))
                if len(indicators) > MAX_INDICATORS:
                    raise ValueError(f"At most {MAX_INDICATORS} unique indicators are allowed; split the input.")
    return sorted(indicators), dict(skipped)


def _instant(value, name):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-][0-2][0-9]:[0-5][0-9])", value
    ):
        raise ValueError(f"{name} must be an ISO 8601 timestamp with seconds and an explicit timezone.")
    result = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    return result


def _options(config):
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    start, end = config.get("start_time"), config.get("end_time")
    period = config.get("Period")
    if start not in (None, "") or end not in (None, ""):
        if period not in (None, ""):
            raise ValueError("Use Period or start_time/end_time, not both.")
        start, end = _instant(start, "start_time"), _instant(end, "end_time")
        if not 0 < (end - start).total_seconds() <= 30 * 86400:
            raise ValueError("The time range must be positive and at most 30 days.")
        start = f"datetime({start.isoformat()})"
        end = f"datetime({end.isoformat()})"
    else:
        period = "7d" if period in (None, "") else period
        match = re.fullmatch(r"([1-9][0-9]{0,6})([dhms])", period) if isinstance(period, str) else None
        if not match or int(match[1]) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[match[2]] > 30 * 86400:
            raise ValueError("Period must be a positive integer with d/h/m/s units, at most 30d (default 7d).")
        start, end = f"ago({period})", "now()"
    mode = config.get("domain_mode")
    mode = "exact" if mode in (None, "") else mode
    if mode not in ("exact", "subdomains"):
        raise ValueError("domain_mode must be exact or subdomains (includes the apex domain).")
    tables = config.get("tables")
    tables = DEFAULT_TABLES if tables in (None, "") else tables
    if isinstance(tables, str):
        tables = [table.strip() for table in tables.split(",")]
    if (
        not isinstance(tables, (list, tuple))
        or not tables
        or any(not isinstance(table, str) or table not in TABLE_FIELDS for table in tables)
    ):
        raise ValueError("tables must select documented tables: " + ", ".join(TABLE_FIELDS))
    tables = tuple(table for table in TABLE_FIELDS if table in tables)
    size = config.get("batch_size")
    size = 100 if size in (None, "") else size
    if isinstance(size, bool) or not re.fullmatch(r"[1-9][0-9]{0,2}", str(size)) or int(size) > 500:
        raise ValueError("batch_size must be an integer between 1 and 500 (default 100).")
    return start, end, mode, tables, int(size)


def _query(indicators, options):
    start, end, mode, tables, _ = options
    values = {kind: [value for item_kind, value in indicators if item_kind == kind] for kind in types_to_use}
    definitions = [f"let MISP_Start = {start};", f"let MISP_End = {end};"]
    for kind, items in values.items():
        if items:
            definitions.append(f"let MISP_{kind.replace('-', '_')} = dynamic({json.dumps(items, ensure_ascii=True)});")
    if values["domain"]:
        definitions.append(
            'let MISP_Host = (value:string) { tolower(trim_end(@"\\.$", tostring(parse_url('
            'iff(value startswith "//", strcat("https:", value), '
            'iff(value matches regex @"^[A-Za-z][A-Za-z0-9+.-]*://", value, strcat("https://", value)))).Host))) };'
        )
        if mode == "subdomains":
            pattern = r"(^|\.)(" + "|".join(re.escape(value) for value in values["domain"]) + ")$"
            definitions.append(f"let MISP_DomainPattern = {_literal(pattern)};")
    branches = []
    for table in tables:
        predicates = []
        for kind, items in values.items():
            if not items:
                continue
            fields = TABLE_FIELDS[table].get("url" if kind == "domain" else kind, ())
            for field in fields:
                if kind == "domain":
                    predicates.append(
                        f"MISP_Host({field}) in (MISP_domain)"
                        if mode == "exact"
                        else f"MISP_Host({field}) matches regex MISP_DomainPattern"
                    )
                elif kind in ("ip-src", "ip-dst"):
                    ipv4 = [value for value in items if ":" not in value]
                    if ipv4:
                        predicates.append(f"{field} in ({', '.join(_literal(value) for value in ipv4)})")
                    predicates.extend(f"ipv6_is_match({field}, {_literal(value)})" for value in items if ":" in value)
                else:
                    operator = "in~" if kind in HASH_LENGTHS else "in"
                    predicates.append(f"{field} {operator} (MISP_{kind})")
        if predicates:
            branches.append(
                f"({table} | where Timestamp between (MISP_Start .. MISP_End) | where ({' or '.join(predicates)}))"
            )
    return " ".join(definitions) + " union withsource=MISP_SourceTable " + ", ".join(branches)


def _batches(indicators, options):
    batches, pending = [], []
    for indicator in indicators:
        candidate = pending + [indicator]
        query = _query(candidate, options)
        if len(candidate) > options[4] or len(query.encode("utf-8")) > MAX_QUERY_BYTES:
            if not pending:
                raise ValueError(
                    "An indicator exceeds the maximum generated query size; shorten the value or select fewer tables."
                )
            batches.append(_query(pending, options))
            pending = [indicator]
            if len(_query(pending, options).encode("utf-8")) > MAX_QUERY_BYTES:
                raise ValueError(
                    "An indicator exceeds the maximum generated query size; shorten the value or select fewer tables."
                )
        else:
            pending = candidate
    if pending:
        batches.append(_query(pending, options))
    return batches


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        options = _options(request.get("config", {}))
        indicators, skipped = _collect(request.get("data"))
        # Report indicators that cannot be matched in the selected tables rather than exporting empty unions.
        supported = {kind for table in options[3] for kind in TABLE_FIELDS[table]}
        if "url" in supported:
            supported.add("domain")
        usable = [indicator for indicator in indicators if indicator[0] in supported]
        if len(usable) != len(indicators):
            skipped["unmapped indicators"] = len(indicators) - len(usable)
        queries = _batches(usable, options)
        output = "\n".join(queries) + ("\n" if queries else "")
        return {
            "response": [],
            "data": base64.b64encode(output.encode("utf-8")).decode("ascii"),
            "summary": {"indicators": len(usable), "queries": len(queries), "skipped": skipped},
        }
    except (ValueError, TypeError, OverflowError) as error:
        return {"error": str(error)}


def introspection():
    return {
        "responseType": responseType,
        "userConfig": userConfig,
        "outputFileExtension": outputFileExtension,
        "inputSource": inputSource,
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
