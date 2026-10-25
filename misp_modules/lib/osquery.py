"""Build osquery packs from MISP indicators without accessing hosts or the network."""

import hashlib
import ipaddress
import json
import re
from collections import Counter

from misp_modules.lib.indicator_list import boolean

WINDOWS_TYPES = {
    "regkey",
    "regkey|value",
    "mutex",
    "windows-service-displayname",
    "windows-scheduled-task",
    "windows-service-name",
    "named pipe",
    "domain",
}
INPUT_TYPES = WINDOWS_TYPES | {"yara", "ip-dst", "ip-src", "filename", "sha256"}
MAX_QUERIES = 1000


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def _registry(value):
    root, separator, rest = value.partition("\\")
    aliases = {
        "HKLM": "HKEY_LOCAL_MACHINE",
        "HKU": "HKEY_USERS",
        "HKCR": "HKEY_CLASSES_ROOT",
        "HKCC": "HKEY_CURRENT_CONFIG",
    }
    if root.upper() in ("HKCU", "HKEY_CURRENT_USER"):
        # Enumerate loaded user hives, then constrain each target key by equality.
        # LIKE ESCAPE cannot be relied on for virtual-table glob expansion.
        suffix = literal(separator + rest)
        return f"key IN (SELECT path || {suffix} FROM registry WHERE key = 'HKEY_USERS' AND type = 'subkey')"
    key = aliases.get(root.upper(), root) + separator + rest
    return f"key = {literal(key)}"


def _scope(value):
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        raise ValueError("scan_path must be an absolute osquery path pattern.")
    if not (value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value)):
        raise ValueError("scan_path must be an absolute osquery path pattern.")
    return value


def query(kind, value, scan_path=""):
    """Return SQL and a platform selector; indicator values are literal matches."""
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError("Empty or invalid value.")
    if kind != "yara" and any(ord(c) < 32 for c in value):
        raise ValueError("Control characters are unsupported.")
    platform = "windows" if kind in WINDOWS_TYPES else "all"
    quoted = literal(value)
    simple = {
        "mutex": ("winbaseobj", "object_name"),
        "windows-service-displayname": ("services", "display_name"),
        "windows-service-name": ("services", "name"),
        "windows-scheduled-task": ("scheduled_tasks", "name"),
        "named pipe": ("pipes", "name"),
        "domain": ("dns_cache", "name"),
    }
    if kind in simple:
        table, column = simple[kind]
        collation = " COLLATE NOCASE" if kind == "domain" else ""
        extra = " AND object_type = 'Mutant'" if kind == "mutex" else ""
        return f"SELECT * FROM {table} WHERE {column} = {quoted}{collation}{extra};", platform
    if kind in ("regkey", "regkey|value"):
        key, separator, data = value.partition("|") if kind == "regkey|value" else (value, "", "")
        if kind == "regkey|value" and (not separator or not key):
            raise ValueError("regkey|value requires a key and data separated by |.")
        extra = f" AND data = {literal(data)}" if separator else ""
        return f"SELECT * FROM registry WHERE {_registry(key)}{extra};", platform
    if kind in ("ip-src", "ip-dst"):
        address = str(ipaddress.ip_address(value))
        column = "local_address" if kind == "ip-src" else "remote_address"
        return f"SELECT * FROM process_open_sockets WHERE {column} = {literal(address)};", platform
    if kind == "filename" and (
        value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith("\\\\")
    ):
        platform = "posix" if value.startswith("/") else "windows"
        return f"SELECT * FROM file WHERE path = {quoted};", platform
    if not scan_path:
        raise ValueError("scan_path required for file scans.")
    platform = "posix" if scan_path.startswith("/") else "windows"
    scope = f"file.path LIKE {literal(scan_path)}"
    if kind == "filename":
        return f"SELECT * FROM file WHERE {scope} AND filename = {quoted};", platform
    if kind == "sha256":
        if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
            raise ValueError("Invalid SHA-256.")
        return (
            (
                "SELECT file.path, hash.sha256 FROM file JOIN hash ON file.path = hash.path "
                f"WHERE {scope} AND file.type = 'regular' AND hash.sha256 = {literal(value.lower())};"
            ),
            platform,
        )
    if kind == "yara":
        return (
            (
                "SELECT file.path, yara_file.matches, yara_file.count FROM file JOIN yara_file ON file.path ="
                f" yara_file.path WHERE {scope} AND file.type = 'regular' AND file.size < 8000000 AND yara_file.sigrule"
                f" = {quoted} AND yara_file.count > 0;"
            ),
            platform,
        )
    raise ValueError("Unsupported indicator type.")


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def build(data, config=None):
    config = {} if config is None else config
    if not isinstance(config, dict):
        raise ValueError("Configuration must be an object.")
    interval = config.get("interval")
    interval = 3600 if interval is None or interval == "" else interval
    if isinstance(interval, bool) or not re.fullmatch(r"[0-9]+", str(interval)) or not 1 <= int(interval) <= 604800:
        raise ValueError("interval must be an integer from 1 to 604800 seconds.")
    scan_path = _scope(config.get("scan_path"))
    include_non_ids = boolean(config.get("include_non_ids"), "include_non_ids")
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ValueError("data must contain an event or list of events.")
    queries, sources, skipped = {}, {}, Counter()
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if boolean(event.get("deleted"), "deleted"):
            continue
        collections = dict(event, **envelope)
        attributes = [(attr, {}) for attr in _records(collections, "Attribute")]
        for obj in _records(collections, "Object"):
            if not boolean(obj.get("deleted"), "deleted"):
                attributes.extend((attr, obj) for attr in _records(obj, "Attribute"))
        for attr, obj in attributes:
            if boolean(attr.get("deleted"), "deleted") or (
                not include_non_ids and not boolean(attr.get("to_ids"), "to_ids")
            ):
                skipped["deleted or non-IDS"] += 1
                continue
            kind = attr.get("type")
            if not isinstance(kind, str) or kind not in INPUT_TYPES:
                skipped["unsupported"] += 1
                continue
            try:
                sql, platform = query(kind, attr.get("value"), scan_path)
            except ValueError as exc:
                skipped[str(exc)] += 1
                continue
            name = "misp_" + hashlib.sha256((kind + "\x00" + sql).encode()).hexdigest()
            queries[name] = {"query": sql, "interval": int(interval), "platform": platform, "removed": False}
            if kind == "yara":
                queries[name]["version"] = "5.24.0"
            ref = {
                "event": str(event.get("uuid") or event.get("id") or "unknown"),
                "attribute": str(attr.get("uuid") or attr.get("id") or "unknown"),
                "misp_type": kind,
            }
            if obj:
                ref["object"] = str(obj.get("uuid") or obj.get("id") or obj.get("name") or "unknown")
            if ref not in sources.setdefault(name, []):
                sources[name].append(ref)
            if len(queries) > MAX_QUERIES:
                raise ValueError(f"At most {MAX_QUERIES} queries are allowed; split the input.")
    pack = {"queries": dict(sorted(queries.items()))}
    summary = {"queries": len(queries), "skipped": dict(skipped)}
    return pack, summary, sources


def serialize(pack):
    return (json.dumps(pack, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")
