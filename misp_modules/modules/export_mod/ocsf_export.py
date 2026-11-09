"""Export MISP indicators as OCSF OSINT Inventory Info events."""

import base64
import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "OCSF Export",
    "description": "Export event and object indicators as OCSF OSINT Inventory Info NDJSON.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Exports supported attributes from all supplied events as OCSF 1.9.0 OSINT Inventory Info events (5021)."
        " Includes typed observables, stable source-based IDs, object context, tags, TLP and modification times."
        " Only to_ids attributes are included by default; include_non_ids enables contextual attributes. Deleted"
        " data is excluded. No additional dependency or remote connection is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/ocsf_export.md)."
    ),
    "references": [
        "https://schema.ocsf.io/1.9.0/classes/osint_inventory_info",
        "https://github.com/ocsf/ocsf-schema/tree/1.9.0",
    ],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded UTF-8 OCSF NDJSON; skipped counts and warnings in the API response.",
}
moduleconfig = ["include_non_ids", "misp_url"]
OCSF_VERSION = "1.9.0"
# MISP type: (hex length, OCSF fingerprint algorithm ID).
HASH_TYPES = {
    "md5": (32, 1),
    "sha1": (40, 2),
    "sha224": (56, 8),
    "sha256": (64, 3),
    "sha384": (96, 9),
    "sha512": (128, 4),
}
# MISP type: (OSINT type ID, observable type ID).
SIMPLE_TYPES = {
    "ip-src": (1, 2),
    "ip-dst": (1, 2),
    "domain": (2, 1),
    "hostname": (3, 1),
    "url": (5, 6),
    "user-agent": (6, 16),
    "email-src": (9, 5),
    "email-dst": (9, 5),
    "filename": (11, 7),
    "regkey": (12, 46),
}
SUPPORTED_TYPES = (
    SIMPLE_TYPES.keys()
    | HASH_TYPES.keys()
    | {"domain|ip", "ip-src|port", "ip-dst|port", "hostname|port", "malware-sample"}
    | {f"filename|{kind}" for kind in HASH_TYPES}
)
TLP_ORDER = {"WHITE": 0, "CLEAR": 0, "GREEN": 1, "AMBER": 2, "AMBER+STRICT": 3, "RED": 4}


def _boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError(f"{name} must be true, false, 1 or 0.")


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _tags(*containers):
    names = set()
    for container in containers:
        for key in ("Tag", "EventTag", "AttributeTag"):
            for entry in _records(container, key):
                tag = entry.get("Tag", entry)
                if isinstance(tag, dict) and isinstance(tag.get("name"), str):
                    names.add(tag["name"])
    return sorted(names)


def _timestamp(value):
    if isinstance(value, bool):
        raise ValueError("Invalid timestamp.")
    if isinstance(value, (int, float)) or isinstance(value, str) and re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        parsed = datetime.fromtimestamp(float(value), timezone.utc)
    else:
        if not isinstance(value, str):
            raise ValueError("Invalid timestamp.")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Timestamps must have a timezone.")
    return int(parsed.timestamp() * 1000)


def _indicator(kind, value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Empty indicator.")
    if kind in HASH_TYPES:
        length, _ = HASH_TYPES[kind]
        if not re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", value):
            raise ValueError("Invalid hash.")
        value = value.lower()
        return {"type_id": 4, "value": value}, 8
    type_id, observable_id = SIMPLE_TYPES[kind]
    if kind in ("ip-src", "ip-dst"):
        if "%" in value:
            raise ValueError("Scoped IP addresses are not supported.")
        value = str(ipaddress.ip_address(value))
    elif kind == "url":
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError("URLs must be absolute and have a host.")
        parsed.port  # Validate a supplied port, even though the original URL is retained.
    indicator = {"type_id": type_id, "value": value}
    if kind == "filename":
        indicator["file"] = {"name": value, "type_id": 0}
    return indicator, observable_id


def _indicators(kind, value):
    if kind in SIMPLE_TYPES or kind in HASH_TYPES:
        return [_indicator(kind, value)], None
    if not isinstance(value, str):
        raise ValueError("Invalid composite indicator.")
    first, separator, second = value.rpartition("|")
    if not separator or not first.strip() or not second.strip():
        raise ValueError("Composite indicators require two non-empty components.")
    if kind == "domain|ip":
        if "|" in first:
            raise ValueError("Invalid domain|ip value.")
        return [_indicator("domain", first), _indicator("ip-dst", second)], None
    if kind.endswith("|port"):
        if not re.fullmatch(r"[0-9]+", second) or not 0 <= int(second) <= 65535:
            raise ValueError("Invalid port.")
        return [_indicator(kind.split("|")[0], first)], int(second)
    hash_type = "md5" if kind == "malware-sample" else kind.split("|")[1]
    indicator, observable_id = _indicator(hash_type, second)
    indicator["file"] = {
        "name": first,
        "type_id": 0,
        "hashes": [{"algorithm_id": HASH_TYPES[hash_type][1], "value": indicator["value"]}],
    }
    return [(indicator, observable_id)], None


def _selected(record, fields):
    return {key: record[key] for key in fields if key in record}


def _source_key(record, fallback):
    for key in ("uuid", "id"):
        if record.get(key):
            return [key, str(record[key])]
    return ["content", fallback]


def _documents(data, include_non_ids, misp_url, now, skipped):
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if _boolean(event.get("deleted"), "deleted"):
            continue
        collections = dict(event, **envelope)
        sources = [(attribute, {}) for attribute in _records(collections, "Attribute")]
        for obj in _records(collections, "Object"):
            if not _boolean(obj.get("deleted"), "deleted"):
                sources.extend((attribute, obj) for attribute in _records(obj, "Attribute"))
        for attribute, obj in sources:
            if _boolean(attribute.get("deleted"), "deleted"):
                continue
            to_ids = _boolean(attribute.get("to_ids"), "to_ids")
            if not include_non_ids and not to_ids:
                continue
            kind, value = attribute.get("type"), attribute.get("value")
            if not isinstance(kind, str) or kind not in SUPPORTED_TYPES:
                skipped["unsupported attribute(s)"] += 1
                continue
            try:
                indicators, port = _indicators(kind, value)
            except ValueError:
                skipped["malformed attribute(s)"] += 1
                continue
            source = [
                _source_key(event, event.get("info", "")),
                _source_key(obj, obj.get("name", "")),
                _source_key(attribute, [kind, value]),
            ]
            uid = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
            tags = _tags(event, envelope, obj, attribute)
            markings = [
                tag[4:].upper() for tag in tags if tag.lower().startswith("tlp:") and tag[4:].upper() in TLP_ORDER
            ]
            common = {"confidence_id": 0, "vendor_name": "MISP"}
            if tags:
                common["labels"] = tags
            if markings:
                # OCSF's enum uses a space, rather than '+', for AMBER+STRICT.
                common["tlp"] = max(markings, key=TLP_ORDER.get).replace("+", " ")
            if isinstance(attribute.get("comment"), str) and attribute["comment"]:
                common["comment"] = attribute["comment"]
            modified = attribute.get("timestamp")
            if modified is None or modified == "":
                modified = event.get("timestamp")
            if modified is not None and modified != "":
                try:
                    common["modified_time"] = _timestamp(modified)
                except (ValueError, TypeError, OverflowError, OSError):
                    skipped["invalid modification timestamp(s)"] += 1
            event_ref = event.get("uuid") or event.get("id")
            if misp_url and event_ref:
                common["src_url"] = f"{misp_url}/events/view/{quote(str(event_ref), safe='')}"
            provenance = {
                "event": _selected(
                    collections,
                    (
                        "uuid",
                        "id",
                        "info",
                        "date",
                        "timestamp",
                        "Orgc",
                        "distribution",
                        "sharing_group_id",
                        "threat_level_id",
                    ),
                ),
                "attribute": _selected(
                    attribute,
                    (
                        "uuid",
                        "id",
                        "type",
                        "value",
                        "category",
                        "comment",
                        "object_relation",
                        "timestamp",
                        "first_seen",
                        "last_seen",
                        "distribution",
                        "sharing_group_id",
                    ),
                ),
                "to_ids": to_ids,
            }
            if obj:
                provenance["object"] = _selected(obj, ("uuid", "id", "name", "meta-category"))
            observables, osint = [], []
            for position, (indicator, observable_id) in enumerate(indicators):
                indicator.update(common, uid=f"{uid}:{position}")
                if attribute.get("uuid") or attribute.get("id"):
                    indicator["external_uid"] = str(attribute.get("uuid") or attribute["id"])
                osint.append(indicator)
                observables.append(
                    {"name": f"osint[{position}].value", "type_id": observable_id, "value": indicator["value"]}
                )
            if port is not None:
                provenance["port"] = port
                observables.append({"name": "unmapped.misp.port", "type_id": 11, "value": str(port)})
            metadata = {
                "version": OCSF_VERSION,
                "product": {"name": "MISP", "vendor_name": "MISP"},
                "uid": uid,
                "processed_time": now,
            }
            if event_ref:
                metadata["original_event_uid"] = str(event_ref)
            yield uid, {
                "category_uid": 5,
                "class_uid": 5021,
                "activity_id": 2,
                "type_uid": 502102,
                "severity_id": 1,
                "time": now,
                "metadata": metadata,
                "osint": osint,
                "observables": observables,
                "unmapped": {"misp": provenance},
            }


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        data = request.get("data")
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            raise ValueError("data must be a list of MISP events.")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        include_non_ids = _boolean(config.get("include_non_ids"), "include_non_ids")
        misp_url = config.get("misp_url")
        if misp_url is None:
            misp_url = ""
        if not isinstance(misp_url, str):
            raise ValueError("misp_url must be an HTTP(S) base URL.")
        if misp_url:
            parsed = urlsplit(misp_url)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.query
                or parsed.fragment
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("misp_url must be an HTTP(S) base URL without credentials, query or fragment.")
            parsed.port
        skipped = Counter()
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        documents = dict(_documents(data, include_non_ids, misp_url.rstrip("/"), now, skipped))
        payload = "".join(json.dumps(document, ensure_ascii=False) + "\n" for document in documents.values())
    except (ValueError, TypeError) as exc:
        return {"error": f"OCSF export: {exc}"}
    response = {"response": [], "data": base64.b64encode(payload.encode("utf-8")).decode("ascii")}
    if skipped:
        response["warnings"] = [f"Skipped {count} {reason}." for reason, count in sorted(skipped.items())]
    return response


def introspection():
    return {
        "input": sorted(SUPPORTED_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "ndjson",
        "responseType": "application/x-ndjson",
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
