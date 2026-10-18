"""Export MISP indicators as ECS documents in Elasticsearch Bulk NDJSON format."""

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
    "name": "Elastic ECS Export",
    "description": "Export event and object indicators as ECS threat indicators in Elasticsearch Bulk NDJSON.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Exports all supplied events, including object attributes, to ECS 9.2 threat.indicator fields. Bulk index"
        " actions use stable source-based IDs. Only to_ids attributes are included by default; include_non_ids enables"
        " contextual attributes. Deleted data is excluded. Source UUIDs, object context, tags, observation times and"
        " TLP markings are preserved. No Elasticsearch connection is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/elastic_ecs_export.md) for the"
        " index template, import procedure, matching fields and lifecycle limitations."
    ),
    "references": [
        "https://www.elastic.co/docs/reference/ecs/ecs-threat",
        "https://github.com/elastic/ecs/blob/v9.2.0/schemas/threat.yml",
        "https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk",
    ],
    "input": "A list of MISP events in standard or legacy export format.",
    "output": "Base64-encoded Bulk NDJSON containing ECS indicator documents; optional API warnings.",
}
moduleconfig = ["index", "include_non_ids", "misp_url"]
ECS_VERSION = "9.2.0"
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}
SIMPLE_TYPES = {"ip-src", "ip-dst", "domain", "hostname", "url", "email-src", "email-dst", "filename", "AS"}
SUPPORTED_TYPES = (
    SIMPLE_TYPES
    | HASH_LENGTHS.keys()
    | {
        "domain|ip",
        "ip-src|port",
        "ip-dst|port",
        "hostname|port",
        "malware-sample",
        *(f"filename|{kind}" for kind in HASH_LENGTHS),
    }
)
TLP_ORDER = {"WHITE": 0, "CLEAR": 1, "GREEN": 2, "AMBER": 3, "AMBER+STRICT": 4, "RED": 5}


def _boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError(f"{name} must be true, false, 1 or 0.")


def _records(container, key):
    value = container.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{key} must be a list of objects.")
    return value


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
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _hash(kind, value):
    if not re.fullmatch(rf"[0-9a-fA-F]{{{HASH_LENGTHS[kind]}}}", value):
        raise ValueError("Invalid file hash.")
    return value.lower()


def _indicator(kind, value):
    if kind in ("ip-src", "ip-dst"):
        if "%" in value:
            raise ValueError("Scoped IP addresses are not supported by the ECS ip type.")
        address = ipaddress.ip_address(value)
        return {"type": f"ipv{address.version}-addr", "ip": str(address), "name": value}
    if kind in ("domain", "hostname"):
        return {"type": "domain-name", "url": {"domain": value}, "name": value}
    if kind in ("email-src", "email-dst"):
        return {"type": "email-addr", "email": {"address": value}, "name": value}
    if kind in HASH_LENGTHS:
        return {"type": "file", "file": {"hash": {kind: _hash(kind, value)}}, "name": value}
    if kind == "filename":
        return {"type": "file", "file": {"name": value}, "name": value}
    if kind == "AS":
        number = re.sub(r"^AS", "", value, flags=re.IGNORECASE)
        if not re.fullmatch(r"[0-9]+", number) or not 0 <= int(number) <= 4294967295:
            raise ValueError("Invalid autonomous system number.")
        return {"type": "autonomous-system", "as": {"number": int(number)}, "name": value}
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("URLs must be absolute and have a host.")
    url = {"full": value, "domain": parsed.hostname, "scheme": parsed.scheme}
    if parsed.port is not None:
        url["port"] = parsed.port
    return {"type": "url", "url": url, "name": value}


def _indicators(kind, value):
    if kind in SIMPLE_TYPES or kind in HASH_LENGTHS:
        return [_indicator(kind, value)]
    first, separator, second = value.rpartition("|")
    if not separator or not first.strip() or not second.strip():
        raise ValueError("Composite indicators require two non-empty components.")
    if kind == "domain|ip":
        if "|" in first:
            raise ValueError("Invalid domain|ip value.")
        return [_indicator("domain", first), _indicator("ip-dst", second)]
    if kind.endswith("|port"):
        if not re.fullmatch(r"[0-9]+", second) or not 0 <= int(second) <= 65535:
            raise ValueError("Invalid port.")
        result = _indicator(kind.split("|")[0], first)
        result["port"] = int(second)
        return [result]
    hash_type = "md5" if kind == "malware-sample" else kind.split("|")[1]
    result = _indicator(hash_type, second)
    result["file"]["name"] = first
    return [result]


def _source_key(record, fallback):
    for key in ("uuid", "id"):
        if record.get(key):
            return [key, str(record[key])]
    return ["content", fallback]


def _selected(record, fields):
    return {key: record[key] for key in fields if key in record}


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
        org = collections.get("Orgc", {})
        provider = org.get("name", "MISP") if isinstance(org, dict) else "MISP"
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
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("Empty indicator.")
                indicators = _indicators(kind, value)
            except ValueError:
                skipped["malformed attribute(s)"] += 1
                continue
            tags = _tags(event, envelope, obj, attribute)
            metadata = {"provider": provider, "confidence": "Not Specified"}
            for field, raw in (
                ("modified_at", attribute.get("timestamp", event.get("timestamp"))),
                ("first_seen", attribute.get("first_seen")),
                ("last_seen", attribute.get("last_seen")),
            ):
                if raw is not None and raw != "":
                    try:
                        metadata[field] = _timestamp(raw)
                    except (ValueError, TypeError, OverflowError, OSError):
                        skipped["invalid timestamp field(s)"] += 1
            markings = [
                tag[4:].upper() for tag in tags if tag.lower().startswith("tlp:") and tag[4:].upper() in TLP_ORDER
            ]
            if markings:
                tlp = max(markings, key=TLP_ORDER.get)
                metadata["marking"] = {"tlp": tlp}
                if tlp in ("CLEAR", "AMBER+STRICT", "WHITE"):
                    metadata["marking"]["tlp_version"] = "1.0" if tlp == "WHITE" else "2.0"
            if attribute.get("comment"):
                metadata["description"] = attribute["comment"]
            event_ref = event.get("uuid") or event.get("id")
            if misp_url and event_ref:
                metadata["reference"] = f"{misp_url}/events/view/{quote(str(event_ref), safe='')}"
            provenance = {
                "event": _selected(
                    event, ("uuid", "id", "info", "date", "timestamp", "distribution", "sharing_group_id")
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
            source = [
                _source_key(event, event.get("info", "")),
                _source_key(obj, obj.get("name", "")),
                _source_key(attribute, [kind, value]),
            ]
            for position, indicator in enumerate(indicators):
                document_id = hashlib.sha256(json.dumps([source, position], sort_keys=True).encode()).hexdigest()
                indicator.update(metadata, id=[str(attribute.get("uuid") or document_id)])
                document = {
                    "@timestamp": now,
                    "ecs": {"version": ECS_VERSION},
                    "event": {
                        "kind": "enrichment",
                        "category": ["threat"],
                        "type": ["indicator"],
                        "dataset": "misp.indicator",
                        "module": "misp",
                        "id": document_id,
                    },
                    "threat": {"indicator": indicator},
                    "misp": provenance,
                }
                if tags:
                    document["tags"] = tags
                yield document_id, document


def handler(q=False):
    if not q:
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
        index = config.get("index")
        if index is None or index == "":
            index = "misp-indicators"
        if not isinstance(index, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,254}", index):
            raise ValueError(
                "index must start with a lowercase letter or digit and contain only a-z, 0-9, dot, dash or underscore"
                " (max 255 characters)."
            )
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
        skipped = Counter()
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        documents = {}
        for document_id, document in _documents(data, include_non_ids, misp_url.rstrip("/"), now, skipped):
            documents[document_id] = document
        lines = []
        for document_id, document in documents.items():
            lines.extend(
                (json.dumps({"index": {"_index": index, "_id": document_id}}), json.dumps(document, ensure_ascii=False))
            )
        payload = ("\n".join(lines) + "\n") if lines else ""
    except (ValueError, TypeError) as exc:
        return {"error": f"Elastic ECS export: {exc}"}
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
