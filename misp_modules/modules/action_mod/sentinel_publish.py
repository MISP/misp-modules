"""Publish MISP indicators directly to Microsoft Sentinel's STIX upload API."""

import ipaddress
import json
import os
import re
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import requests

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Microsoft Sentinel Publish",
    "description": "Publish MISP indicators directly to Microsoft Sentinel's STIX upload API with per-object results.",
    "module-type": ["action"],
    "logo": "",
    "requirements": ["requests", "Microsoft Sentinel Contributor at the target workspace"],
    "features": (
        "Converts IDS-marked event and object attributes into STIX 2.1 indicators and uploads batches of up to 100"
        " objects. Supports dry runs, explicit workspace selection, expiry and checked per-object results. Entra"
        " credentials come from the module server environment. No external script installation is required. See the"
        " [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/sentinel_publish.md)."
    ),
    "references": ["https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api"],
    "input": "MISP events and object attributes, including attribute UUIDs and Unix timestamps.",
    "output": "Upload counts and per-indicator outcomes; errors signal incomplete publication.",
}
moduleconfig = {
    "params": {
        "workspace_id": {"type": "string", "description": "Required: target Log Analytics workspace UUID"},
        "source": {"type": "string", "description": "Stable source-system namespace", "value": "misp-modules"},
        "expiration_days": {"type": "string", "description": "Days until indicator expiry (1-365)", "value": "30"},
        "confidence": {"type": "string", "description": "STIX confidence (0-100)", "value": "50"},
        "dry_run": {
            "type": "string",
            "description": "true previews STIX payloads without network access",
            "value": "false",
        },
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"
API_VERSION = "2024-02-01-preview"
UPLOAD_ORIGIN = "https://api.ti.sentinel.azure.com"
AUTH_ORIGIN = "https://login.microsoftonline.com"
SCOPE = "https://management.azure.com/.default"
MAX_INDICATORS = 1000
BATCH_SIZE = 100
MAX_BATCH_BYTES = 1024 * 1024
DEADLINE_SECONDS = 240
HASH_LENGTHS = {"md5": ("MD5", 32), "sha1": ("SHA-1", 40), "sha256": ("SHA-256", 64), "sha512": ("SHA-512", 128)}
EMAIL_TYPES = {"email", "email-src", "email-dst"}
SUPPORTED_TYPES = (
    {"domain", "hostname", "url", "ip-src", "ip-dst", "domain|ip", "malware-sample"}
    | EMAIL_TYPES
    | HASH_LENGTHS.keys()
    | {f"filename|{kind}" for kind in HASH_LENGTHS}
)
TLP_MARKINGS = {
    "tlp:white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "tlp:clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "tlp:green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "tlp:amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "tlp:red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


class PublishError(Exception):
    """An error safe to return without provider bodies or credential details."""


def _boolean(value):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError("Boolean values must be true, false, 1 or 0.")


def _uuid(value, name):
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a UUID string.")
    try:
        identifier = uuid.UUID(value)
    except ValueError:
        raise ValueError(f"{name} must be a UUID string.") from None
    if not identifier.int:
        raise ValueError(f"{name} must be a non-nil UUID.")
    return str(identifier)


def _integer(value, default, minimum, maximum, name):
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,3}", str(value)):
        raise ValueError(f"{name} must be an integer.")
    number = int(value)
    if not minimum <= number <= maximum:
        raise ValueError(f"{name} is outside its supported range.")
    return number


def _settings(params):
    if not isinstance(params, dict):
        raise ValueError("params must be an object.")
    source = params.get("source")
    if source is None or source == "":
        source = "misp-modules"
    if not isinstance(source, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9 ._:/-]{0,63}", source):
        raise ValueError("source must be 1-64 ASCII letters, digits, spaces or ._:/- and start with a letter or digit.")
    if source.lower().strip() == "microsoft sentinel":
        raise ValueError("The source-system name Microsoft Sentinel is reserved by the API.")
    return {
        "workspace_id": _uuid(params.get("workspace_id"), "workspace_id"),
        "source": source,
        "days": _integer(params.get("expiration_days"), 30, 1, 365, "expiration_days"),
        "confidence": _integer(params.get("confidence"), 50, 0, 100, "confidence"),
        "dry_run": _boolean(params.get("dry_run")),
    }


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _tags(*containers):
    names = set()
    for container in containers:
        for key in ("Tag", "EventTag", "AttributeTag"):
            for tag in _records(container, key):
                tag = tag.get("Tag", tag)
                if isinstance(tag, dict) and isinstance(tag.get("name"), str):
                    tag["name"].encode("utf-8")
                    if tag["name"]:
                        names.add(tag["name"])
    return names


def _domain(value):
    domain = value.removesuffix(".").encode("idna").decode("ascii").lower()
    if len(domain) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")
    ):
        raise ValueError("Invalid domain.")
    return domain


def _atomic(kind, value):
    value.encode("utf-8")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Control characters are unsupported.")
    if kind in HASH_LENGTHS:
        algorithm, length = HASH_LENGTHS[kind]
        if not re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", value):
            raise ValueError("Invalid hash.")
        return f"file:hashes.'{algorithm}'", value.lower()
    if kind in ("ip-src", "ip-dst"):
        if "%" in value:
            raise ValueError("Scoped IPv6 is unsupported.")
        address = ipaddress.ip_address(value)
        return f"ipv{address.version}-addr:value", str(address)
    if kind in ("domain", "hostname"):
        return "domain-name:value", _domain(value)
    if kind in EMAIL_TYPES:
        local, separator, domain = value.rpartition("@")
        if not separator or not re.fullmatch(r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
            raise ValueError("Unsupported email address.")
        return "email-addr:value", local + "@" + _domain(domain)
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or any(char.isspace() for char in value):
        raise ValueError("URL must be absolute HTTP(S) with a host and no whitespace.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credential-bearing URLs are unsupported.")
    parsed.port
    return "url:value", value


def _atoms(kind, value):
    if "|" not in kind and kind != "malware-sample":
        return [_atomic(kind, value)]
    first, separator, second = value.rpartition("|")
    if not separator or not first.strip() or not second.strip():
        raise ValueError("Invalid composite.")
    if kind == "domain|ip":
        return [_atomic("domain", first), _atomic("ip-dst", second)]
    return [_atomic("md5" if kind == "malware-sample" else kind.split("|")[1], second)]


def _stamp(value):
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _collect(data, settings, now):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(envelope, dict) for envelope in data):
        raise ValueError("data must contain an event or list of events.")
    indicators, skipped = {}, Counter()
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if _boolean(event.get("deleted")):
            continue
        collections = dict(event, **envelope)
        attributes = [(attribute, {}) for attribute in _records(collections, "Attribute")]
        for obj in _records(collections, "Object"):
            if not _boolean(obj.get("deleted")):
                attributes.extend((attribute, obj) for attribute in _records(obj, "Attribute"))
        for attribute, obj in attributes:
            if _boolean(attribute.get("deleted")) or not _boolean(attribute.get("to_ids")):
                skipped["deleted or non-IDS"] += 1
                continue
            kind, value = attribute.get("type"), attribute.get("value")
            if not isinstance(kind, str) or kind not in SUPPORTED_TYPES:
                skipped["unsupported"] += 1
                continue
            try:
                identifier = _uuid(attribute.get("uuid"), "attribute UUID")
                timestamp = attribute.get("timestamp")
                if isinstance(timestamp, bool) or not re.fullmatch(r"[0-9]{1,10}", str(timestamp)):
                    raise ValueError("Attribute timestamp must be Unix seconds.")
                created = datetime.fromtimestamp(int(timestamp), timezone.utc)
                if created > now:
                    raise ValueError("Attribute timestamp is in the future.")
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("Empty value.")
                atoms = _atoms(kind, value)
            except (ValueError, OverflowError, OSError):
                skipped["malformed value or identity/timestamp"] += 1
                continue
            labels = _tags(event, envelope, obj, attribute)
            ref = {
                "event": str(event.get("uuid") or event.get("id") or "unknown"),
                "attribute": identifier,
                "misp_type": kind,
            }
            if obj:
                ref["object"] = str(obj.get("uuid") or obj.get("id") or obj.get("name") or "unknown")
            for path, normalized in atoms:
                escaped = normalized.replace("\\", "\\\\").replace("'", "\\'")
                pattern = f"[{path} = '{escaped}']"
                stix_id = "indicator--" + str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        json.dumps(
                            [
                                "misp-sentinel-publish",
                                settings["workspace_id"],
                                settings["source"],
                                identifier,
                                str(int(timestamp)),
                                pattern,
                            ]
                        ),
                    )
                )
                entry = indicators.setdefault(
                    stix_id, {"pattern": pattern, "created": _stamp(created), "sources": [], "labels": set()}
                )
                if ref not in entry["sources"]:
                    entry["sources"].append(ref)
                entry["labels"].update(labels)
                if len(indicators) > MAX_INDICATORS:
                    raise ValueError(f"At most {MAX_INDICATORS} unique indicators are allowed; split the input.")
    objects, outcomes = [], []
    for identifier, entry in sorted(indicators.items()):
        refs = sorted(entry["sources"], key=lambda ref: json.dumps(ref, sort_keys=True))
        item = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": identifier,
            "created": entry["created"],
            "modified": _stamp(now),
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "pattern": entry["pattern"],
            "valid_from": entry["created"],
            "valid_until": _stamp(now + timedelta(days=settings["days"])),
            "confidence": settings["confidence"],
            "name": "MISP " + identifier,
            "description": json.dumps(refs, sort_keys=True),
            "external_references": [{"source_name": "MISP", "external_id": ref["attribute"]} for ref in refs],
        }
        if entry["labels"]:
            item["labels"] = sorted(entry["labels"])
        markings = {TLP_MARKINGS[label.lower()] for label in entry["labels"] if label.lower() in TLP_MARKINGS}
        if markings:
            item["object_marking_refs"] = sorted(markings)
        objects.append(item)
        outcomes.append({"id": identifier, "sources": refs})
    return objects, outcomes, dict(skipped)


def _request(session, endpoint, **kwargs):
    try:
        response = session.post(endpoint, timeout=15, verify=True, allow_redirects=False, **kwargs)
    except (requests.RequestException, OSError):
        raise PublishError("Request failed; remote outcome may be unknown. Check Sentinel before retrying.") from None
    if response.status_code != 200:
        raise PublishError(f"HTTP {response.status_code}; remote outcome may be unknown.")
    return response


def _authenticate(session):
    try:
        tenant = _uuid(os.getenv("SENTINEL_TENANT_ID"), "tenant ID")
        client = _uuid(os.getenv("SENTINEL_CLIENT_ID"), "client ID")
        secret = os.getenv("SENTINEL_CLIENT_SECRET", "")
        if not secret or any(ord(char) < 32 or ord(char) == 127 for char in secret):
            raise ValueError("Invalid client secret.")
    except ValueError:
        raise PublishError(
            "Configure SENTINEL_TENANT_ID, SENTINEL_CLIENT_ID and SENTINEL_CLIENT_SECRET on the module server."
        ) from None
    response = _request(
        session,
        f"{AUTH_ORIGIN}/{tenant}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client,
            "client_secret": secret,
            "scope": SCOPE,
        },
    )
    try:
        body = response.json()
        token = body["access_token"]
        if (
            body.get("token_type", "").lower() != "bearer"
            or not isinstance(token, str)
            or not token
            or any(not 33 <= ord(char) <= 126 for char in token)
            or type(body.get("expires_in")) is not int
            or body["expires_in"] <= DEADLINE_SECONDS + 15
        ):
            raise ValueError("Invalid token response.")
    except (ValueError, KeyError, TypeError, AttributeError):
        raise PublishError("Invalid or short-lived Entra token response; no indicators submitted.") from None
    session.headers.update({"Authorization": f"Bearer {token}"})


def _upload(session, endpoint, payload):
    response = _request(session, endpoint, params={"api-version": API_VERSION}, json=payload)
    if not response.content.strip():
        return set()
    try:
        body = response.json()
        if not isinstance(body, dict) or set(body) != {"errors"} or not isinstance(body["errors"], list):
            raise ValueError("Invalid response.")
        failures = set()
        for error in body["errors"]:
            index = error["recordIndex"]
            messages = error["errorMessages"]
            if (
                type(index) is not int
                or not 0 <= index < len(payload["stixobjects"])
                or index in failures
                or not isinstance(messages, list)
                or not messages
                or any(not isinstance(message, str) for message in messages)
            ):
                raise ValueError("Invalid per-object result.")
            failures.add(index)
        return failures
    except (ValueError, TypeError, KeyError):
        raise PublishError(
            "Invalid upload acknowledgement; remote outcome may be unknown. Check Sentinel before retrying."
        ) from None


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        if "filteredItems" in request or "matchingData" in request:
            raise ValueError("Workflow filters/extracted data are unsupported; supply selected events in data.")
        settings = _settings(request.get("params", {}))
        now = datetime.now(timezone.utc)
        objects, outcomes, skipped = _collect(request.get("data"), settings, now)
        batches = [
            {"sourcesystem": settings["source"], "stixobjects": objects[offset : offset + BATCH_SIZE]}
            for offset in range(0, len(objects), BATCH_SIZE)
        ]
        if any(len(json.dumps(batch).encode("utf-8")) > MAX_BATCH_BYTES for batch in batches):
            raise ValueError("A batch exceeds the local 1 MiB limit; split the input or reduce metadata.")
    except (ValueError, TypeError) as exc:
        return {"error": f"Sentinel publish: {exc}"}
    summary = {
        "success": True,
        "dry_run": settings["dry_run"],
        "workspace_id": settings["workspace_id"],
        "uploaded": 0,
        "failed": 0,
        "planned": 0,
        "skipped": skipped,
        "items": outcomes,
    }
    result = {"result_key": "sentinel_publish", "data": summary}
    if settings["dry_run"]:
        summary["planned"] = len(objects)
        summary["payloads"] = batches
        for item in outcomes:
            item["status"] = "planned"
        return result
    if not objects:
        return result
    endpoint = f"{UPLOAD_ORIGIN}/workspaces/{settings['workspace_id']}/threat-intelligence-stix-objects:upload"
    deadline = time.monotonic() + DEADLINE_SECONDS
    with requests.Session() as session:
        session.headers.update({"Accept": "application/json"})
        try:
            _authenticate(session)
        except PublishError as exc:
            summary["success"] = False
            result["error"] = f"Sentinel authentication: {exc}"
            for item in outcomes:
                item["status"] = "not_attempted"
            return result
        stopped = None
        for batch_index, batch in enumerate(batches):
            batch_items = outcomes[batch_index * BATCH_SIZE : (batch_index + 1) * BATCH_SIZE]
            try:
                if stopped is not None:
                    raise PublishError(stopped)
                if time.monotonic() >= deadline:
                    raise PublishError("Publication time budget exceeded; batch not attempted.")
                failures = _upload(session, endpoint, batch)
                for index, item in enumerate(batch_items):
                    if index in failures:
                        item.update(status="failed", error="Sentinel rejected this indicator.")
                        summary["failed"] += 1
                    else:
                        item["status"] = "uploaded"
                        summary["uploaded"] += 1
            except PublishError as exc:
                for item in batch_items:
                    item.update(status="failed", error=str(exc))
                    summary["failed"] += 1
                stopped = "Publication stopped after an uncertain or unsuccessful batch; batch not attempted."
    if summary["failed"]:
        summary["success"] = False
        result["error"] = (
            f"Sentinel publish: {summary['failed']} failed; {summary['uploaded']} uploaded. Publication may be partial."
        )
    return result


def introspection():
    return {"config": moduleconfig}


def version():
    return dict(moduleinfo, config=moduleconfig)
