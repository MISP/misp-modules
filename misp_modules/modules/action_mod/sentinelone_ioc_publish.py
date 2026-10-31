"""Publish MISP indicators to SentinelOne's scoped Threat Intelligence API."""

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
    "name": "SentinelOne IOC Publish",
    "description": "Publish MISP event and object indicators to SentinelOne Threat Intelligence with explicit scope.",
    "module-type": ["action"],
    "logo": "",
    "requirements": ["requests", "SentinelOne Threat Intelligence.view and Threat Intelligence.manage permissions"],
    "features": (
        "Publishes IDS-marked hashes, domains, URLs and IP addresses from supplied events and objects. Requires account"
        " or site scope, uses stable external IDs, checks existing records, and supports expiry and dry runs. Existing"
        " records are not changed or deleted. Credentials and console URL come from the module server environment. See"
        " the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/sentinelone_ioc_publish.md)."
    ),
    "references": [
        "https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/mgmt-console-api/references/tags/Threat_Intelligence.md",
    ],
    "input": "MISP events in standard, bare or legacy format, supplied in workflow data.",
    "output": "Per-indicator publication outcomes and counts; errors signal incomplete publication.",
}
moduleconfig = {
    "params": {
        "scope": {"type": "string", "description": "Required: account or site"},
        "scope_id": {"type": "string", "description": "Required: the single SentinelOne account or site ID"},
        "source": {
            "type": "string",
            "description": "Stable source namespace, unique to this MISP publisher",
            "value": "misp-modules",
        },
        "expiration_days": {
            "type": "string",
            "description": "1-180 days; maximum 30 when publishing IP addresses",
            "value": "14",
        },
        "severity": {"type": "string", "description": "SentinelOne severity score, integer 0-7", "value": "4"},
        "dry_run": {
            "type": "string",
            "description": "true previews payloads without credentials or network access",
            "value": "false",
        },
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"
API_PATH = "/web/api/v2.1/threat-intelligence/iocs"
MAX_INDICATORS = 100
DEADLINE_SECONDS = 240
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
EMPTY_FILE_HASHES = {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
SUPPORTED_TYPES = (
    {"domain", "hostname", "url", "ip-src", "ip-dst", "domain|ip", "malware-sample"}
    | HASH_LENGTHS.keys()
    | {f"filename|{kind}" for kind in HASH_LENGTHS}
)


class PublishError(Exception):
    """Sanitized failure suitable for a workflow result."""


def _boolean(value):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError("dry_run must be true, false, 1 or 0.")


def _integer(value, name, default, maximum):
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,3}", str(value)):
        raise ValueError(f"{name} must be an integer.")
    number = int(value)
    if not (0 if name == "severity" else 1) <= number <= maximum:
        raise ValueError(f"{name} is outside its supported range.")
    return number


def _settings(params):
    if not isinstance(params, dict):
        raise ValueError("params must be an object.")
    scope, scope_id = params.get("scope"), params.get("scope_id")
    if scope not in ("account", "site"):
        raise ValueError("scope must be account or site.")
    if not isinstance(scope_id, str) or not re.fullmatch(r"[1-9][0-9]{17,19}", scope_id):
        raise ValueError("scope_id must be a single 18-20 digit account or site ID.")
    source = params.get("source")
    if source is None or source == "":
        source = "misp-modules"
    if not isinstance(source, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9 ._:/-]{0,63}", source):
        raise ValueError("source must be 1-64 ASCII letters, digits, spaces or ._:/- and start with a letter or digit.")
    return {
        "scope": scope,
        "scope_id": scope_id,
        "source": source,
        "days": _integer(params.get("expiration_days"), "expiration_days", 14, 180),
        "severity": _integer(params.get("severity"), "severity", 4, 7),
        "dry_run": _boolean(params.get("dry_run")),
    }


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _flag(value):
    # MISP serializes boolean attributes as booleans, 0/1, or equivalent strings.
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError("Invalid MISP boolean flag.")


def _atomic(kind, value):
    if kind in HASH_LENGTHS:
        if not re.fullmatch(rf"[0-9a-fA-F]{{{HASH_LENGTHS[kind]}}}", value) or value.lower() == EMPTY_FILE_HASHES[kind]:
            raise ValueError("Invalid file hash.")
        return kind.upper(), value.lower()
    if kind in ("ip-src", "ip-dst"):
        if "%" in value:
            raise ValueError("Scoped IPs are unsupported.")
        address = ipaddress.ip_address(value)
        return f"IPV{address.version}", str(address)
    if kind == "url":
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname or any(char.isspace() for char in value):
            raise ValueError("URL must be absolute with a host and no whitespace.")
        if parsed.port is not None and not 0 <= parsed.port <= 65535:
            raise ValueError("Invalid URL port.")
        return "URL", value
    domain = value.removesuffix(".").encode("idna").decode("ascii").lower()
    if len(domain) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")
    ):
        raise ValueError("Invalid DNS name.")
    return "DNS", domain


def _indicators(kind, value):
    if "|" not in kind and kind != "malware-sample":
        return [_atomic(kind, value)]
    first, separator, second = value.rpartition("|")
    if not separator or not first.strip() or not second.strip():
        raise ValueError("Invalid composite.")
    if kind == "domain|ip":
        return [_atomic("domain", first), _atomic("ip-dst", second)]
    return [_atomic("md5" if kind == "malware-sample" else kind.split("|")[1], second)]


def _collect(data, skipped):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(event, dict) for event in data):
        raise ValueError("data must contain an event or list of events.")
    indicators = {}
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if _flag(event.get("deleted")):
            continue
        collections = dict(event, **envelope)
        attributes = [(attribute, {}) for attribute in _records(collections, "Attribute")]
        for obj in _records(collections, "Object"):
            if not _flag(obj.get("deleted")):
                attributes.extend((attribute, obj) for attribute in _records(obj, "Attribute"))
        for attribute, obj in attributes:
            if _flag(attribute.get("deleted")) or not _flag(attribute.get("to_ids")):
                skipped["deleted or non-IDS"] += 1
                continue
            kind, value = attribute.get("type"), attribute.get("value")
            if not isinstance(kind, str) or kind not in SUPPORTED_TYPES:
                skipped["unsupported"] += 1
                continue
            try:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("Empty value.")
                atoms = _indicators(kind, value)
            except ValueError:
                skipped["malformed"] += 1
                continue
            ref = {
                "event": str(event.get("uuid") or event.get("id") or "unknown"),
                "attribute": str(attribute.get("uuid") or attribute.get("id") or "unknown"),
                "misp_type": kind,
            }
            if obj:
                ref["object"] = str(obj.get("uuid") or obj.get("id") or obj.get("name") or "unknown")
            for atom in atoms:
                refs = indicators.setdefault(atom, [])
                if ref not in refs:
                    refs.append(ref)
                if len(indicators) > MAX_INDICATORS:
                    raise ValueError(f"At most {MAX_INDICATORS} unique indicators are allowed; split the input.")
    return indicators


def _endpoint():
    base = os.getenv("SENTINELONE_URL", "")
    parsed = urlsplit(base)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(
            "SENTINELONE_URL must be an HTTPS console origin without credentials, path, query or fragment."
        )
    parsed.port  # Validate an explicitly supplied port without changing the origin.
    token = os.getenv("SENTINELONE_API_TOKEN", "")
    if not token or any(ord(char) < 32 or ord(char) == 127 for char in token):
        raise ValueError("SENTINELONE_API_TOKEN must be configured on the module server.")
    return base.rstrip("/") + API_PATH, token


def _request(session, endpoint, method, **kwargs):
    try:
        response = session.request(method, endpoint, timeout=15, allow_redirects=False, verify=True, **kwargs)
    except requests.RequestException:
        raise PublishError(
            f"{method} request failed; remote outcome may be unknown. Check SentinelOne before retrying."
        ) from None
    if not 200 <= response.status_code < 300:
        raise PublishError(f"{method}: SentinelOne HTTP {response.status_code}.")
    try:
        body = response.json()
    except ValueError:
        raise PublishError(f"{method}: invalid JSON response; remote outcome may be unknown.") from None
    if (
        not isinstance(body, dict)
        or body.get("errors")
        or body.get("warnings")
        or not isinstance(body.get("data"), list)
    ):
        raise PublishError(f"{method}: invalid response or API errors/warnings; remote outcome may be unknown.")
    return body


def _identity(record, item, settings):
    scope_id = record.get("scopeId")
    return (
        record.get("source") == item["source"]
        and record.get("externalId") == item["externalId"]
        and record.get("type") == item["type"]
        and record.get("value") == item["value"]
        and record.get("method") == "EQUALS"
        and record.get("scope") == settings["scope"]
        and scope_id in (settings["scope_id"], [settings["scope_id"]])
        and isinstance(record.get("uuid"), str)
        and bool(record["uuid"])
    )


def _publish(session, endpoint, item, settings, deadline):
    scope_key = "accountIds" if settings["scope"] == "account" else "siteIds"
    body = _request(
        session,
        endpoint,
        "GET",
        params={scope_key: settings["scope_id"], "tenant": "false", "externalId": item["externalId"], "limit": 2},
    )
    records = body["data"]
    pagination = body.get("pagination")
    if (
        not isinstance(pagination, dict)
        or type(pagination.get("totalItems")) is not int
        or pagination.get("nextCursor")
        or pagination["totalItems"] != len(records)
        or len(records) > 1
    ):
        raise PublishError("GET: incomplete or ambiguous lookup; no IOC submitted.")
    if records:
        record = records[0]
        if not isinstance(record, dict) or not _identity(record, item, settings):
            raise PublishError("GET: existing record does not match publisher identity and scope; no IOC submitted.")
        try:
            expiry = datetime.fromisoformat(record["validUntil"].replace("Z", "+00:00"))
            if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                raise ValueError("Expired IOC.")
        except (KeyError, TypeError, ValueError, AttributeError):
            raise PublishError(
                "Existing IOC expiry is invalid or elapsed; renew it in SentinelOne. No IOC submitted."
            ) from None
        return "existing", record["uuid"]
    if time.monotonic() >= deadline:
        raise PublishError("Publication time budget exceeded after lookup; no IOC submitted.")
    body = _request(
        session, endpoint, "POST", json={"filter": {scope_key: [settings["scope_id"]], "tenant": False}, "data": [item]}
    )
    records = body["data"]
    if len(records) != 1 or not isinstance(records[0], dict) or not _identity(records[0], item, settings):
        raise PublishError("POST: no unambiguous scoped acknowledgement; remote outcome may be unknown.")
    return "created", records[0]["uuid"]


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
        skipped = Counter()
        indicators = _collect(request.get("data"), skipped)
        if settings["days"] > 30 and any(kind in ("IPV4", "IPV6") for kind, _ in indicators):
            raise ValueError(
                "SentinelOne IP indicators permit at most 30 expiration_days; split mixed inputs if needed."
            )
    except (ValueError, TypeError) as exc:
        return {"error": f"SentinelOne IOC publish: {exc}"}
    summary = {
        "success": True,
        "dry_run": settings["dry_run"],
        "created": 0,
        "existing": 0,
        "failed": 0,
        "planned": 0,
        "skipped": dict(skipped),
        "items": [],
    }
    result = {"result_key": "sentinelone_ioc_publish", "data": summary}
    if not indicators:
        return result
    session = None
    if not settings["dry_run"]:
        try:
            endpoint, token = _endpoint()
        except ValueError:
            return {
                "error": (
                    "SentinelOne IOC publish: configure SENTINELONE_URL as a credential-free HTTPS console origin and"
                    " SENTINELONE_API_TOKEN on the module server."
                )
            }
        session = requests.Session()
        session.headers.update(
            {"Authorization": f"ApiToken {token}", "Accept": "application/json", "Content-Type": "application/json"}
        )
    now = datetime.now(timezone.utc)
    expiry = (now + timedelta(days=settings["days"])).isoformat(timespec="seconds").replace("+00:00", "Z")
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        for (kind, value), refs in indicators.items():
            external_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    json.dumps(
                        [
                            "misp-sentinelone-ioc-publish",
                            settings["scope"],
                            settings["scope_id"],
                            settings["source"],
                            kind,
                            value,
                        ]
                    ),
                )
            )
            item = {
                "type": kind,
                "value": value,
                "source": settings["source"],
                "externalId": external_id,
                "method": "EQUALS",
                "validUntil": expiry,
                "severity": settings["severity"],
                "name": f"MISP {kind} {external_id}",
                "description": ("MISP sources: " + "; ".join(f"{ref['event']}/{ref['attribute']}" for ref in refs))[
                    :500
                ],
            }
            outcome = {"type": kind, "value": value, "externalId": external_id, "sources": refs}
            if settings["dry_run"]:
                scope_key = "accountIds" if settings["scope"] == "account" else "siteIds"
                outcome.update(
                    status="planned",
                    payload={"filter": {scope_key: [settings["scope_id"]], "tenant": False}, "data": [item]},
                )
                summary["planned"] += 1
            else:
                try:
                    if time.monotonic() >= deadline:
                        raise PublishError("Publication time budget exceeded; indicator not attempted.")
                    status, identifier = _publish(session, endpoint, item, settings, deadline)
                    outcome.update(status=status, uuid=identifier)
                    summary[status] += 1
                except PublishError as exc:
                    outcome.update(status="failed", error=str(exc))
                    summary["failed"] += 1
                except Exception:
                    outcome.update(
                        status="failed",
                        error=(
                            "SentinelOne request failed; remote outcome may be unknown. Check SentinelOne before"
                            " retrying."
                        ),
                    )
                    summary["failed"] += 1
            summary["items"].append(outcome)
    finally:
        if session is not None:
            session.close()
    if summary["failed"]:
        summary["success"] = False
        result["error"] = (
            f"SentinelOne IOC publish: {summary['failed']} failed; {summary['created']} created and"
            f" {summary['existing']} existing unchanged. Publication may be partial."
        )
    return result


def introspection():
    return {"config": moduleconfig}


def version():
    return dict(moduleinfo, config=moduleconfig)
