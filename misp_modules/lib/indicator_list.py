"""Shared, network-free collection of normalized MISP indicators for typed lists."""

import ipaddress
import re
from collections import Counter
from urllib.parse import urlsplit

HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
INDICATOR_TYPES = {"ipv4", "ipv6", "domain", "url", *HASH_LENGTHS}
SUPPORTED_TYPES = (
    {"ip-src", "ip-dst", "domain", "hostname", "url", "domain|ip", "malware-sample"}
    | HASH_LENGTHS.keys()
    | {f"filename|{kind}" for kind in HASH_LENGTHS}
)


def boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError(f"{name} must be true, false, 1 or 0.")


def indicator_type(value):
    if value is None or value == "":
        return "ipv4"
    if not isinstance(value, str) or value not in INDICATOR_TYPES:
        raise ValueError("indicator_type must be ipv4, ipv6, domain, url, md5, sha1, sha256 or sha512.")
    return value


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _atomic(kind, value):
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Control characters are not supported.")
    if kind in HASH_LENGTHS:
        if not re.fullmatch(rf"[0-9a-fA-F]{{{HASH_LENGTHS[kind]}}}", value):
            raise ValueError("Invalid hash.")
        return kind, value.lower()
    if kind in ("ip-src", "ip-dst"):
        if "%" in value:
            raise ValueError("Scoped IPv6 is unsupported.")
        address = ipaddress.ip_address(value)
        return f"ipv{address.version}", str(address)
    if kind == "url":
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname or any(char.isspace() for char in value):
            raise ValueError("URL must be absolute with a host and no whitespace.")
        parsed.port  # Reject invalid ports while preserving the exact URL value.
        return "url", value
    domain = value.removesuffix(".").encode("idna").decode("ascii").lower()
    if len(domain) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")
    ):
        raise ValueError("Invalid DNS name.")
    return "domain", domain


def _indicators(kind, value):
    if "|" not in kind and kind != "malware-sample":
        return [_atomic(kind, value)]
    first, separator, second = value.rpartition("|")
    if not separator or not first.strip() or not second.strip():
        raise ValueError("Invalid composite.")
    if kind == "domain|ip":
        return [_atomic("domain", first), _atomic("ip-dst", second)]
    return [_atomic("md5" if kind == "malware-sample" else kind.split("|")[1], second)]


def collect(data, selected_type, include_non_ids=False, limit=None):
    """Return unique values with their provenance, plus skipped-attribute counts."""
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(envelope, dict) for envelope in data):
        raise ValueError("data must contain an event or list of events.")
    values, skipped = {}, Counter()
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if boolean(event.get("deleted"), "deleted"):
            continue
        collections = dict(event, **envelope)
        attributes = [(attribute, {}) for attribute in _records(collections, "Attribute")]
        for obj in _records(collections, "Object"):
            if not boolean(obj.get("deleted"), "deleted"):
                attributes.extend((attribute, obj) for attribute in _records(obj, "Attribute"))
        for attribute, obj in attributes:
            if boolean(attribute.get("deleted"), "deleted") or (
                not boolean(attribute.get("to_ids"), "to_ids") and not include_non_ids
            ):
                skipped["deleted or non-IDS"] += 1
                continue
            kind, value = attribute.get("type"), attribute.get("value")
            if not isinstance(kind, str) or kind not in SUPPORTED_TYPES:
                skipped["unsupported"] += 1
                continue
            try:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("Empty value.")
                atoms = [normalized for atom_type, normalized in _indicators(kind, value) if atom_type == selected_type]
            except ValueError:
                skipped["malformed"] += 1
                continue
            if not atoms:
                skipped["other indicator type"] += 1
                continue
            ref = {
                "event": str(event.get("uuid") or event.get("id") or "unknown"),
                "attribute": str(attribute.get("uuid") or attribute.get("id") or "unknown"),
                "misp_type": kind,
            }
            if obj:
                ref["object"] = str(obj.get("uuid") or obj.get("id") or obj.get("name") or "unknown")
            for atom in atoms:
                refs = values.setdefault(atom, [])
                if ref not in refs:
                    refs.append(ref)
                if limit is not None and len(values) > limit:
                    raise ValueError(f"At most {limit} unique values are allowed; split the input.")
    return values, dict(skipped)
