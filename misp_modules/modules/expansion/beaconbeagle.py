"""Lookup BeaconBeagle infrastructure and pivot through decoded configurations."""

import json
import re
from ipaddress import ip_address
from urllib.parse import urlsplit
from uuid import UUID

from pymisp import MISPObject
from pymisp.exceptions import PyMISPError

from misp_modules.lib.beaconbeagle import HASH, Client, canonical, convert, host, identity, integer, path_key

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["ip-src", "ip-dst", "domain", "hostname", "url", "sha256", "AS", "text"],
    "format": "misp_standard",
}
moduleconfig = {"max_configs": "Maximum decoded configurations per lookup, 1–20 (default 10)."}
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "BeaconBeagle Lookup",
    "description": "Look up Cobalt Strike beacon and C2 infrastructure, configurations and configuration-field pivots.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests", "PyMISP", "No API key required"],
    "features": (
        "Queries beacon and C2 details for IPs, C2 details and configuration search for domains/URLs, configuration"
        " hashes, ASN/country network facets and arbitrary exact configuration-field pivots. Returns decoded"
        " malware-config and ip-port objects plus full source JSON. See documentation/expansion/beaconbeagle.md."
    ),
    "references": ["https://beaconbeagle.com/", "https://beaconbeagle.com/api/"],
    "input": "IP, domain, hostname, URL, configuration SHA-256, AS or text JSON {path, value} / {countries: [FR]}.",
    "output": "Observed infrastructure, decoded configurations, raw evidence and explicit lookup coverage.",
}


def lookup(attribute):
    kind, value = attribute["type"], attribute["value"].strip()
    if kind in ("ip-src", "ip-dst"):
        return "ip", str(ip_address(value))
    if kind in ("domain", "hostname"):
        if host(value)[0] != "domain":
            raise ValueError("Expected a domain or hostname")
        return "host", host(value)[1]
    if kind == "url":
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Expected an HTTP(S) URL without credentials")
        host(parsed.hostname)
        return "url", value
    if kind == "sha256":
        if not HASH.fullmatch(value):
            raise ValueError("Expected a BeaconBeagle configuration SHA-256")
        return "hash", value.lower()
    if kind == "AS":
        value = value.upper().removeprefix("AS")
        if not value.isdecimal() or not 1 <= int(value) <= 4294967295:
            raise ValueError("Invalid ASN")
        return "network", {"asns": [value]}
    pivot = json.loads(value)
    if isinstance(pivot, dict) and set(pivot) == {"countries"}:
        countries = pivot["countries"]
        if (
            not isinstance(countries, list)
            or not countries
            or not all(isinstance(country, str) and re.fullmatch(r"[a-zA-Z]{2}", country) for country in countries)
        ):
            raise ValueError("Expected a list of two-letter country codes")
        return "network", {"countries": sorted(set(country.upper() for country in countries))}
    if not isinstance(pivot, dict) or set(pivot) != {"path", "value"}:
        raise ValueError("Text pivots require a JSON object with path and value")
    if not isinstance(pivot["path"], str) or not re.fullmatch(r"[A-Za-z0-9_.]+", pivot["path"]):
        raise ValueError("Invalid configuration field path")
    if type(pivot["value"]) not in (str, int, float, bool) or pivot["value"] == "":
        raise ValueError("Pivot value must be a nonempty scalar")
    if not isinstance(pivot["value"], str):
        pivot["value"] = canonical(pivot["value"])
    return "pivot", pivot


def expand(attribute, config):
    mode, value = lookup(attribute)
    limit = integer(config.get("max_configs"), 10, 20)
    attributes, objects, hashes, coverage = [], [], [], {}

    def record(kind, key, data):
        event, _ = convert(kind, key, data)
        attributes.extend(event["Attribute"])
        for obj in event["Object"]:
            obj.setdefault("ObjectReference", []).append(
                {
                    "uuid": identity(obj["uuid"], attribute["uuid"], "describes"),
                    "object_uuid": obj["uuid"],
                    "referenced_uuid": attribute["uuid"],
                    "relationship_type": "describes",
                }
            )
            objects.append(obj)

    def candidates(data, field="items"):
        items = data.get(field)
        if not isinstance(items, list):
            raise ValueError("Invalid BeaconBeagle lookup results")
        for item in items:
            candidate = item.get("hash") if isinstance(item, dict) else item
            if not isinstance(candidate, str) or not HASH.fullmatch(candidate):
                raise ValueError("Invalid BeaconBeagle configuration hash")
            if candidate not in hashes:
                hashes.append(candidate)

    with Client() as client:
        if mode in ("ip", "host", "url"):
            key = urlsplit(value).hostname if mode == "url" else value
            if mode == "ip":
                data = client.get("beacons/" + path_key(key), missing=True)
                coverage["beacon_found"] = data is not None
                if data is not None:
                    record("beacons", key, data)
                    data = client.get("beacons/" + path_key(key) + "/configs", {"limit": limit + 1, "offset": 0})
                    candidates(data)
                    coverage["beacon_config_total"] = data.get("total")
            data = client.get("c2/" + path_key(key), missing=True)
            coverage["c2_found"] = data is not None
            if data is not None:
                record("c2", key, data)
                candidates(client.get("c2/" + path_key(key) + "/configs"), "hashes")
            if mode != "ip":
                data = client.get("configs/search", {"q": value, "limit": limit + 1, "offset": 0})
                candidates(data)
                coverage["search_total"] = data.get("total")
                coverage["search_semantics"] = "BeaconBeagle text search; returned matches require review"
        elif mode == "hash":
            hashes.append(value)
        elif mode == "pivot":
            data = client.get("pivot", {**value, "limit": limit + 1, "offset": 0})
            candidates(data, "hashes")
            coverage["pivot_total"] = data.get("total")
        else:
            data = client.post("netsearch/query", {**value, "limit": limit + 1, "offset": 0})
            candidates(data, "hashes")
            coverage["network_totals"] = data.get("totals")
            coverage["network_beacons"] = data.get("beacons", [])
            coverage["network_c2"] = data.get("c2", [])
        missing = []
        for config_hash in hashes[:limit]:
            data = client.get("configs/" + path_key(config_hash), missing=True)
            if data is None:
                missing.append(config_hash)
            else:
                record("configs", config_hash, data)
        coverage.update(
            {
                "configurations_returned": len(hashes[:limit]) - len(missing),
                "max_configs": limit,
                "candidate_hashes": hashes,
                "missing_configurations": missing,
            }
        )
        totals = [coverage.get(k) for k in ("beacon_config_total", "search_total", "pivot_total")]
        totals.append((coverage.get("network_totals") or {}).get("hashes"))
        coverage["limited"] = len(hashes) > limit or any(type(total) is int and total > limit for total in totals)
    context = MISPObject("annotation", standalone=False)
    context.add_attribute("text", value=canonical(coverage), to_ids=False, disable_correlation=True)
    context.add_reference(attribute["uuid"], "describes")
    objects.append(json.loads(context.to_json()))
    # Keep the original attribute and its metadata when an observed value matches it.
    unique = {(item["type"], item["value"]): item for item in attributes}
    unique[(attribute["type"], attribute["value"])] = attribute
    return {"results": {"Attribute": list(unique.values()), "Object": objects}}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all(attribute.get(k) for k in ("type", "value", "uuid")):
            raise ValueError("An attribute with type, value and uuid is required")
        if attribute["type"] not in mispattributes["input"] or not isinstance(attribute["value"], str):
            raise ValueError("Unsupported attribute type or value")
        config = request.get("config", {})
        if not isinstance(config, dict):
            raise ValueError("Config must be an object")
        UUID(attribute["uuid"])
        return expand(attribute, config)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, OSError, PyMISPError):
        return {"error": "Invalid request or BeaconBeagle response; check input, service status and result limits."}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
