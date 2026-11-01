"""MISP adapters for the query and field conventions in DomainTools' reference modules."""

import ipaddress
import json
import re
from uuid import UUID

import idna
import requests
from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

REFERENCE = "https://github.com/DomainTools/domaintools_misp"
PIVOT_MAP = {
    "domain": "domain",
    "hostname": "nameserver_host",
    "ip-src": "ip",
    "ip-dst": "ip",
    "whois-registrant-email": "email",
    "email-src": "email",
    "email-dst": "email",
    "whois-registrar": "registrar",
    "whois-registrant-name": "registrant",
    "x509-fingerprint-sha1": "ssl_hash",
}


class IrisError(ValueError):
    """A diagnostic safe to show without request credentials."""


def _number(config, name, default, maximum, minimum=1):
    value = config.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not str(value).isdigit() or not minimum <= int(value) <= maximum:
        raise IrisError(f"{name} must be an integer between {minimum} and {maximum}.")
    return int(value)


def _domain(value):
    value = idna.encode(value.rstrip("."), uts46=True, transitional=False).decode("ascii").lower()
    if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
        raise IrisError("Invalid domain or hostname.")
    return value


def _value(kind, value):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise IrisError("A nonempty string value is required.")
    value = value.strip()
    if kind in ("domain", "hostname"):
        return _domain(value)
    if kind in ("ip-src", "ip-dst"):
        return str(ipaddress.ip_address(value))
    if kind == "x509-fingerprint-sha1":
        if not re.fullmatch(r"[a-fA-F0-9]{40}", value):
            raise IrisError("A certificate SHA-1 fingerprint is required.")
        return value.lower()
    if kind in ("whois-registrant-email", "email-src", "email-dst") and not re.fullmatch(r"[^@\s]+@[^@\s]+", value):
        raise IrisError("An email address is required.")
    return value


def _fetch(service, field, value, config, limit):
    payload = {"api_username": config["username"], "api_key": config["api_key"], field: value}
    if service == "iris-investigate":
        payload["page_size"] = limit
    try:
        response = requests.post(
            "https://api.domaintools.com/v1/" + service + "/",
            data=payload,
            timeout=(5, 30),
            verify=True,
            allow_redirects=False,
        )
    except requests.RequestException:
        raise IrisError("DomainTools request failed or timed out.") from None
    if response.status_code != 200:
        raise IrisError(f"DomainTools returned HTTP {response.status_code}; check account entitlement and quota.")
    try:
        result = response.json()
    except ValueError:
        raise IrisError("DomainTools returned invalid JSON.") from None
    if not isinstance(result, dict) or not isinstance(result.get("response"), dict):
        raise IrisError("DomainTools returned an invalid response envelope.")
    result = result["response"]
    if result.get("error"):
        raise IrisError("DomainTools rejected the query; check account entitlement and quota.")
    if not isinstance(result.get("results"), list):
        raise IrisError("DomainTools returned invalid result rows.")
    return result


def _scalar(value):
    return value.get("value") if isinstance(value, dict) else value


def _annotation(event, source, title, data):
    obj = MISPObject("annotation")
    obj.comment = title
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True), to_ids=False, disable_correlation=True)
    obj.add_reference(source["uuid"], "describes")
    event.add_object(obj)


def _add(obj, relation, entry, threshold):
    value = _scalar(entry)
    if value is None or value == "" or isinstance(value, (list, dict)):
        return
    attribute = obj.add_attribute(relation, value=value, to_ids=False)
    if isinstance(entry, dict) and type(entry.get("count")) is int:
        count = entry["count"]
        attribute.comment = f"DomainTools Guided Pivot: {count} domains share this value."
        if 0 < count < threshold:
            attribute.add_tag("Guided Pivot")


def _object(event, source, name):
    obj = MISPObject(name)
    obj.add_reference(source["uuid"], "describes")
    event.add_object(obj)
    return obj


def _map(event, source, row, limit, threshold, pivot):
    if not isinstance(row, dict) or not isinstance(row.get("domain"), str):
        raise IrisError("DomainTools returned an invalid domain record.")
    domain = _domain(row["domain"])
    _annotation(event, source, "DomainTools Iris: " + domain, row)
    obj = _object(event, source, "domain-ip")
    _add(obj, "domain", domain, threshold)
    for address in (row.get("ip") or [])[:limit]:
        field = address.get("address") if isinstance(address, dict) else address
        value = _scalar(field)
        if value:
            entry = (
                dict(field, value=str(ipaddress.ip_address(value)))
                if isinstance(field, dict)
                else str(ipaddress.ip_address(value))
            )
            _add(obj, "ip", entry, threshold)
    whois = _object(event, source, "whois")
    _add(whois, "domain", domain, threshold)
    for key, relation in [
        ("registrar", "registrar"),
        ("registrant_org", "registrant-org"),
        ("create_date", "creation-date"),
        ("expiration_date", "expiration-date"),
    ]:
        _add(whois, relation, row.get(key), threshold)
    registrant = row.get("registrant_contact") or {}
    for key, relation in [("name", "registrant-name"), ("org", "registrant-org"), ("phone", "registrant-phone")]:
        _add(whois, relation, registrant.get(key), threshold)
    for email in (registrant.get("email") or [])[:limit]:
        _add(whois, "registrant-email", email, threshold)
    for key in ("name_server", "mx"):
        for record in (row.get(key) or [])[:limit]:
            host = _scalar(record.get("host"))
            if not host:
                continue
            host = _domain(host)
            dns = _object(event, source, "domain-ip")
            dns.comment = "DomainTools " + key + " for " + domain
            entry = record["host"]
            _add(dns, "hostname", dict(entry, value=host) if isinstance(entry, dict) else host, threshold)
            for address in (record.get("ip") or [])[:limit]:
                value = _scalar(address)
                if value:
                    _add(dns, "ip", str(ipaddress.ip_address(value)), threshold)
    if pivot:
        for certificate in (row.get("ssl_info") or [])[:limit]:
            fingerprint = _scalar(certificate.get("hash"))
            if fingerprint:
                obj = _object(event, source, "x509")
                _add(obj, "x509-fingerprint-sha1", _value("x509-fingerprint-sha1", fingerprint), threshold)
        redirect = _scalar(row.get("redirect_domain"))
        if redirect:
            obj = _object(event, source, "domain-ip")
            _add(obj, "domain", _domain(redirect), threshold)


def enrich(q, mode):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("attribute"), dict):
            raise IrisError("A MISP attribute with type, value and UUID is required.")
        source = request["attribute"]
        UUID(source["uuid"])
        kind = source["type"]
        if kind not in (PIVOT_MAP if mode == "pivot" else {"domain"}):
            raise IrisError("Unsupported attribute type for this Iris module.")
        value = _value(kind, source["value"])
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise IrisError("The module config must be an object.")
        for key in ("username", "api_key"):
            if not isinstance(config.get(key), str) or not config[key].strip():
                raise IrisError(f"Missing {key} configuration.")
        limit = _number(config, "results_limit", 100, 100)
        threshold = _number(config, "guided_pivot_threshold", 300, 100000, 0) if mode == "pivot" else 0
        service = "iris-enrich" if mode == "enrich" else "iris-investigate"
        field = PIVOT_MAP[kind] if mode == "pivot" else "domain"
        result = _fetch(service, field, value, config, limit)
        event = MISPEvent()
        event.add_attribute(**source)
        for row in result["results"][:limit]:
            _map(event, source, row, limit, threshold, mode == "pivot")
        metadata = {
            k: result[k]
            for k in ("results_count", "total_count", "missing_domains", "limit_exceeded", "position")
            if k in result
        }
        if metadata or len(result["results"]) > limit:
            metadata.update(imported_results=min(len(result["results"]), limit), results_limit=limit)
            _annotation(event, source, "DomainTools Iris response metadata", metadata)
        data = json.loads(event.to_json())
        return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}
    except IrisError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, PyMISPError):
        return {"error": "Invalid MISP request or DomainTools response."}
