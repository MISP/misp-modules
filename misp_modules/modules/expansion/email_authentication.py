"""Collect published SPF, DMARC and selector-specific DKIM DNS records."""

import ipaddress
import json
import math
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from uuid import UUID

import dns.exception
import dns.resolver
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["hostname", "domain"], "format": "misp_standard"}
moduleinfo = {
    "version": "1.0",
    "author": "MISP",
    "description": "Gather published SPF, DKIM and DMARC DNS records for a hostname or domain.",
    "module-type": ["expansion"],
    "name": "Email Authentication",
    "logo": "",
    "requirements": ["dnspython", "PyMISP"],
    "features": (
        "Collect SPF TXT records at the exact input name, DMARC at _dmarc, and DKIM keys at configured selectors. "
        "Return one email-authentication object per record, retaining the query name, resolved owner, TTL and "
        "observation time. Uses a bundled version-2 extension of the object introduced in misp-objects PR #579. "
        "DNS records do not establish message authentication results. DKIM selector discovery is incomplete; "
        "no result does not establish that DKIM is disabled. See documentation/expansion/email_authentication.json."
    ),
    "references": [
        "https://github.com/MISP/misp-objects/pull/579",
        "https://www.rfc-editor.org/rfc/rfc7208",
        "https://www.rfc-editor.org/rfc/rfc6376",
        "https://www.rfc-editor.org/rfc/rfc7489",
    ],
    "input": "A hostname or domain MISP attribute with type, value and UUID.",
    "output": "Linked email-authentication objects with published DNS records and to_ids=false.",
}
moduleconfig = ["nameserver", "dkim_selectors", "query_timeout", "max_time"]

DEFAULT_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "dkim", "s1", "s2")
MAX_RECORDS_PER_QUERY = 20


def _name(value):
    if not isinstance(value, str) or not value:
        raise ValueError("The DNS name must be a non-empty string.")
    value = value.removesuffix(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")
    ):
        raise ValueError("Invalid DNS name.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Expected a hostname or domain, not an IP address.")


def _seconds(config, key, default, minimum, maximum):
    raw = config.get(key)
    if raw is None or raw == "":
        raw = default
    if isinstance(raw, bool):
        raise ValueError(f"Invalid {key}.")
    value = float(raw)
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum} seconds.")
    return value


def _settings(config, domain):
    if not isinstance(config, dict):
        raise ValueError("The module config must be a JSON object.")
    raw = config.get("dkim_selectors")
    if raw is None or raw == "":
        selectors = list(DEFAULT_SELECTORS)
    elif isinstance(raw, str):
        selectors = list(dict.fromkeys(_name(s.strip()) for s in raw.split(",")))
    else:
        raise ValueError("dkim_selectors must be a comma-separated string.")
    if len(selectors) > 32:
        raise ValueError("At most 32 DKIM selectors may be queried.")
    if any(len(f"{selector}._domainkey.{domain}") > 253 for selector in selectors) or len(f"_dmarc.{domain}") > 253:
        raise ValueError("A policy query name exceeds the DNS name length limit.")
    nameserver = config.get("nameserver") or None
    if nameserver is not None:
        if not isinstance(nameserver, str):
            raise ValueError("nameserver must be an IPv4 or IPv6 address string.")
        nameserver = str(ipaddress.ip_address(nameserver))
    return (
        selectors,
        nameserver,
        _seconds(config, "query_timeout", 2, 0.1, 10),
        _seconds(config, "max_time", 20, 1, 25),
    )


@lru_cache(maxsize=1)
def _object_template():
    return json.loads(
        resources.files("misp_modules").joinpath("data", "email-authentication", "definition.json").read_text()
    )


def _matches(record, relation):
    if relation == "spf-record":
        return re.match(r"^v=spf1(?:\s|$)", record, re.IGNORECASE) is not None
    if relation == "dmarc-record":
        return re.match(r"^v=DMARC1\s*(?:;|$)", record, re.IGNORECASE) is not None
    # DKIM's v= tag is optional. A p= tag, including an empty revoked key,
    # identifies key material at this selector; arbitrary TXT data is ignored.
    tags = {}
    for part in record.split(";"):
        if not part.strip():
            continue
        key, separator, value = part.strip().partition("=")
        key = key.strip()
        if not separator or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*", key) or key in tags:
            return False
        tags[key] = value.strip()
    return "p" in tags and ("v" not in tags or (re.match(r"^v=DKIM1\s*;", record) is not None and tags["v"] == "DKIM1"))


def _lookup(resolver, query, deadline, timeout):
    name, relation, selector = query
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return query, [], f"{name}: time budget exhausted."
    try:
        answer = resolver.resolve(name + ".", "TXT", search=False, lifetime=min(timeout, remaining))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return query, [], ""
    except dns.exception.DNSException as error:
        return query, [], f"{name}: {type(error).__name__}."
    records = []
    seen = set()
    warnings = []
    for rdata in answer:
        try:
            # Chunks are one TXT RR, concatenated without inserting whitespace.
            text = b"".join(rdata.strings).decode("utf-8")
        except UnicodeDecodeError:
            warnings.append(f"{name}: non-UTF-8 TXT record skipped.")
            continue
        if text in seen or not _matches(text, relation):
            continue
        seen.add(text)
        if len(records) == MAX_RECORDS_PER_QUERY:
            warnings.append(f"{name}: record limit of {MAX_RECORDS_PER_QUERY} reached.")
            break
        records.append((text, answer.rrset.name.to_text().removesuffix("."), answer.rrset.ttl))
    return query, records, " ".join(dict.fromkeys(warnings))


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not check_input_attribute(attribute):
            return {"error": f"{standard_error_message}, with type, value and uuid."}
        if attribute["type"] not in mispattributes["input"]:
            raise ValueError("Unsupported input attribute type.")
        UUID(attribute["uuid"])
        domain = _name(attribute["value"])
        config = request.get("config")
        selectors, nameserver, timeout, max_time = _settings({} if config is None else config, domain)
        source = MISPAttribute()
        source.from_dict(**attribute)
        event = MISPEvent()
        event.add_attribute(**source)

        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = timeout
        if nameserver:
            resolver.nameservers = [nameserver]
        queries = [(domain, "spf-record", None), (f"_dmarc.{domain}", "dmarc-record", None)]
        queries.extend((f"{selector}._domainkey.{domain}", "dkim-record", selector) for selector in selectors)
        deadline = time.monotonic() + max_time
        observed = datetime.now(timezone.utc)
        warnings = []
        objects = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = pool.map(lambda query: _lookup(resolver, query, deadline, timeout), queries)
            for (name, relation, selector), records, warning in responses:
                if warning:
                    warnings.append(warning)
                for text, owner, ttl in records:
                    obj = MISPObject(
                        "email-authentication", strict=True, misp_objects_template_custom=_object_template()
                    )
                    for field, value in (
                        ("domain", domain),
                        ("dns-name", name),
                        ("dns-owner", owner),
                        ("dns-ttl", str(ttl)),
                        (relation, text),
                    ):
                        obj.add_attribute(field, value, to_ids=False)
                    if selector:
                        obj.add_attribute("dkim-selector", selector, to_ids=False)
                    obj.first_seen = obj.last_seen = observed
                    obj.comment = "Published DNS record; message authentication has not been evaluated."
                    obj.add_reference(source.uuid, "derived-from")
                    objects.append(obj)
        if not objects:
            return {
                "error": (
                    (
                        f"No email-authentication DNS records found for {domain}. "
                        "DKIM lookup covers only the configured selectors. "
                        + " ".join(warnings)
                    ).strip()
                )
            }
        if warnings:
            objects[0].comment += " Partial lookup: " + " ".join(warnings)
        for obj in objects:
            event.add_object(obj)
        data = json.loads(event.to_json())
        return {"results": {key: data[key] for key in ("Attribute", "Object")}}
    except (ValueError, TypeError, AttributeError, dns.exception.DNSException, PyMISPError) as error:
        return {"error": f"Email authentication lookup failed: {error}"}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
