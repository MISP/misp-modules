"""Enumerate DNS data types and retain complete records and correlation pivots."""

import ipaddress
import json
import math
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from urllib.parse import urlsplit
from uuid import UUID

import dns.exception
import dns.flags
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

from . import check_input_attribute, standard_error_message

mispattributes = {
    "input": [
        "domain",
        "hostname",
        "domain|ip",
        "hostname|port",
        "url",
        "email",
        "email-src",
        "email-dst",
        "dns-soa-email",
        "ip-src",
        "ip-dst",
        "ip-src|port",
        "ip-dst|port",
    ],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.0",
    "author": "MISP",
    "description": "Enumerate DNS record types and extract domain, IP, email and URL pivots.",
    "module-type": ["expansion"],
    "name": "DNS Record Enumeration",
    "logo": "",
    "requirements": ["dnspython", "PyMISP"],
    "features": (
        "Query each dnspython-known DNS data type explicitly, including SOA, TXT, MX, NS, SRV, CAA and DNSSEC. "
        "Return complete dns-resource-record objects with owner, type, class, TTL, RDATA and typed pivots. "
        "Accept DNS names, URLs, email addresses and IPs (reverse DNS). Query common mail-policy TXT names and "
        "optionally resolve discovered names to A/AAAA. Eight workers share a total time budget; failures retain "
        "successful results. See documentation/expansion/dns_query.json for configuration and limitations."
    ),
    "references": ["https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml"],
    "input": "A supported MISP attribute containing type, value and UUID.",
    "output": "Linked dns-resource-record objects; newly generated attributes have to_ids=false.",
}
moduleconfig = ["nameserver", "record_types", "query_timeout", "max_time", "max_pivots", "mail_policy"]

# These are reserved values, query/meta types, authentication or EDNS machinery,
# rather than ordinary resource data to enumerate. ANY is deliberately excluded.
EXCLUDED_TYPES = {0, 41, 249, 250, 251, 252, 253, 254, 255, 65535}
DEFAULT_TYPES = tuple(t.name.replace("_", "-") for t in dns.rdatatype.RdataType if t.value not in EXCLUDED_TYPES)
COMMON_TYPES = ("A", "AAAA", "CNAME", "SOA", "NS", "MX", "TXT", "SRV", "CAA", "HTTPS", "SVCB", "PTR")
MAX_RECORDS = 1000


def _hostname(value):
    value = value.removesuffix(".").encode("idna").decode("ascii").lower()
    if (
        not value
        or len(value) > 253
        or any(not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label) for label in value.split("."))
    ):
        raise ValueError("Invalid DNS name.")
    return value


def _query_name(attribute):
    value = attribute["value"]
    if not isinstance(value, str) or not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("The input must be a non-empty string without whitespace or control characters.")
    kind = attribute["type"]
    if "|" in kind:
        value, separator, suffix = value.partition("|")
        if not separator or not suffix:
            raise ValueError("Invalid composite attribute.")
        if kind.endswith("|port") and (not suffix.isascii() or not suffix.isdigit() or not 1 <= int(suffix) <= 65535):
            raise ValueError("Invalid port in composite attribute.")
        if kind == "domain|ip":
            ipaddress.ip_address(suffix)
    if kind == "url":
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.netloc or not parsed.hostname or "%" in parsed.hostname:
            raise ValueError("The URL must include a scheme and valid hostname.")
        parsed.port  # Validate an explicit port even though DNS does not use it.
        value = parsed.hostname
    elif kind in {"email", "email-src", "email-dst", "dns-soa-email"}:
        local, separator, value = value.rpartition("@")
        if not separator or not local:
            raise ValueError("The email address must contain a local part and domain.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if kind.startswith("ip-"):
            raise ValueError("Invalid IP address.")
        return _hostname(value) + ".", False
    return address.reverse_pointer + ".", True


def _number(config, key, default, minimum, maximum, integer=False):
    raw = config.get(key, default)
    if raw is None or raw == "":
        raw = default
    if isinstance(raw, bool):
        raise ValueError(f"Invalid {key}.")
    value = float(raw)
    if not math.isfinite(value) or not minimum <= value <= maximum or (integer and not value.is_integer()):
        raise ValueError(f"{key} must be between {minimum} and {maximum}.")
    return int(value) if integer else value


def _settings(config):
    if not isinstance(config, dict):
        raise ValueError("The module config must be a JSON object.")
    record_types = config.get("record_types", "all")
    if record_types is None or record_types == "":
        record_types = "all"
    if not isinstance(record_types, str):
        raise ValueError("record_types must be 'all' or a comma-separated list.")
    if record_types.strip().lower() == "all":
        types = set(DEFAULT_TYPES)
    else:
        types = set()
        for item in record_types.split(","):
            rdtype = dns.rdatatype.from_text(item.strip().upper())
            if int(rdtype) in EXCLUDED_TYPES:
                raise ValueError("record_types cannot include reserved, meta, transfer or authentication types.")
            types.add(dns.rdatatype.to_text(rdtype))
        if len(types) > 128:
            raise ValueError("At most 128 record types can be specified.")
    types = [t for t in COMMON_TYPES if t in types] + sorted(types - set(COMMON_TYPES))
    mail_policy = config.get("mail_policy", "true")
    if mail_policy is None or mail_policy == "":
        mail_policy = "true"
    if str(mail_policy).lower() not in {"true", "false", "1", "0"}:
        raise ValueError("mail_policy must be true or false.")
    return (
        types,
        _number(config, "query_timeout", 2, 0.1, 10),
        _number(config, "max_time", 30, 1, 120),
        _number(config, "max_pivots", 16, 0, 64, integer=True),
        str(mail_policy).lower() in {"true", "1"},
    )


@lru_cache(maxsize=1)
def _object_template():
    # Keep this identical to MISP/misp-objects/objects/dns-resource-record.
    return json.loads(
        resources.files("misp_modules").joinpath("data", "dns-resource-record", "definition.json").read_text()
    )


def _text_pivots(text):
    """Extract explicit policy mechanisms, addresses and URLs, not arbitrary words."""
    for match in re.finditer(r"https?://[^\s\"<>;]+", text):
        yield "url", match.group()
    for match in re.finditer(r"(?:mailto:)?([a-zA-Z0-9_.+%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text):
        yield "email", match[1]
    if text.lower().startswith("v=spf1"):
        for token in text.split()[1:]:
            token = token.lstrip("+-~?")
            match = re.fullmatch(r"ip[46]:(.+)", token, re.IGNORECASE)
            if match:
                try:
                    network = ipaddress.ip_network(match[1], strict=False)
                    if network.version == (4 if token.lower().startswith("ip4:") else 6):
                        yield "ip", str(network.network_address) if network.num_addresses == 1 else str(network)
                except ValueError:
                    pass
            match = re.fullmatch(r"(?:include:|redirect=|a:|mx:|exists:)([^/]+)(?:/.*)?", token, re.IGNORECASE)
            if match and "%" not in match[1]:  # SPF macros require a mail transaction context.
                try:
                    yield "domain", _hostname(match[1])
                except ValueError:
                    pass


def _pivots(record):
    kind = dns.rdatatype.to_text(record.rdtype)
    for field in (
        "target",
        "exchange",
        "mname",
        "replacement",
        "next",
        "signer",
        "intermediate",
        "map822",
        "mapx400",
        "fqdn",
        "gateway",
    ):
        value = getattr(record, field, None)
        if isinstance(value, dns.name.Name) and value != dns.name.root:
            yield "domain", value.to_text().rstrip(".").lower()
    if kind in {"A", "AAAA"}:
        yield "ip", record.address
    if kind == "SOA":
        if len(record.rname.labels) > 2:
            local = record.rname.labels[0].decode("utf-8", errors="replace")
            domain = dns.name.Name(record.rname.labels[1:]).to_text().rstrip(".").lower()
            yield "soa-email", f"{local}@{domain}"
        for field in ("serial", "refresh", "retry", "expire", "minimum"):
            yield field, str(getattr(record, field))
    if kind == "RP":
        mailbox = record.mbox
        if len(mailbox.labels) > 2:
            yield "email", mailbox.labels[0].decode("utf-8", errors="replace") + "@" + dns.name.Name(
                mailbox.labels[1:]
            ).to_text().rstrip(".")
        if record.txt != dns.name.root:
            yield "domain", record.txt.to_text().rstrip(".").lower()
    for field, relation in (
        ("preference", "priority"),
        ("priority", "priority"),
        ("weight", "weight"),
        ("port", "port"),
    ):
        value = getattr(record, field, None)
        if value is not None and (relation != "port" or value):
            yield relation, str(value)
    if kind in {"SVCB", "HTTPS"}:
        for key, param in record.params.items():
            if int(key) in {4, 6}:
                for address in param.addresses:
                    yield "ip", address
            elif int(key) == 3:
                yield "port", str(param.port)
    if kind in {"TXT", "SPF"}:
        text = b"".join(record.strings).decode("utf-8", errors="replace")
        yield "text", text
        yield from _text_pivots(text)
    if kind == "URI":
        target = record.target.decode("utf-8", errors="replace")
        if target.startswith(("http://", "https://")):
            yield "url", target
    if kind == "CAA":
        tag = record.tag.decode("ascii", errors="replace").lower()
        value = record.value.decode("utf-8", errors="replace")
        if tag in {"issue", "issuewild"} and value.split(";", 1)[0].strip():
            try:
                yield "domain", _hostname(value.split(";", 1)[0].strip())
            except ValueError:
                pass
        yield from _text_pivots(value)


def _sections(response):
    if response is None:
        return []
    return [
        (section, rrset)
        for section in ("answer", "authority", "additional")
        for rrset in getattr(response, section, [])
        if int(rrset.rdtype) not in EXCLUDED_TYPES
    ]


def _lookup(resolver, name, kind, deadline, timeout):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return name, [], f"{name} {kind}: total time budget exhausted"
    try:
        answer = resolver.resolve(name, kind, search=False, lifetime=min(timeout, remaining))
        # Retain alias RRsets with their own owners, instead of attributing the
        # canonical target's data to the original input name.
        return name, _sections(answer.response), None
    except dns.resolver.NoAnswer as error:
        response = error.kwargs.get("response")
        return name, _sections(response), None
    except dns.resolver.NXDOMAIN as error:
        rrsets = [entry for response in error.kwargs.get("responses", {}).values() for entry in _sections(response)]
        return name, rrsets, f"{name} {kind}: NXDOMAIN"
    except dns.exception.DNSException as error:
        return name, [], f"{name} {kind}: {type(error).__name__}"


def _enumerate(resolver, queries, deadline, timeout):
    with ThreadPoolExecutor(max_workers=8) as executor:
        # Resolver configuration stays immutable while resolve() runs concurrently.
        futures = [executor.submit(_lookup, resolver, name, kind, deadline, timeout) for name, kind in queries]
        return [future.result() for future in futures]


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not check_input_attribute(attribute):
            return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
        if attribute["type"] not in mispattributes["input"]:
            raise ValueError("Unsupported input attribute type.")
        UUID(attribute["uuid"])
        name, reverse = _query_name(attribute)
        config = request.get("config")
        if config is None:
            config = {}
        types, timeout, max_time, max_pivots, mail_policy = _settings(config)
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=1232)
        if config.get("nameserver"):
            resolver.nameservers = [str(ipaddress.ip_address(config["nameserver"]))]
        deadline = time.monotonic() + max_time
        queries = [(name, kind) for kind in types]
        if mail_policy and not reverse:
            queries.extend((f"{prefix}.{name}", "TXT") for prefix in ("_dmarc", "_mta-sts", "_smtp._tls"))

        event = MISPEvent()
        source = MISPAttribute()
        source.from_dict(**attribute)
        event.add_attribute(**source)
        objects = {}
        discovered = set()
        warnings = []
        observed = datetime.now(timezone.utc)

        def collect(responses):
            for queried, rrsets, warning in responses:
                if warning:
                    warnings.append(warning)
                for section, rrset in rrsets:
                    owner = rrset.name.to_text().lower()
                    if owner != ".":
                        owner = owner.rstrip(".")
                    kind = dns.rdatatype.to_text(rrset.rdtype)
                    for record in rrset:
                        key = (owner, rrset.rdclass, kind, record.to_text())
                        if key in objects:
                            obj = objects[key]
                            if queried.rstrip(".") not in {
                                a.value for a in obj.get_attributes_by_relation("queried-name")
                            }:
                                obj.add_attribute("queried-name", queried.rstrip("."), to_ids=False)
                            if section not in {a.value for a in obj.get_attributes_by_relation("section")}:
                                obj.add_attribute("section", section, to_ids=False)
                            continue
                        if len(objects) >= MAX_RECORDS:
                            warnings.append(f"Result limit of {MAX_RECORDS} records reached.")
                            return
                        obj = MISPObject(
                            "dns-resource-record", strict=True, misp_objects_template_custom=_object_template()
                        )
                        for relation, value in (
                            ("queried-name", queried.rstrip(".")),
                            ("rrname", owner),
                            ("rrtype", kind),
                            ("rrclass", dns.rdataclass.to_text(rrset.rdclass)),
                            ("section", section),
                            ("ttl", str(rrset.ttl)),
                            ("rdata", record.to_text()),
                        ):
                            obj.add_attribute(relation, value, to_ids=False)
                        seen = set()
                        for relation, value in _pivots(record):
                            if not value or (relation, value) in seen:
                                continue
                            seen.add((relation, value))
                            obj.add_attribute(relation, value, to_ids=False)
                            if relation == "domain":
                                discovered.add(value)
                        obj.first_seen = observed
                        obj.last_seen = observed
                        obj.add_reference(source.uuid, "derived-from")
                        objects[key] = obj

        collect(_enumerate(resolver, queries, deadline, timeout))
        # One bounded follow-up stage; discovered data never causes recursive crawling.
        pivots = sorted(discovered - {name.rstrip(".")})
        if max_pivots and len(pivots) > max_pivots:
            warnings.append(f"Address follow-ups limited to {max_pivots} of {len(pivots)} discovered names.")
        followups = []
        if max_pivots and len(objects) < MAX_RECORDS:
            for pivot in pivots[:max_pivots]:
                try:
                    followups.extend((_hostname(pivot) + ".", kind) for kind in ("A", "AAAA"))
                except ValueError:
                    continue
            collect(_enumerate(resolver, followups, deadline, timeout))
        if not objects:
            return {"error": f"No DNS records returned for {name} " + " ".join(dict.fromkeys(warnings))}
        if warnings:
            next(iter(objects.values())).comment = "Partial enumeration: " + " ".join(dict.fromkeys(warnings))
        for obj in objects.values():
            event.add_object(obj)
        data = json.loads(event.to_json())
        return {"results": {key: data[key] for key in ("Attribute", "Object")}}
    except (ValueError, TypeError, AttributeError, dns.exception.DNSException, PyMISPError) as error:
        return {"error": f"DNS enumeration failed: {error}"}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
