"""Expand a URL into DNS endpoints and IPv4 origin ASNs."""

import ipaddress
import json
from urllib.parse import urlsplit
from uuid import UUID

import dns.exception
import dns.resolver
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["url"], "format": "misp_standard"}
moduleinfo = {
    "version": "1.0",
    "author": "MISP",
    "description": "Resolve URL hosts into IPv4/IPv6 IP-port objects and IPv4 ASN objects.",
    "module-type": ["expansion"],
    "name": "URL DNS and ASN Expansion",
    "logo": "",
    "requirements": ["dnspython", "PyMISP"],
    "features": (
        "Resolve all A and AAAA records, create one TCP ip-port object per address, and query Team Cymru DNS"
        " for IPv4 origin ASNs. Explicit ports override HTTP/HTTPS defaults. Every object references the"
        " original URL attribute. ASN failures preserve endpoint results with an explanatory comment."
    ),
    "references": ["https://www.team-cymru.com/ip-asn-mapping"],
    "input": "A URL attribute with type, value and UUID.",
    "output": "Linked ip-port objects for IPv4/IPv6 and asn objects for public IPv4 addresses.",
}
moduleconfig = ["nameserver"]


def _parse_url(value):
    if not isinstance(value, str) or not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("The URL must be a non-empty string without whitespace or control characters.")
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc or not parsed.hostname:
        raise ValueError("The URL must include a scheme and hostname, for example https://example.org/.")
    host = parsed.hostname
    if "%" in host:
        raise ValueError("Percent-encoded hostnames and scoped IPv6 addresses are not supported.")
    port = parsed.port
    if parsed.netloc.endswith(":"):
        raise ValueError("An explicit port must contain a number.")
    if port is None:
        port = {"http": 80, "https": 443}.get(parsed.scheme.lower())
    if port is None:
        raise ValueError("URL schemes other than HTTP/HTTPS require an explicit TCP port.")
    if not 1 <= port <= 65535:
        raise ValueError("The TCP port must be between 1 and 65535.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        host = host.encode("idna").decode("ascii").rstrip(".")
        # Validate before DNS to avoid accepting invalid URL authorities as DNS names.
        labels = host.split(".")
        if len(host) > 253 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for c in label)
            for label in labels
        ):
            raise ValueError("Invalid URL hostname.")
        address = None
    return host, port, address


def _resolve_addresses(resolver, host):
    addresses = set()
    warnings = []
    for record_type, family in (("A", 4), ("AAAA", 6)):
        try:
            for record in resolver.resolve(f"{host}.", record_type):
                address = ipaddress.ip_address(str(record))
                if address.version == family:
                    addresses.add(address)
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            warnings.append("The URL hostname does not exist (NXDOMAIN).")
            break
        except (dns.exception.DNSException, ValueError) as error:
            warnings.append(f"{record_type} lookup failed ({type(error).__name__}).")
    if not addresses:
        raise ValueError("No IPv4 or IPv6 addresses resolved. " + " ".join(warnings))
    return sorted(addresses, key=lambda address: (address.version, int(address))), warnings


def _txt_records(resolver, name):
    # A TXT RR can consist of multiple quoted chunks; concatenate before parsing.
    return [b"".join(record.strings).decode("utf-8") for record in resolver.resolve(name, "TXT")]


def _origin_asns(resolver, address):
    name = ".".join(reversed(str(address).split("."))) + ".origin.asn.cymru.com."
    records = set()
    for text in _txt_records(resolver, name):
        fields = [field.strip() for field in text.split("|")]
        if len(fields) < 2:
            continue
        try:
            network = ipaddress.ip_network(fields[1])
            if network.version != 4 or address not in network:
                continue
        except ValueError:
            continue
        # Multi-origin prefixes contain space-separated AS numbers.
        for number in fields[0].split():
            if number.isascii() and number.isdigit() and 1 <= int(number) <= 4294967295:
                records.add((int(number), str(network)))
    if not records:
        raise ValueError("No valid IPv4 origin ASN record returned.")
    return sorted(records)


def _asn_object(resolver, number, source_uuid):
    obj = MISPObject("asn", strict=True)
    obj.add_attribute("asn", f"AS{number}", to_ids=False)
    obj.add_reference(source_uuid, "related-to")
    try:
        for text in _txt_records(resolver, f"AS{number}.asn.cymru.com."):
            fields = [field.strip() for field in text.split("|", 4)]
            if len(fields) == 5 and fields[0] == str(number) and fields[4] and fields[4] != "NA":
                obj.add_attribute("description", fields[4], to_ids=False)
                break
    except (dns.exception.DNSException, UnicodeError):
        obj.comment = "ASN description lookup failed; the origin ASN is retained."
    return obj


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "The request must be a JSON object."}
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if attribute["type"] != "url":
        return {"error": "Unsupported attribute type: expected url."}

    try:
        if not isinstance(attribute["uuid"], str):
            raise ValueError("The URL attribute UUID must be a string.")
        UUID(attribute["uuid"])
        host, port, literal = _parse_url(attribute["value"])
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise ValueError("The module config must be a JSON object.")
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 5
        if config.get("nameserver"):
            resolver.nameservers = [str(ipaddress.ip_address(config["nameserver"]))]
        addresses, warnings = ([literal], []) if literal is not None else _resolve_addresses(resolver, host)

        event = MISPEvent()
        source = MISPAttribute()
        source.from_dict(**attribute)
        event.add_attribute(**source)
        asns = {}
        subnets = {}
        for address in addresses:
            endpoint = MISPObject("ip-port", strict=True)
            endpoint.add_attribute("ip", str(address), to_ids=False)
            endpoint.add_attribute("dst-port", port, to_ids=False)
            endpoint.add_attribute("protocol", "tcp", to_ids=False)
            if literal is None:
                endpoint.add_attribute("hostname", host, to_ids=False)
            endpoint.add_reference(source.uuid, "derived-from")
            notes = list(warnings)
            if address.version == 4:
                if not address.is_global or address.is_multicast:
                    notes.append("ASN lookup skipped: this IPv4 address is not globally routable unicast.")
                else:
                    try:
                        origins = _origin_asns(resolver, address)
                    except (dns.exception.DNSException, UnicodeError, ValueError) as error:
                        notes.append(f"IPv4 ASN lookup unavailable ({type(error).__name__}).")
                    else:
                        linked_asns = set()
                        for number, subnet in origins:
                            if number not in asns:
                                asns[number] = _asn_object(resolver, number, source.uuid)
                                subnets[number] = set()
                            if subnet not in subnets[number]:
                                asns[number].add_attribute("subnet-announced", subnet, to_ids=False)
                                subnets[number].add(subnet)
                            if number not in linked_asns:
                                endpoint.add_reference(asns[number].uuid, "belongs-to")
                                linked_asns.add(number)
            if notes:
                endpoint.comment = " ".join(notes)
            event.add_object(endpoint)
        for obj in asns.values():
            event.add_object(obj)
        data = json.loads(event.to_json())
        return {"results": {key: data[key] for key in ("Attribute", "Object")}}
    except (ValueError, TypeError, dns.exception.DNSException, PyMISPError) as error:
        return {"error": f"URL expansion failed: {error}"}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
