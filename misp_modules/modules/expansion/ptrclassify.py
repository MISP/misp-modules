import ipaddress
import json
import re
from functools import lru_cache

from dns import exception, resolver, reversename
from ptrclassify import PTRClassifier
from pymisp import MISPAttribute, MISPEvent

from . import check_input_attribute, standard_error_message

mispattributes = {
    "input": ["ip-src", "ip-dst", "domain|ip", "hostname", "domain"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": 1,
    "author": "MISP Project",
    "description": "Classify PTR hostnames and tag queried attributes with the ptrclassify taxonomy.",
    "module-type": ["expansion", "hover"],
    "name": "PTR Classification",
    "logo": "",
    "requirements": ["ptrclassify and dnspython Python libraries; DNS access for IP lookups"],
    "features": (
        "IPv4 and IPv6 attributes are reverse-resolved and every distinct PTR hostname is classified locally using"
        " ptrclassify's built-in rules. Hostname and domain attributes are classified directly, without DNS or an API"
        " key. Matching ptrclassify taxonomy tags are added to the queried attribute, retaining its UUID and existing"
        " tags, and to any returned PTR hostname attributes. A text attribute provides the classification labels,"
        " confidence, evidence, rule IDs and potential location hints for hover and expansion. No match produces an"
        " informative result without adding tags. Configure `nameserver` to use a specific DNS server; otherwise the"
        " system resolver is used. DNS lookups have a five-second lifetime.\n\nClassification is heuristic: PTR names"
        " are operator-controlled, and inferred locations are hints, not verified geolocation. Hover displays the"
        " enrichment; importing the expansion applies the returned tags in MISP. Enable the ptrclassify taxonomy in"
        " MISP to manage these tags."
    ),
    "references": [
        "https://github.com/adulau/ptrclassify",
        "https://misp-project.org/taxonomies.html#_ptrclassify",
    ],
    "input": "An ip-src, ip-dst, domain|ip, hostname or domain attribute.",
    "output": "The tagged input attribute, PTR hostnames for IP lookups, and explainable classification text.",
}
moduleconfig = ["nameserver"]


@lru_cache(maxsize=1)
def _classifier():
    # Rules are immutable during classification; compile them once for repeated hovers.
    return PTRClassifier()


def _hostname(value):
    hostname = value.removesuffix(".").lower().encode("idna").decode("ascii")
    if (
        not hostname
        or len(hostname) > 253
        or any(not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label) for label in hostname.split("."))
    ):
        raise ValueError("Invalid hostname.")
    return hostname


def _ptr_hostnames(address, config):
    dns_resolver = resolver.Resolver()
    dns_resolver.timeout = 2
    dns_resolver.lifetime = 5
    if config.get("nameserver"):
        dns_resolver.nameservers = [str(ipaddress.ip_address(config["nameserver"]))]
    answers = dns_resolver.resolve(reversename.from_address(address), "PTR")
    return sorted({_hostname(answer.to_text()) for answer in answers})


def _add_tags(attribute, tags):
    existing = {tag.name for tag in attribute.tags}
    for tag in sorted(set(tags) - existing):
        attribute.add_tag(tag)


def _summary(classification):
    lines = [f"PTR classification for {classification.hostname} (heuristic)"]
    if not classification.labels:
        lines.append("No classification labels matched; no taxonomy tags added.")
    for label in classification.labels:
        lines.append(
            f"{label.value} — confidence: {label.confidence:g}; "
            f"evidence: {', '.join(label.evidence)}; rules: {', '.join(label.rule_ids)}"
        )
    for location in classification.locations:
        place = ", ".join(value for value in (location.city, location.region, location.country) if value)
        lines.append(
            f"Potential location: {place} (code: {location.code}; confidence: {location.confidence:g}; "
            f"evidence: {location.evidence}; rule: {location.rule_id}). This is not verified geolocation."
        )
    if classification.hints:
        lines.append(f"Hints: {json.dumps(classification.hints, sort_keys=True)}")
    return "\n".join(lines)


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "Invalid request."}
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute_type = attribute["type"]
    if attribute_type not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    value = attribute["value"]
    if not isinstance(value, str) or not value.strip():
        return {"error": "An attribute value is required."}
    config = request.get("config") or {}
    if not isinstance(config, dict):
        return {"error": "Invalid module configuration."}

    is_ip = attribute_type in ("ip-src", "ip-dst", "domain|ip")
    try:
        if is_ip:
            if attribute_type == "domain|ip":
                domain, separator, address = value.partition("|")
                if not domain or not separator:
                    raise ValueError("Invalid domain|ip value.")
            else:
                address = value
            address = str(ipaddress.ip_address(address))
            hostnames = _ptr_hostnames(address, config)
            if not hostnames:
                return {"error": f"No PTR record found for {address}."}
        else:
            hostnames = [_hostname(value)]
    except (resolver.NXDOMAIN, resolver.NoAnswer):
        return {"error": f"No PTR record found for {address}."}
    except exception.Timeout:
        return {"error": "PTR lookup timed out."}
    except exception.DNSException as error:
        return {"error": f"PTR lookup failed: {error}"}
    except ValueError as error:
        return {"error": f"Invalid IP, hostname or nameserver: {error}"}

    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    event = MISPEvent()
    classifier = _classifier()
    for hostname in hostnames:
        classification = classifier.classify(hostname)
        tags = classification.values()
        _add_tags(input_attribute, tags)
        if is_ip:
            ptr_attribute = event.add_attribute("hostname", hostname, to_ids=False, comment=f"PTR record for {address}")
            _add_tags(ptr_attribute, tags)
        event.add_attribute("text", _summary(classification), to_ids=False, comment="ptrclassify enrichment")
    event.add_attribute(**input_attribute)
    return {"results": {"Attribute": json.loads(event.to_json())["Attribute"]}}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
