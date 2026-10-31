import ipaddress
import json
import re
from functools import lru_cache
from importlib import metadata, resources

from dns import exception, resolver, reversename
from ptrclassify import PTRClassifier, PTRRecord
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {
    "input": ["ip-src", "ip-dst", "domain|ip", "hostname", "domain"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": 2,
    "author": "MISP Project",
    "description": "Classify PTR hostnames and tag queried attributes with the ptrclassify taxonomy.",
    "module-type": ["expansion", "hover"],
    "name": "PTR Classification",
    "logo": "",
    "requirements": ["ptrclassify and dnspython Python libraries; DNS access for IP lookups"],
    "features": (
        "IPv4 and IPv6 attributes are reverse-resolved and every distinct PTR hostname is classified locally using"
        " ptrclassify's built-in rules, retaining the queried address to detect IP-encoded naming. Hostname and domain"
        " attributes are classified directly, without DNS or an API key. Matching ptrclassify taxonomy tags are added"
        " to the queried attribute, retaining its UUID and existing tags, and to PTR answers in a `dns-record` object."
        " One `ptrclassify` object per hostname holds the classification labels, confidence, evidence, rule IDs and"
        " potential location hints. Repeated classification fields share the machine tag as their attribute comment;"
        " location fields share a rule-ID/code comment. Classification objects reference the queried attribute and, for"
        " IP lookups, the DNS object. No match returns an object with `matched=0` without adding tags. Configure"
        " `nameserver` to use a specific DNS server; otherwise the system resolver is used. DNS lookups have a"
        " five-second lifetime.\n\nClassification is heuristic: PTR names are operator-controlled, and inferred"
        " locations are hints, not verified geolocation. Hover displays the enrichment; importing the expansion applies"
        " the returned tags in MISP. Enable the ptrclassify taxonomy in MISP to manage these tags, and install the"
        " ptrclassify MISP object template. The module bundles the template so it also works with PyMISP versions that"
        " do not yet include it."
    ),
    "references": [
        "https://github.com/adulau/ptrclassify",
        "https://misp-project.org/taxonomies.html#_ptrclassify",
    ],
    "input": "An ip-src, ip-dst, domain|ip, hostname or domain attribute.",
    "output": (
        "The tagged input attribute, one ptrclassify object per hostname, and a dns-record object for IP lookups."
    ),
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


@lru_cache(maxsize=1)
def _object_template():
    # Keep the bundled template in sync with MISP/misp-objects/objects/ptrclassify.
    return json.loads(resources.files("misp_modules").joinpath("data", "ptrclassify", "definition.json").read_text())


def _classification_object(classification, source_uuid, dns_uuid=None):
    result = MISPObject("ptrclassify", strict=True, misp_objects_template_custom=_object_template())
    hostname = result.add_attribute("hostname", classification.hostname)
    _add_tags(hostname, classification.values())
    result.add_attribute("matched", "1" if classification.labels else "0")
    result.add_attribute("classifier-version", metadata.version("ptrclassify"))
    if classification.address:
        result.add_attribute("ip", classification.address)
    for label in classification.labels:
        for relation, value in (
            ("classification", label.value),
            ("category", label.category),
            ("label", label.label),
            ("confidence", label.confidence),
        ):
            result.add_attribute(relation, value, comment=label.value)
        for evidence in label.evidence:
            result.add_attribute("evidence", evidence, comment=label.value)
        for rule_id in label.rule_ids:
            result.add_attribute("rule-id", rule_id, comment=label.value)
        if label.description:
            result.add_attribute("classification-description", label.description, comment=label.value)
    for location in classification.locations:
        group = f"{location.rule_id}:{location.code}"
        for relation, value in (
            ("location-code", location.code),
            ("location-city", location.city),
            ("location-region", location.region),
            ("location-country", location.country),
            ("location-confidence", location.confidence),
            ("location-evidence", location.evidence),
            ("location-rule-id", location.rule_id),
            ("location-description", location.description),
        ):
            if value is not None:
                result.add_attribute(relation, value, comment=group)
    for hint, relation in (("embedded_ip", "embedded-ip"), ("cloud_region", "cloud-region")):
        if classification.hints.get(hint):
            result.add_attribute(relation, classification.hints[hint])
    for conflict in classification.hints.get("conflicts", []):
        result.add_attribute("conflict", conflict)
    result.add_reference(source_uuid, "characterizes")
    if dns_uuid:
        result.add_reference(dns_uuid, "derived-from")
    return result


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
    dns_record = None
    if is_ip:
        dns_record = MISPObject("dns-record", strict=True, default_attributes_parameters={"to_ids": False})
        dns_record.add_attribute(
            "queried-domain", reversename.from_address(address).to_text().rstrip("."), to_ids=False
        )
        dns_record.add_reference(input_attribute.uuid, "related-to")
    classifier = _classifier()
    for hostname in hostnames:
        if is_ip:
            owner = reversename.from_address(address).to_text()
            record = PTRRecord(
                raw=f"{owner} PTR {hostname}.", hostname=hostname, address=address, owner=owner, record_type="PTR"
            )
            classification = classifier.classify(record)
        else:
            classification = classifier.classify(hostname)
        tags = classification.values()
        _add_tags(input_attribute, tags)
        if is_ip:
            ptr_attribute = dns_record.add_attribute("ptr-record", hostname, to_ids=False)
            _add_tags(ptr_attribute, tags)
        event.add_object(
            _classification_object(classification, input_attribute.uuid, dns_record.uuid if is_ip else None)
        )
    if dns_record is not None:
        event.add_object(dns_record)
    event.add_attribute(**input_attribute)
    result = json.loads(event.to_json())
    return {"results": {key: result[key] for key in ("Attribute", "Object")}}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
