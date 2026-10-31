import ipaddress
import json
from urllib.parse import urlparse

import requests
from publicsuffixlist import PublicSuffixList
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {
    "input": ["domain", "hostname", "ip-src", "ip-dst", "url"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": 2,
    "author": "Ali Bhutto",
    "description": (
        "An expansion module to query the public RDAP bootstrap (rdap.org) for"
        " registration data of a domain, hostname, IP address or URL. RDAP"
        " (Registration Data Access Protocol, RFC 9082/9083) is the free,"
        " unauthenticated and structured successor to WHOIS."
    ),
    "module-type": ["expansion", "hover"],
    "name": "RDAP Lookup",
    "logo": "",
    "requirements": [],
    "features": (
        "The module takes a domain, hostname, IP address or URL attribute as"
        " input, resolves a URL to its host, and queries the rdap.org bootstrap"
        " which redirects to the authoritative RDAP server for the object. The"
        " registrar, registration and expiration dates, name servers, status and"
        " registrant information are parsed into a MISP whois object. A"
        " hostname, subdomain or URL host is looked up at its registered domain"
        " (ICANN section of the Public Suffix List), and the object's comment"
        " says so."
    ),
    "references": ["https://about.rdap.org/", "https://rdap.org/"],
    "input": "A domain, hostname, IP address or URL attribute.",
    "output": "A whois object holding the registration data returned by RDAP.",
}
moduleconfig = []

RDAP_URL = "https://rdap.org"

# Registries delegate under ICANN suffixes only: a name under a private suffix
# such as duckdns.org is registered under .org, so its registry answers for
# duckdns.org and not for foo.duckdns.org.
_PSL = PublicSuffixList(only_icann=True)

# RDAP event actions (RFC 9083) mapped to whois object relations.
_EVENT_MAPPING = {
    "registration": "creation-date",
    "expiration": "expiration-date",
    "last changed": "modification-date",
}


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _registered_domain(host):
    """The registered domain of ``host``, or ``host`` itself when it is a
    public suffix."""
    return _PSL.privatesuffix(host) or host


def _vcard_value(entity, field):
    """Pull a single field (e.g. ``fn``, ``org``, ``email``) out of an RDAP
    entity's jCard ``vcardArray`` (RFC 7095), or ``None``."""
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for item in vcard[1]:
        # each item is [name, params, type, value]
        if len(item) >= 4 and item[0] == field:
            value = item[3]
            if isinstance(value, list):
                value = " ".join(str(part) for part in value if part)
            return value
    return None


def _entity_by_role(entities, role):
    for entity in entities or []:
        if role in entity.get("roles", []):
            return entity
    return None


def _add_if(misp_object, relation, value):
    if value:
        misp_object.add_attribute(relation, value)


def _parse_rdap(rdap, queried_value, is_ip, host=None):
    """Build a MISP whois object from an RDAP response.

    ``queried_value`` is the name asked for, used rather than RDAP's
    ``ldhName`` which some registries return uppercased. ``host`` is the input
    host when it differs from the registered domain asked for. It is only named
    in the comment, never added as a second ``domain``, so that the record does
    not read as the host's own registration.
    """
    whois = MISPObject("whois")
    whois.add_attribute("ip-address" if is_ip else "domain", queried_value)
    if host:
        whois.add_attribute("comment", f"Registration data for {queried_value}, the registered domain of {host}.")

    registrar = _entity_by_role(rdap.get("entities"), "registrar")
    if registrar:
        _add_if(whois, "registrar", _vcard_value(registrar, "fn"))

    registrant = _entity_by_role(rdap.get("entities"), "registrant")
    if registrant:
        _add_if(whois, "registrant-name", _vcard_value(registrant, "fn"))
        _add_if(whois, "registrant-org", _vcard_value(registrant, "org"))
        _add_if(whois, "registrant-email", _vcard_value(registrant, "email"))

    for event in rdap.get("events", []):
        relation = _EVENT_MAPPING.get(event.get("eventAction"))
        if relation and event.get("eventDate"):
            _add_if(whois, relation, event["eventDate"])

    for nameserver in rdap.get("nameservers", []):
        _add_if(whois, "nameserver", nameserver.get("ldhName"))

    if rdap.get("status"):
        whois.add_attribute("text", "status: " + ", ".join(rdap["status"]))

    return whois


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute.get("type") not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}

    value = attribute["value"]
    if attribute["type"] == "url":
        host = urlparse(value).hostname
        if not host:
            return {"error": f"Could not extract a host from URL {value}."}
        value = host
    value = value.strip().lower().rstrip(".")

    is_ip = _is_ip(value)
    host = None
    if not is_ip:
        registered = _registered_domain(value)
        if registered != value:
            host, value = value, registered
    path = f"ip/{value}" if is_ip else f"domain/{value}"
    try:
        response = requests.get(
            f"{RDAP_URL}/{path}",
            headers={"Accept": "application/rdap+json"},
            timeout=15,
        )
    except requests.RequestException as e:
        return {"error": f"Error while querying rdap.org: {e}"}

    # Not every registry answers 404 for an unknown name (PIR answers 400). Do
    # not call it unregistered: a TLD without an RDAP service also answers 404.
    if response.status_code == 404 or (response.status_code == 400 and not is_ip):
        if host:
            return {"error": f"No RDAP record found for {value} (the registered domain of {host})."}
        return {"error": f"No RDAP record found for {value}."}
    if response.status_code != 200:
        return {"error": f"Error while querying rdap.org - {response.status_code}: {response.reason}"}

    try:
        rdap = response.json()
    except ValueError:
        return {"error": "RDAP server returned a non-JSON response."}

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    whois = _parse_rdap(rdap, value, is_ip, host)
    whois.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(whois)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object")}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
