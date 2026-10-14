import json
import logging
import sys
import time

from dnstrails import APIError, DnsTrails
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

log = logging.getLogger("dnstrails")
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["hostname", "domain", "ip-src", "ip-dst"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "2",
    "author": "Sebastien Larinier @sebdraven",
    "description": "An expansion modules for SecurityTrails.",
    "module-type": ["expansion", "hover"],
    "name": "SecurityTrails Lookup",
    "logo": "securitytrails.png",
    "requirements": [
        "dnstrails python library",
        "An access to the SecurityTrails API (apikey)",
    ],
    "features": (
        "The module takes a domain, hostname or IP address attribute as input and queries the SecurityTrails API with"
        " it.\n\nThe current and historical DNS records are returned as passive-dns objects carrying the dates"
        " SecurityTrails saw them, the registration data as whois objects, and the domains hosted on an IP address as"
        " domain-ip objects."
    ),
    "references": ["https://securitytrails.com/"],
    "input": "A domain, hostname or IP address attribute.",
    "output": "passive-dns, whois and domain-ip objects describing what SecurityTrails knows about the input.",
}

# config fields that your code expects from the site admin
moduleconfig = ["apikey"]

# SecurityTrails current_dns section -> (record type, the key holding the value)
_CURRENT_DNS = (
    ("a", "A", "ip"),
    ("aaaa", "AAAA", "ipv6"),
    ("ns", "NS", "nameserver"),
    ("mx", "MX", "hostname"),
    ("soa", "SOA", "email"),
)

# SecurityTrails whois contact keys -> whois object relations
_REGISTRANT = (
    ("email", "registrant-email"),
    ("telephone", "registrant-phone"),
    ("name", "registrant-name"),
    ("registrarName", "registrar"),
    ("createdDate", "creation-date"),
)


class SecurityTrailsParser:
    def __init__(self, attribute):
        self.misp_event = MISPEvent()
        self.input_attribute = MISPAttribute()
        self.input_attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.input_attribute)

    def add_object(self, misp_object):
        misp_object.add_reference(self.input_attribute.uuid, "related-to")
        self.misp_event.add_object(misp_object)

    def add_passive_dns(self, rrname, rrtype, rdata, time_first=None, time_last=None):
        """One observation of one record. SecurityTrails dates every section it
        returns, which is what passive-dns is for and what the free-text answer
        pushed into a comment."""
        if not rdata:
            return
        misp_object = MISPObject("passive-dns")
        misp_object.add_attribute("rrname", rrname)
        misp_object.add_attribute("rrtype", rrtype)
        misp_object.add_attribute("rdata", rdata)
        misp_object.add_attribute("origin", "SecurityTrails")
        if time_first:
            misp_object.add_attribute("time_first", time_first)
        if time_last:
            misp_object.add_attribute("time_last", time_last)
        self.add_object(misp_object)

    def add_whois(self, entry, domain, text=None):
        """The registrant block of a whois answer, current or historical."""
        misp_object = MISPObject("whois")
        misp_object.add_attribute("domain", domain)
        registrant = _select_registrant_item(entry)
        if registrant:
            for key, relation in _REGISTRANT:
                if registrant[0].get(key):
                    misp_object.add_attribute(relation, registrant[0][key])
        for nameserver in entry.get("nameServers") or []:
            misp_object.add_attribute("nameserver", nameserver)
        if text:
            misp_object.add_attribute("text", text)
        if len(misp_object.attributes) > 1:
            self.add_object(misp_object)

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if not request.get("config") or not (request["config"].get("apikey")):
        misperrors["error"] = "SecurityTrails authentication is missing"
        return misperrors

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        misperrors["error"] = "Unsupported attributes types"
        return misperrors

    api = DnsTrails(request["config"].get("apikey"))
    if not api:
        misperrors["error"] = "SecurityTrails Error instance api"
        return misperrors

    parser = SecurityTrailsParser(attribute)
    try:
        if attribute["type"] in ("ip-src", "ip-dst"):
            expand_searching_domain(api, parser, attribute["value"])
        else:
            handle_domain(api, parser, attribute["value"])
    except APIError as e:
        misperrors["error"] = e.value
        return misperrors
    return parser.get_results()


def handle_domain(api, parser, domain):
    expand_domain_info(api, parser, domain)
    time.sleep(1)
    expand_subdomains(api, parser, domain)
    time.sleep(1)
    expand_whois(api, parser, domain)
    time.sleep(1)
    expand_history_ipv4_ipv6(api, parser, domain)
    time.sleep(1)
    expand_history_dns(api, parser, domain)
    expand_history_whois(api, parser, domain)


def expand_domain_info(api, parser, domain):
    results = api.domain(domain)
    if not results or "current_dns" not in results:
        return
    for section, rrtype, key in _CURRENT_DNS:
        entry = results["current_dns"].get(section) or {}
        first_seen = entry.get("first_seen")
        for value in entry.get("values") or []:
            parser.add_passive_dns(domain, rrtype, value.get(key), time_first=first_seen)


def expand_subdomains(api, parser, domain):
    results = api.subdomains(domain)
    if not results:
        return
    for subdomain in results.get("subdomains") or []:
        parser.misp_event.add_attribute(
            type="domain",
            value=f"{subdomain}.{domain}",
            category="Network activity",
            comment=f"subdomain of {domain} by SecurityTrails",
        )


def expand_whois(api, parser, domain):
    results = api.whois(domain)
    if results:
        parser.add_whois(results, domain)


def expand_history_ipv4_ipv6(api, parser, domain):
    _history_ip(api.history_dns_ipv4(domain), parser, domain, "A", "ip")
    time.sleep(1)
    _history_ip(api.history_dns_aaaa(domain), parser, domain, "AAAA", "ipv6")


def expand_history_dns(api, parser, domain):
    _history_dns(api.history_dns_ns(domain), parser, domain, "NS", "nameserver")
    time.sleep(1)
    _history_dns(api.history_dns_soa(domain), parser, domain, "SOA", "email")
    time.sleep(1)
    _history_dns(api.history_dns_mx(domain), parser, domain, "MX", "host")


def expand_history_whois(api, parser, domain):
    results = api.history_whois(domain)
    if not results:
        return
    for item in (results.get("result") or {}).get("items") or []:
        status = " ".join(item.get("status") or [])
        parser.add_whois(item, domain, text=f"status: {status}" if status else None)


def _history_ip(results, parser, domain, rrtype, key):
    if not results:
        return
    for record in results.get("records") or []:
        for item in record.get("values") or []:
            parser.add_passive_dns(
                domain,
                rrtype,
                item.get(key),
                time_first=record.get("first_seen"),
                time_last=record.get("last_seen"),
            )


def _history_dns(results, parser, domain, rrtype, key):
    if not results:
        return
    for record in results.get("records") or []:
        values = record.get("values")
        if values is None:
            continue
        if not isinstance(values, list):
            values = [values]
        for item in values:
            parser.add_passive_dns(
                domain,
                rrtype,
                item.get(key),
                time_first=record.get("first_seen"),
                time_last=record.get("last_seen"),
            )


def expand_searching_domain(api, parser, ip):
    results = api.searching_domains(ipv4=ip)
    if not results:
        return
    for record in results.get("records") or []:
        hostname = record.get("hostname")
        if not hostname:
            continue
        misp_object = MISPObject("domain-ip")
        misp_object.add_attribute("domain", hostname)
        misp_object.add_attribute("ip", ip)
        host_provider = record.get("host_provider") or []
        if host_provider:
            misp_object.add_attribute("text", f"host provider: {host_provider[0]}")
        parser.add_object(misp_object)
        registrar = (record.get("whois") or {}).get("registrar")
        if registrar:
            parser.add_whois({"contacts": [{"type": "registrant", "registrarName": registrar}]}, hostname)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def _select_registrant_item(entry):
    res = None
    if "contacts" in entry:
        res = list(filter(lambda x: x.get("type") == "registrant", entry["contacts"]))

    if "contact" in entry:
        res = list(filter(lambda x: x.get("type") == "registrant", entry["contact"]))

    return res
