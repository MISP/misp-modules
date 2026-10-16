import json
import re
from datetime import datetime
from ipaddress import ip_address

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, checking_error, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "hostname"], "format": "misp_standard"}
moduleinfo = {
    "version": "1",
    "author": "OTI Labs",
    "description": (
        "An expansion module for the OTI Labs Domain Intelligence API (https://oti-labs.com/domain-intelligence-api)."
        " One request returns WHOIS/RDAP registration, DNS records, the certificate the domain serves, live"
        " subdomains with their IP addresses and the SPF, DMARC and DKIM records."
    ),
    "module-type": ["expansion", "hover"],
    "name": "OTI Labs Domain Intelligence",
    "logo": "",
    "requirements": [
        "A RapidAPI key subscribed to the OTI Labs Domain Intelligence API (the free plan includes 1,000 requests a"
        " month)."
    ],
    "features": (
        "The module takes a domain or a hostname and queries the /lookup endpoint of the OTI Labs Domain Intelligence"
        " API.\n\nThe response is mapped to a whois object (registrar, creation, update and expiry dates,"
        " nameservers), an x509 object (issuer, subject, serial number, validity dates, SANs), a dns-record object"
        " (MX, NS, TXT, SOA), a domain-ip object for the domain (A/AAAA records plus the SPF, DMARC and DKIM"
        " results as text) and one domain-ip object per live subdomain with its IP address. The number of"
        " subdomain objects is capped by the subdomain_limit setting (default 50)."
    ),
    "references": [
        "https://oti-labs.com/domain-intelligence-api",
        "https://github.com/osiris-technical-institute/domain-intelligence-api",
    ],
    "input": "A domain or a hostname.",
    "output": "whois, x509, dns-record and domain-ip objects describing the domain and its live subdomains.",
}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "subdomain_limit"]

API_HOST = "domain-intelligence-api.p.rapidapi.com"
API_URL = f"https://{API_HOST}/lookup/"
API_TIMEOUT = 30
DEFAULT_SUBDOMAIN_LIMIT = 50
SAN_LIMIT = 50


def _datetime(value):
    """Return the value if it is an ISO 8601 date, else None (some ccTLD registries return free text)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value


def _is_ip(value):
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _hostname(value):
    """Lower-case a DNS name and drop the trailing dot; MX values also drop their priority."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.split()[-1].rstrip(".").lower() or None


def _txt(value):
    """Join the quoted strings of a TXT record into one value."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', value)
    return "".join(parts) if parts else value


def _subdomain_limit(value):
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return DEFAULT_SUBDOMAIN_LIMIT
    return max(0, limit)


def _lookup(apikey, domain):
    headers = {"X-RapidAPI-Key": apikey, "X-RapidAPI-Host": API_HOST, "Accept": "application/json"}
    try:
        response = requests.get(API_URL + domain, headers=headers, timeout=API_TIMEOUT)
    except requests.exceptions.RequestException as e:
        return None, "Error while querying the OTI Labs API: %s" % e
    if response.status_code in (401, 403):
        return None, (
            "The OTI Labs API rejected the key (HTTP %s). Use a RapidAPI key subscribed to the Domain Intelligence API."
            % response.status_code
        )
    if response.status_code == 429:
        return None, "OTI Labs API quota or rate limit reached (HTTP 429)."
    if response.status_code != 200:
        return None, "Error while querying the OTI Labs API: HTTP %s" % response.status_code
    try:
        data = response.json()
    except ValueError:
        return None, "Invalid JSON received from the OTI Labs API"
    if not isinstance(data, dict):
        return None, "Unexpected response from the OTI Labs API"
    return data, None


class OTILabsParser:
    def __init__(self, attribute, subdomain_limit):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.attribute)
        self.domain = attribute["value"].strip().lower().rstrip(".")
        self.subdomain_limit = subdomain_limit
        self.objects = 0

    def parse(self, data):
        sections = {}
        for name in ("whois", "ssl", "dns", "email_security", "subdomains"):
            section = data.get(name)
            sections[name] = section if isinstance(section, dict) and "error" not in section else {}
        self._parse_whois(sections["whois"])
        self._parse_ssl(sections["ssl"])
        self._parse_dns(sections["dns"], sections["email_security"])
        self._parse_subdomains(sections["subdomains"])

    def results(self):
        if not self.objects:
            return {"error": "The OTI Labs API returned no data for %s." % self.domain}
        event = json.loads(self.misp_event.to_json())
        return {"results": {key: event[key] for key in ("Attribute", "Object") if key in event}}

    def _add(self, misp_object, relationship="characterizes"):
        misp_object.add_reference(self.attribute.uuid, relationship)
        self.misp_event.add_object(misp_object)
        self.objects += 1

    def _parse_whois(self, whois):
        if not whois:
            return
        whois_object = MISPObject("whois")
        whois_object.add_attribute("domain", self.domain)
        if whois.get("registrar"):
            whois_object.add_attribute("registrar", whois["registrar"])
        for relation, key in (
            ("creation-date", "created"),
            ("modification-date", "updated"),
            ("expiration-date", "expires"),
        ):
            value = _datetime(whois.get(key))
            if value:
                whois_object.add_attribute(relation, value)
        for nameserver in whois.get("nameservers") or []:
            nameserver = _hostname(nameserver)
            if nameserver:
                whois_object.add_attribute("nameserver", nameserver)
        if whois.get("status"):
            whois_object.add_attribute("text", "Status: %s" % ", ".join(whois["status"]), disable_correlation=True)
        if len(whois_object.attributes) > 1:
            self._add(whois_object)

    def _parse_ssl(self, ssl):
        if not ssl:
            return
        x509_object = MISPObject("x509")
        for relation, key in (
            ("issuer", "issuer"),
            ("subject", "subject"),
            ("serial-number", "serial_number"),
            ("signature_algorithm", "signature_algorithm"),
        ):
            if ssl.get(key):
                x509_object.add_attribute(relation, str(ssl[key]))
        for relation, key in (("validity-not-before", "valid_from"), ("validity-not-after", "valid_to")):
            value = _datetime(ssl.get(key))
            if value:
                x509_object.add_attribute(relation, value)
        for name in (ssl.get("sans") or [])[:SAN_LIMIT]:
            if isinstance(name, str) and name and not name.startswith("*"):
                x509_object.add_attribute("dns_names", name.lower())
        if ssl.get("issuer") or ssl.get("serial_number"):
            self._add(x509_object)

    def _parse_dns(self, dns, email_security):
        domain_object = MISPObject("domain-ip")
        domain_object.add_attribute("domain", self.domain)
        for address in (dns.get("A") or []) + (dns.get("AAAA") or []):
            if _is_ip(address):
                domain_object.add_attribute("ip", address)
        for text in self._email_security_texts(email_security):
            domain_object.add_attribute("text", text, disable_correlation=True)
        if len(domain_object.attributes) > 1:
            self._add(domain_object)

        record_object = MISPObject("dns-record")
        record_object.add_attribute("queried-domain", self.domain)
        for relation, key in (("mx-record", "MX"), ("ns-record", "NS"), ("soa-record", "SOA")):
            for value in dns.get(key) or []:
                name = _hostname(value.split()[0]) if key == "SOA" else _hostname(value)
                if name:
                    record_object.add_attribute(relation, name)
        for value in dns.get("TXT") or []:
            record_object.add_attribute("txt-record", _txt(value), disable_correlation=True)
        if dns.get("CAA"):
            record_object.add_attribute("text", "CAA: %s" % "; ".join(dns["CAA"]), disable_correlation=True)
        if len(record_object.attributes) > 1:
            self._add(record_object)

    @staticmethod
    def _email_security_texts(email_security):
        texts = []
        spf = email_security.get("spf")
        if isinstance(spf, dict):
            records = spf.get("records") or []
            texts.append("SPF: %s" % (" | ".join(records) if records else "MISSING"))
        dmarc = email_security.get("dmarc")
        if isinstance(dmarc, dict):
            records = dmarc.get("records") or []
            texts.append("DMARC: %s" % (" | ".join(records) if records else "MISSING"))
        dkim = email_security.get("dkim")
        if isinstance(dkim, dict):
            found = dkim.get("found") or []
            if found:
                texts.append("DKIM: found on selector(s) %s" % ", ".join(found))
            else:
                texts.append("DKIM: not found on the common selectors tested")
        return texts

    def _parse_subdomains(self, subdomains):
        if not subdomains:
            return
        live = subdomains.get("live") or []
        added = 0
        for item in live:
            if added >= self.subdomain_limit:
                break
            if not isinstance(item, dict):
                continue
            host = _hostname(item.get("host"))
            if not host or host == self.domain:
                continue
            subdomain_object = MISPObject("domain-ip")
            subdomain_object.add_attribute("hostname", host)
            target = item.get("ip")
            if isinstance(target, str) and _is_ip(target):
                subdomain_object.add_attribute("ip", target)
            elif isinstance(target, str) and target:
                subdomain_object.add_attribute("text", "CNAME target: %s" % target, disable_correlation=True)
            self._add(subdomain_object, "related-to")
            added += 1
        count = subdomains.get("count")
        if count is None:
            return
        live_count = subdomains.get("live_count")
        if live_count is None:
            # The first lookup of a domain returns before the API has resolved every name.
            summary = (
                "OTI Labs found %s subdomains of %s; the live check is still running, query again shortly for"
                " the live hosts and their IP addresses" % (count, self.domain)
            )
        else:
            summary = "OTI Labs found %s subdomains of %s, %s of them resolving now" % (count, self.domain, live_count)
            if added < len(live):
                summary += "; the first %s live ones were added" % added
        self.misp_event.add_attribute(type="text", value=summary, category="Other", disable_correlation=True)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    config = request.get("config") or {}
    apikey = config.get("apikey")
    if not apikey:
        misperrors["error"] = "An OTI Labs API key (a RapidAPI key) is required."
        return misperrors
    attribute = request.get("attribute")
    if not attribute or not check_input_attribute(attribute):
        return {"error": "%s, %s." % (standard_error_message, checking_error)}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type (expected domain or hostname)."}
    domain = attribute["value"].strip().lower().rstrip(".")
    data, error = _lookup(apikey, domain)
    if error:
        misperrors["error"] = error
        return misperrors
    parser = OTILabsParser(attribute, _subdomain_limit(config.get("subdomain_limit")))
    parser.parse(data)
    return parser.results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
