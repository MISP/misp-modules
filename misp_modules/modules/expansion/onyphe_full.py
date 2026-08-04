# -*- coding: utf-8 -*-

import ipaddress
import json

from pymisp import MISPEvent, MISPObject
from pyonyphe import Onyphe, OnypheError

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["ip-src", "ip-dst", "hostname", "domain"],
    "output": ["hostname", "domain", "ip-src", "ip-dst", "url", "port", "comment"],
    "format": "misp_standard",
}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "2",
    "author": "Sebastien Larinier @sebdraven",
    "description": "Module to process a full query on Onyphe.",
    "module-type": ["expansion", "hover"],
    "name": "Onyphe Full Lookup",
    "logo": "onyphe.jpg",
    "requirements": ["pyonyphe python library, version 3.0.3 or later", "An access to the Onyphe API (apikey)"],
    "features": (
        "This module takes a domain, hostname, or IP address attribute as input and runs one ONYPHE Query Language"
        " search per category (datascan, vulnscan, resolver, ctl, pastries, threatlist). The parsing is here more"
        " advanced than the one of the onyphe module, and returns more attributes, since more categories and more"
        " fields of the query results are watched and parsed.\n\nCategories the API key is not entitled to are"
        " skipped rather than failing the whole query, and are listed in a comment attribute so the analyst knows"
        " the event is partial."
    ),
    "references": ["https://www.onyphe.io/", "https://github.com/onyphe/pyonyphe"],
    "input": "A domain, hostname or IP address MISP attribute.",
    "output": "MISP attributes and objects fetched from the Onyphe queries.",
}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "limit"]

IP_TYPES = ("ip-src", "ip-dst")

# categories queried for an IP address and for a domain / hostname
IP_CATEGORIES = ("datascan", "vulnscan", "resolver", "ctl", "pastries", "threatlist")
ASSET_CATEGORIES = ("datascan", "resolver", "ctl", "pastries", "threatlist")

# results fetched per category, the Search API pages at 10000 anyway
DEFAULT_LIMIT = 100
PAGE_SIZE = 100

SKIPPED_PREFIX = "Onyphe categories not returned: "


def as_list(value):
    """ONYPHE returns either a scalar or a list depending on the document, normalise both."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def is_routable(value):
    """Reject private, loopback, link-local, multicast and otherwise reserved addresses.

    Pastes routinely contain configuration samples, so ONYPHE extracts 127.0.0.1, RFC1918
    ranges or 224.0.0.0 from them. Those are noise in a MISP event, not indicators.

    The checks are spelled out rather than delegated to `is_global`: multicast is not part of
    the private ranges, so `is_global` answers True for 224.0.0.1, and the exact semantics of
    `is_global` have moved across Python versions.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def looks_like_host(value):
    """Cheap sanity check for names mined from the free text of a paste."""
    if not isinstance(value, str):
        return False
    value = value.strip()
    return bool(value) and "." in value and not any(char in value for char in " \t/:@")


class OnypheFullClient:

    def __init__(self, api_key, attribute, limit=DEFAULT_LIMIT):
        self.onyphe_client = Onyphe(api_key=api_key)
        self.attribute = attribute
        self.limit = limit
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.skipped = []
        self.__seen = set()

    def close(self):
        self.onyphe_client.close()

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if key in event}
        return results

    # -- querying -----------------------------------------------------------

    def get_query_onyphe(self):
        categories = IP_CATEGORIES if self.attribute["type"] in IP_TYPES else ASSET_CATEGORIES
        parsers = {
            "ctl": self.__parse_certificate,
            "datascan": self.__parse_datascan,
            "pastries": self.__parse_pastries,
            "resolver": self.__parse_resolver,
            "threatlist": self.__parse_threatlist,
            "vulnscan": self.__parse_vulnscan,
        }
        for category in categories:
            try:
                for hit in self.__search(category):
                    parsers[category](hit)
            except OnypheError as e:
                # a license may not cover every category, that is not a reason to fail the lookup
                self.skipped.append(f"{category}: {e}")
        self.__report_skipped()

    def __search(self, category):
        query = f"category:{category} {self.__field()}:{self.attribute['value']}"
        return self.onyphe_client.search_iter(query, size=PAGE_SIZE, max_results=self.limit)

    def __field(self):
        if self.attribute["type"] in IP_TYPES:
            return "ip"
        if self.attribute["type"] == "domain":
            return "domain"
        return "hostname"

    def __report_skipped(self):
        """Surface the categories that were dropped instead of letting them vanish.

        A key not entitled to vulnscan produces an event that simply holds no vulnerability,
        with nothing telling the analyst whether the asset is clean or the query incomplete.
        """
        if not self.skipped:
            return
        self.__add_attribute(
            "comment",
            SKIPPED_PREFIX + "; ".join(self.skipped),
            category="Other",
            to_ids=False,
            comment="These Onyphe categories were not queried successfully, the event is partial",
        )

    # -- helpers ------------------------------------------------------------

    def __already(self, attribute_type, value):
        return ("attribute", attribute_type, str(value)) in self.__seen

    def __add_attribute(self, attribute_type, value, **kwargs):
        """Add an event attribute once, ONYPHE repeats the same observation across documents."""
        if not value:
            return
        key = ("attribute", attribute_type, str(value))
        if key in self.__seen:
            return
        self.__seen.add(key)
        self.misp_event.add_attribute(attribute_type, value, **kwargs)

    def __add_object(self, misp_object, signature):
        key = ("object", misp_object.name, signature)
        if key in self.__seen:
            return None
        self.__seen.add(key)
        misp_object.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(misp_object)
        return misp_object

    # -- parsers ------------------------------------------------------------

    def __parse_datascan(self, hit):
        misp_object = MISPObject("ip-port")
        anchored = False

        for ip in as_list(hit.get("ip")):
            misp_object.add_attribute("ip", ip)
            anchored = True
        for domain in as_list(hit.get("domain")):
            misp_object.add_attribute("domain", domain)
            anchored = True
        for hostname in as_list(hit.get("hostname")):
            misp_object.add_attribute("hostname", hostname)
            anchored = True
        if hit.get("port"):
            misp_object.add_attribute("dst-port", hit["port"])
            anchored = True

        if not anchored:
            return

        if hit.get("transport"):
            misp_object.add_attribute("protocol", hit["transport"])
        if hit.get("asn"):
            misp_object.add_attribute("AS", hit["asn"])
        if hit.get("country"):
            misp_object.add_attribute("country-code", hit["country"])
        if hit.get("seen_date"):
            misp_object.add_attribute("last-seen", hit["seen_date"])

        description = " ".join(
            str(hit[field]) for field in ("protocol", "product", "productversion", "organization") if hit.get(field)
        )
        if description:
            misp_object.add_attribute("text", description)

        signature = f"{hit.get('ip')}|{hit.get('port')}|{hit.get('transport')}"
        if self.__add_object(misp_object, signature) is None:
            return

        for cve in as_list(hit.get("cve")):
            self.__add_vulnerability(cve, misp_object.uuid)

        if "issuer" in hit:
            self.__parse_certificate(hit)

    def __parse_vulnscan(self, hit):
        for cve in as_list(hit.get("cve")):
            self.__add_vulnerability(cve, None)

    def __parse_resolver(self, hit):
        for ip in as_list(hit.get("ip")):
            self.__add_attribute("ip-dst", ip, category="Network activity")
        for domain in as_list(hit.get("domain")):
            self.__add_attribute("domain", domain, category="Network activity")
        # `reverse` and `forward` hold fully qualified names, not registrable domains
        for hostname in as_list(hit.get("hostname")) + as_list(hit.get("reverse")) + as_list(hit.get("forward")):
            if not self.__already("domain", hostname):
                self.__add_attribute("hostname", hostname, category="Network activity")

        for ip in as_list(hit.get("ip")):
            for name in as_list(hit.get("domain")):
                misp_object = MISPObject("domain-ip")
                misp_object.add_attribute("ip", ip)
                misp_object.add_attribute("domain", name)
                if hit.get("type"):
                    misp_object.add_attribute("text", f"{hit['type']} record seen by Onyphe")
                self.__add_object(misp_object, f"{ip}|{name}")

    def __parse_pastries(self, hit):
        # everything mined from the text of a paste is context, not an observation of the
        # queried asset: it is added with to_ids disabled so it never reaches a detection feed
        if hit.get("source") == "pastebin" and hit.get("key"):
            self.__add_attribute(
                "url",
                f"https://pastebin.com/raw/{hit['key']}",
                category="External analysis",
                to_ids=False,
                comment=f"Paste where {self.attribute['value']} was found by Onyphe",
            )

        comment = "Found in a paste indexed by Onyphe"
        for domain in as_list(hit.get("domain")):
            if looks_like_host(domain):
                self.__add_attribute("domain", domain, category="Network activity", to_ids=False, comment=comment)
        for hostname in as_list(hit.get("hostname")):
            if looks_like_host(hostname) and not self.__already("domain", hostname):
                self.__add_attribute("hostname", hostname, category="Network activity", to_ids=False, comment=comment)
        for ip in as_list(hit.get("ip")):
            if is_routable(ip):
                self.__add_attribute("ip-dst", ip, category="Network activity", to_ids=False, comment=comment)

    def __parse_threatlist(self, hit):
        threatlist = hit.get("threatlist")
        if not threatlist:
            return
        self.__add_attribute(
            "comment",
            f"seen {hit.get('seen_date', 'at an unknown date')} on {threatlist}",
            category="Other",
            comment=f"{self.attribute['value']} is present in an Onyphe threatlist",
        )

    def __parse_certificate(self, hit):
        fingerprint = hit.get("fingerprint") or {}
        signature = fingerprint.get("sha256") or hit.get("serial")
        if not signature:
            return

        misp_object = MISPObject("x509")

        # note: the x509 `ip` relation is a Subject Alternative Name, not the host serving the
        # certificate -- the queried value is tied to the object through its reference instead.
        if hit.get("serial"):
            misp_object.add_attribute("serial-number", hit["serial"])

        for algorithm in ("md5", "sha1", "sha256"):
            if fingerprint.get(algorithm):
                misp_object.add_attribute(f"x509-fingerprint-{algorithm}", fingerprint[algorithm])

        algorithm = (hit.get("signature") or {}).get("algorithm", "")
        value = ""
        if "sha256" in algorithm and "RSA" in algorithm:
            value = "SHA256_WITH_RSA_ENCRYPTION"
        elif "sha1" in algorithm and "RSA" in algorithm:
            value = "SHA1_WITH_RSA_ENCRYPTION"
        if value:
            misp_object.add_attribute("signature_algorithm", value)

        publickey = hit.get("publickey") or {}
        if publickey.get("algorithm"):
            misp_object.add_attribute("pubkey-info-algorithm", publickey["algorithm"])
        if "exponent" in publickey:
            misp_object.add_attribute("pubkey-info-exponent", publickey["exponent"])
        if "length" in publickey:
            misp_object.add_attribute("pubkey-info-size", publickey["length"])

        issuer = (hit.get("issuer") or {}).get("commonname")
        if issuer:
            misp_object.add_attribute("issuer", issuer)

        subject = (hit.get("subject") or {}).get("commonname")
        if subject:
            misp_object.add_attribute("subject", subject)

        validity = hit.get("validity") or {}
        if validity.get("notbefore"):
            misp_object.add_attribute("validity-not-before", validity["notbefore"])
        if validity.get("notafter"):
            misp_object.add_attribute("validity-not-after", validity["notafter"])

        self.__add_object(misp_object, signature)

    def __add_vulnerability(self, cve, referenced_uuid):
        misp_object = MISPObject("vulnerability")
        misp_object.add_attribute("id", cve)
        misp_object.add_attribute("state", "Published")
        if self.__add_object(misp_object, cve) is None:
            return
        if referenced_uuid:
            misp_object.add_reference(referenced_uuid, "affects")


def handler(q=False):
    if not q:
        return False

    request = json.loads(q)
    attribute = request["attribute"]

    if not request.get("config") or not request["config"].get("apikey"):
        misperrors["error"] = "Onyphe authentication is missing"
        return misperrors

    try:
        limit = int(request["config"].get("limit") or DEFAULT_LIMIT)
    except (TypeError, ValueError):
        limit = DEFAULT_LIMIT

    onyphe_client = OnypheFullClient(request["config"]["apikey"], attribute, limit)
    try:
        onyphe_client.get_query_onyphe()
    except OnypheError as e:
        misperrors["error"] = f"Onyphe error: {e}"
        return misperrors
    finally:
        onyphe_client.close()

    return {"results": onyphe_client.get_results()}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
