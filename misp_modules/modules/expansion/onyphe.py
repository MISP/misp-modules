# -*- coding: utf-8 -*-

import json

from pymisp import MISPEvent, MISPObject
from pyonyphe import Onyphe, OnypheError

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["ip-src", "ip-dst", "hostname", "domain"],
    "output": ["hostname", "domain", "ip-src", "ip-dst", "url"],
    "format": "misp_standard",
}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "3",
    "author": "Sebastien Larinier @sebdraven",
    "description": "Module to process a query on Onyphe.",
    "module-type": ["expansion", "hover"],
    "name": "Onyphe Lookup",
    "logo": "onyphe.jpg",
    "requirements": ["pyonyphe python library, version 3.0.3 or later", "An access to the Onyphe API (apikey)"],
    "features": (
        "This module takes a domain, hostname, or IP address attribute as input in order to query the Onyphe Summary"
        " API. Data fetched from the query is then parsed and MISP attributes and objects are extracted."
    ),
    "references": ["https://www.onyphe.io/", "https://github.com/onyphe/pyonyphe"],
    "input": "A domain, hostname or IP address MISP attribute.",
    "output": "MISP attributes fetched from the Onyphe query.",
}

# config fields that your code expects from the site admin
moduleconfig = ["apikey"]

IP_TYPES = ("ip-src", "ip-dst")


def as_list(value):
    """ONYPHE returns either a scalar or a list depending on the document, normalise both."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


class OnypheClient:

    def __init__(self, api_key, attribute):
        self.onyphe_client = Onyphe(api_key=api_key)
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)

    def close(self):
        self.onyphe_client.close()

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if key in event}
        return results

    def get_query_onyphe(self):
        if self.attribute["type"] in IP_TYPES:
            self.__summary_ip()
        elif self.attribute["type"] == "domain":
            self.__summary_domain()
        elif self.attribute["type"] == "hostname":
            self.__summary_hostname()

    def __summary_ip(self):
        for r in self.onyphe_client.summary_ip(self.attribute["value"]).results:
            for domain in as_list(r.get("domain")):
                self.__get_object_domain_ip(domain, "domain")

            for hostname in as_list(r.get("hostname")):
                self.__get_object_domain_ip(hostname, "hostname")

            if "issuer" in r:
                self.__get_object_certificate(r)

    def __summary_domain(self):
        for r in self.onyphe_client.summary_domain(self.attribute["value"]).results:
            for domain in as_list(r.get("domain")):
                self.misp_event.add_attribute("domain", domain)

            for hostname in as_list(r.get("hostname")):
                self.misp_event.add_attribute("hostname", hostname)

            for ip in as_list(r.get("ip")):
                self.__get_object_domain_ip(ip, "ip")

            if "issuer" in r:
                self.__get_object_certificate(r)

    def __summary_hostname(self):
        for r in self.onyphe_client.summary_hostname(self.attribute["value"]).results:
            for domain in as_list(r.get("domain")):
                self.misp_event.add_attribute("domain", domain)

            for hostname in as_list(r.get("hostname")):
                self.misp_event.add_attribute("hostname", hostname)

            for ip in as_list(r.get("ip")):
                self.__get_object_domain_ip(ip, "ip")

            if "issuer" in r:
                self.__get_object_certificate(r)

            for cve in as_list(r.get("cve")):
                self.__get_object_cve(r, cve)

    def __get_object_certificate(self, r):
        object_certificate = MISPObject("x509")

        # note: the x509 `ip` relation is a Subject Alternative Name, not the host serving the
        # certificate -- the queried value is tied to the object through its reference instead.
        if r.get("serial"):
            object_certificate.add_attribute("serial-number", r["serial"])

        fingerprint = r.get("fingerprint") or {}
        for algorithm in ("md5", "sha1", "sha256"):
            if fingerprint.get(algorithm):
                object_certificate.add_attribute(f"x509-fingerprint-{algorithm}", fingerprint[algorithm])

        signature = (r.get("signature") or {}).get("algorithm", "")
        value = ""
        if "sha256" in signature and "RSA" in signature:
            value = "SHA256_WITH_RSA_ENCRYPTION"
        elif "sha1" in signature and "RSA" in signature:
            value = "SHA1_WITH_RSA_ENCRYPTION"
        if value:
            object_certificate.add_attribute("signature_algorithm", value)

        publickey = r.get("publickey") or {}
        if publickey.get("algorithm"):
            object_certificate.add_attribute("pubkey-info-algorithm", publickey["algorithm"])
        if "exponent" in publickey:
            object_certificate.add_attribute("pubkey-info-exponent", publickey["exponent"])
        if "length" in publickey:
            object_certificate.add_attribute("pubkey-info-size", publickey["length"])

        issuer = (r.get("issuer") or {}).get("commonname")
        if issuer:
            object_certificate.add_attribute("issuer", issuer)

        subject = (r.get("subject") or {}).get("commonname")
        if subject:
            object_certificate.add_attribute("subject", subject)

        validity = r.get("validity") or {}
        if validity.get("notbefore"):
            object_certificate.add_attribute("validity-not-before", validity["notbefore"])
        if validity.get("notafter"):
            object_certificate.add_attribute("validity-not-after", validity["notafter"])

        object_certificate.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(object_certificate)

    def __get_object_domain_ip(self, obs, relation):
        objet_domain_ip = MISPObject("domain-ip")
        objet_domain_ip.add_attribute(relation, obs)
        relation_attr = self.__get_relation_attribute()
        if relation_attr:
            objet_domain_ip.add_attribute(relation_attr, self.attribute["value"])
            objet_domain_ip.add_reference(self.attribute["uuid"], "related-to")
            self.misp_event.add_object(objet_domain_ip)

    def __get_relation_attribute(self):

        if self.attribute["type"] in IP_TYPES:
            return "ip"
        elif self.attribute["type"] == "domain":
            return "domain"
        elif self.attribute["type"] == "hostname":
            return "hostname"

    def __get_object_cve(self, item, cve):
        object_cve = MISPObject("vulnerability")
        object_cve.add_attribute("id", cve)
        object_cve.add_attribute("state", "Published")

        for ip in as_list(item.get("ip")):
            for misp_object in self.misp_event.objects:
                if any(att.value == ip for att in misp_object.attributes):
                    object_cve.add_reference(misp_object.uuid, "affects")

        object_cve.add_reference(self.attribute["uuid"], "affects")
        self.misp_event.add_object(object_cve)


def handler(q=False):
    if not q:
        return False

    request = json.loads(q)
    attribute = request["attribute"]

    if not request.get("config") or not request["config"].get("apikey"):
        misperrors["error"] = "Onyphe authentication is missing"
        return misperrors

    api_key = request["config"].get("apikey")

    onyphe_client = OnypheClient(api_key, attribute)
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
