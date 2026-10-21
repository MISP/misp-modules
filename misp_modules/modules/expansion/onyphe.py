# -*- coding: utf-8 -*-

import json

from pymisp import MISPEvent, MISPObject
from pyonyphe import Onyphe, OnypheError

from . import onyphe_full

misperrors = {"error": "Error"}

mispattributes = {
    "input": list(onyphe_full.mispattributes["input"]),
    "output": ["hostname", "domain", "ip-src", "ip-dst", "url"],
    "format": "misp_standard",
}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "4",
    "author": "Sebastien Larinier @sebdraven",
    "description": "Module to process a query on Onyphe.",
    "module-type": ["expansion", "hover"],
    "name": "Onyphe Lookup",
    "logo": "onyphe.jpg",
    "requirements": ["pyonyphe python library, version 3.1.0 or later", "An access to the Onyphe API (apikey)"],
    "features": (
        "Enriches IPs and hostnames using ctiscan Search and domains using riskscan/vulnscan Search. "
        "Uses category-specific field names and returns service observations, endpoints, certificates and CVEs. "
        "Set mode=summary to keep the legacy Summary lookup, which does not return ctiscan/ctiurl. "
        "Install the bundled onyphe-service template in MISP for Search results."
    ),
    "references": [
        "https://www.onyphe.io/",
        "https://github.com/onyphe/pyonyphe",
        "https://github.com/onyphe/material/tree/master/openapi",
    ],
    "input": "An IP, domain, hostname, URL, CPE or X.509 fingerprint MISP attribute.",
    "output": "MISP attributes fetched from the Onyphe query.",
}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "mode", "limit", "timeout", "since"]

IP_TYPES = ("ip-src", "ip-dst")


def as_list(value):
    """ONYPHE returns either a scalar or a list depending on the document, normalise both."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


class OnypheClient(onyphe_full.OnypheFullClient):

    def __init__(self, api_key, attribute):
        self.onyphe_client = Onyphe(api_key=api_key)
        self.attribute = attribute
        self.objects = {}
        self.misp_event = MISPEvent()
        source = self.misp_event.add_attribute(**attribute)
        self.attribute = source.to_dict()

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
        self.parse_certificate(r)

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
    config = request.get("config") or {}
    mode = config.get("mode") or "search"
    if mode not in ("search", "summary"):
        return {"error": "Invalid Onyphe mode; use search or summary"}
    if mode == "search":
        attribute_type = (request.get("attribute") or {}).get("type")
        config["categories"] = (
            "riskscan,vulnscan" if attribute_type == "domain" else "ctiurl" if attribute_type == "url" else "ctiscan"
        )
        request["config"] = config
        return onyphe_full.handler(json.dumps(request))
    attribute = request.get("attribute") or {}
    if attribute.get("type") not in (*IP_TYPES, "domain", "hostname"):
        return {"error": "Summary mode supports only IP, domain and hostname attributes"}

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
