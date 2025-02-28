# -*- coding: utf-8 -*-

import json

from pymisp import MISPEvent, MISPObject

from misp_modules.lib.onyphe import Onyphe

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["ip-src", "ip-dst", "hostname", "domain"],
    "output": ["hostname", "domain", "ip-src", "ip-dst", "url"],
    "format": "misp_standard",
}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "2",
    "author": "Sebastien Larinier @sebdraven",
    "description": "Module to process a query on Onyphe.",
    "module-type": ["expansion", "hover"],
    "name": "Onyphe Lookup",
    "logo": "onyphe.jpg",
    "requirements": ["onyphe python library", "An access to the Onyphe API (apikey)"],
    "features": (
        "This module takes a domain, hostname, or IP address attribute as input in order to query the Onyphe API. Data"
        " fetched from the query is then parsed and MISP attributes are extracted."
    ),
    "references": ["https://www.onyphe.io/", "https://github.com/sebdraven/pyonyphe"],
    "input": "A domain, hostname or IP address MISP attribute.",
    "output": "MISP attributes fetched from the Onyphe query.",
}

# config fields that your code expects from the site admin
moduleconfig = ["apikey"]


class OnypheClient:

    def __init__(self, api_key, attribute):
        self.onyphe_client = Onyphe(api_key=api_key)
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if key in event}
        return results

    def get_query_onyphe(self):
        if self.attribute["type"] == "ip-src" or self.attribute["type"] == "ip-dst":
            self.__summary_ip()
        if self.attribute["type"] == "domain":
            self.__summary_domain()
        if self.attribute["type"] == "hostname":
            self.__summary_hostname()

    def __summary_ip(self):
        results = self.onyphe_client.summary_ip(self.attribute["value"])
        if "results" in results:
            for r in results["results"]:
                if "domain" in r:
                    domain = r["domain"]
                    if isinstance(domain, list):
                        for d in domain:
                            self.__get_object_domain_ip(d, "domain")
                    elif isinstance(domain, str):
                        self.__get_object_domain_ip(domain, "domain")

                if "hostname" in r:
                    hostname = r["hostname"]
                    if isinstance(hostname, list):
                        for d in hostname:
                            self.__get_object_domain_ip(d, "domain")
                    elif isinstance(hostname, str):
                        self.__get_object_domain_ip(hostname, "domain")

                if "issuer" in r:
                    self.__get_object_certificate(r)

    def __summary_domain(self):
        results = self.onyphe_client.summary_domain(self.attribute["value"])
        if "results" in results:
            for r in results["results"]:

                for domain in r.get("domain"):
                    self.misp_event.add_attribute("domain", domain)
                for hostname in r.get("hostname"):
                    self.misp_event.add_attribute("hostname", hostname)
                if "ip" in r:
                    if type(r["ip"]) is str:
                        self.__get_object_domain_ip(r["ip"], "ip")
                    if type(r["ip"]) is list:
                        for ip in r["ip"]:
                            self.__get_object_domain_ip(ip, "ip")
                if "issuer" in r:
                    self.__get_object_certificate(r)

    def __summary_hostname(self):
        results = self.onyphe_client.summary_hostname(self.attribute["value"])
        if "results" in results:

            for r in results["results"]:
                if "domain" in r:
                    if type(r["domain"]) is str:
                        self.misp_event.add_attribute("domain", r["domain"])
                    if type(r["domain"]) is list:
                        for domain in r["domain"]:
                            self.misp_event.add_attribute("domain", domain)

                if "hostname" in r:
                    if type(r["hostname"]) is str:
                        self.misp_event.add_attribute("hostname", r["hostname"])
                    if type(r["hostname"]) is list:
                        for hostname in r["hostname"]:
                            self.misp_event.add_attribute("hostname", hostname)

                if "ip" in r:
                    if type(r["ip"]) is str:
                        self.__get_object_domain_ip(r["ip"], "ip")
                    if type(r["ip"]) is list:
                        for ip in r["ip"]:
                            self.__get_object_domain_ip(ip, "ip")

                if "issuer" in r:
                    self.__get_object_certificate(r)

                if "cve" in r:
                    if type(r["cve"]) is list:
                        for cve in r["cve"]:
                            self.__get_object_cve(r, cve)

    def __get_object_certificate(self, r):
        object_certificate = MISPObject("x509")
        object_certificate.add_attribute("ip", self.attribute["value"])
        object_certificate.add_attribute("serial-number", r["serial"])
        object_certificate.add_attribute("x509-fingerprint-sha256", r["fingerprint"]["sha256"])
        object_certificate.add_attribute("x509-fingerprint-sha1", r["fingerprint"]["sha1"])
        object_certificate.add_attribute("x509-fingerprint-md5", r["fingerprint"]["md5"])

        signature = r["signature"]["algorithm"]
        value = ""
        if "sha256" in signature and "RSA" in signature:
            value = "SHA256_WITH_RSA_ENCRYPTION"
        elif "sha1" in signature and "RSA" in signature:
            value = "SHA1_WITH_RSA_ENCRYPTION"
        if value:
            object_certificate.add_attribute("signature_algorithm", value)

        object_certificate.add_attribute("pubkey-info-algorithm", r["publickey"]["algorithm"])

        if "exponent" in r["publickey"]:
            object_certificate.add_attribute("pubkey-info-exponent", r["publickey"]["exponent"])
        if "length" in r["publickey"]:
            object_certificate.add_attribute("pubkey-info-size", r["publickey"]["length"])

        object_certificate.add_attribute("issuer", r["issuer"]["commonname"])
        object_certificate.add_attribute("validity-not-before", r["validity"]["notbefore"])
        object_certificate.add_attribute("validity-not-after", r["validity"]["notbefore"])
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

        if self.attribute["type"] == "ip-src":
            return "ip"
        elif self.attribute["type"] == "ip-dst":
            return "ip"
        elif self.attribute["type"] == "domain":
            return "domain"
        elif self.attribute["type"] == "hostname":
            return "domain"

    def __get_object_cve(self, item, cve):
        attributes = []
        object_cve = MISPObject("vulnerability")
        object_cve.add_attribute("id", cve)
        object_cve.add_attribute("state", "Published")

        if type(item["ip"]) is list:
            for ip in item["ip"]:
                attributes.extend(list(filter(lambda x: x["value"] == ip, self.misp_event["Attribute"])))
                for obj in self.misp_event["Object"]:
                    attributes.extend(list(filter(lambda x: x["value"] == ip, obj["Attribute"])))
        if type(item["ip"]) is str:

            for obj in self.misp_event["Object"]:
                for att in obj["Attribute"]:
                    if att["value"] == item["ip"]:
                        object_cve.add_reference(obj["uuid"], "cve")

        self.misp_event.add_object(object_cve)


def handler(q=False):
    if q:

        request = json.loads(q)
        attribute = request["attribute"]

        if not request.get("config") or not request["config"].get("apikey"):
            misperrors["error"] = "Onyphe authentication is missing"
            return misperrors

        api_key = request["config"].get("apikey")

        onyphe_client = OnypheClient(api_key, attribute)
        onyphe_client.get_query_onyphe()
        results = onyphe_client.get_results()

        return {"results": results}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
