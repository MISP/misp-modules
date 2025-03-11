# -*- coding: utf-8 -*-

import json
from datetime import datetime

import shodan
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.2",
    "author": "Raphaël Vinot",
    "description": "Module to query on Shodan.",
    "module-type": ["expansion"],
    "name": "Shodan Lookup",
    "logo": "shodan.png",
    "requirements": ["shodan python library", "An access to the Shodan API (apikey)"],
    "features": (
        "The module takes an IP address as input and queries the Shodan API to get some additional data about it."
    ),
    "references": ["https://www.shodan.io/"],
    "input": "An IP address MISP attribute.",
    "output": "Text with additional data about the input, resulting from the query on Shodan.",
}

moduleconfig = ["apikey"]


class ShodanParser:
    def __init__(self, attribute):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.attribute)
        self.ip_address_mapping = {
            "asn": {"type": "AS", "object_relation": "asn"},
            "city": {"type": "text", "object_relation": "city"},
            "country_code": {"type": "text", "object_relation": "country-code"},
            "country_name": {"type": "text", "object_relation": "country"},
            "isp": {"type": "text", "object_relation": "ISP"},
            "latitude": {"type": "float", "object_relation": "latitude"},
            "longitude": {"type": "float", "object_relation": "longitude"},
            "org": {"type": "text", "object_relation": "organization"},
            "postal_code": {"type": "text", "object_relation": "zipcode"},
            "region_code": {"type": "text", "object_relation": "region-code"},
        }
        self.ip_port_mapping = {
            "domains": {"type": "domain", "object_relation": "domain"},
            "hostnames": {"type": "hostname", "object_relation": "hostname"},
        }
        self.vulnerability_mapping = {
            "cvss": {"type": "float", "object_relation": "cvss-score"},
            "summary": {"type": "text", "object_relation": "summary"},
        }
        self.x509_mapping = {
            "bits": {"type": "text", "object_relation": "pubkey-info-size"},
            "expires": {"type": "datetime", "object_relation": "validity-not-after"},
            "issued": {"type": "datetime", "object_relation": "validity-not-before"},
            "issuer": {"type": "text", "object_relation": "issuer"},
            "serial": {"type": "text", "object_relation": "serial-number"},
            "sig_alg": {"type": "text", "object_relation": "signature_algorithm"},
            "subject": {"type": "text", "object_relation": "subject"},
            "type": {"type": "text", "object_relation": "pubkey-info-algorithm"},
            "version": {"type": "text", "object_relation": "version"},
        }

    def query_shodan(self, apikey):
        # Query Shodan and get the results in a json blob
        api = shodan.Shodan(apikey)
        query_results = api.host(self.attribute.value)

        # Parse the information about the IP address used as input
        ip_address_attributes = []
        for feature, mapping in self.ip_address_mapping.items():
            if query_results.get(feature):
                attribute = {"value": query_results[feature]}
                attribute.update(mapping)
                ip_address_attributes.append(attribute)
        if ip_address_attributes:
            ip_address_object = MISPObject("ip-api-address")
            for attribute in ip_address_attributes:
                ip_address_object.add_attribute(**attribute)
            ip_address_object.add_reference(self.attribute.uuid, "describes")
            self.misp_event.add_object(ip_address_object)

        # Parse the hostnames / domains and ports associated with the IP address
        if query_results.get("ports"):
            ip_port_object = MISPObject("ip-port")
            ip_port_object.add_attribute(**self._get_source_attribute())
            feature = self.attribute.type.split("-")[1]
            for port in query_results["ports"]:
                attribute = {
                    "type": "port",
                    "object_relation": f"{feature}-port",
                    "value": port,
                }
                ip_port_object.add_attribute(**attribute)
            for feature, mapping in self.ip_port_mapping.items():
                for value in query_results.get(feature, []):
                    attribute = {"value": value}
                    attribute.update(mapping)
                    ip_port_object.add_attribute(**attribute)
            ip_port_object.add_reference(self.attribute.uuid, "extends")
            self.misp_event.add_object(ip_port_object)
        else:
            if any(query_results.get(feature) for feature in ("domains", "hostnames")):
                domain_ip_object = MISPObject("domain-ip")
                domain_ip_object.add_attribute(**self._get_source_attribute())
                for feature in ("domains", "hostnames"):
                    for value in query_results[feature]:
                        attribute = {
                            "type": "domain",
                            "object_relation": "domain",
                            "value": value,
                        }
                        domain_ip_object.add_attribute(**attribute)
                domain_ip_object.add_reference(self.attribute.uuid, "extends")
                self.misp_event.add_object(domain_ip_object)

        # Parse data within the "data" field
        if query_results.get("vulns"):
            vulnerabilities = {}
            for data in query_results["data"]:
                # Parse vulnerabilities
                if data.get("vulns"):
                    for cve, vulnerability in data["vulns"].items():
                        if cve not in vulnerabilities:
                            vulnerabilities[cve] = vulnerability
                # Also parse the certificates
                if data.get("ssl"):
                    self._parse_cert(data["ssl"])
            for cve, vulnerability in vulnerabilities.items():
                vulnerability_object = MISPObject("vulnerability")
                vulnerability_object.add_attribute(**{"type": "vulnerability", "object_relation": "id", "value": cve})
                for feature, mapping in self.vulnerability_mapping.items():
                    if vulnerability.get(feature):
                        attribute = {"value": vulnerability[feature]}
                        attribute.update(mapping)
                        vulnerability_object.add_attribute(**attribute)
                if vulnerability.get("references"):
                    for reference in vulnerability["references"]:
                        vulnerability_object.add_attribute(
                            **{
                                "type": "link",
                                "object_relation": "references",
                                "value": reference,
                            }
                        )
                vulnerability_object.add_reference(self.attribute.uuid, "vulnerability-of")
                self.misp_event.add_object(vulnerability_object)
            for cve_id in query_results["vulns"]:
                if cve_id not in vulnerabilities:
                    attribute = {"type": "vulnerability", "value": cve_id}
                    self.misp_event.add_attribute(**attribute)
        else:
            # We have no vulnerability data, we only check if we have
            # certificates within the "data" field
            for data in query_results["data"]:
                if data.get("ssl"):
                    self._parse_cert(data["ssl"]["cert"])

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": results}

    # When we want to add the IP address information in objects such as the
    # domain-ip or ip-port objects referencing the input IP address attribute
    def _get_source_attribute(self):
        return {
            "type": self.attribute.type,
            "object_relation": self.attribute.type,
            "value": self.attribute.value,
        }

    def _parse_cert(self, certificate):
        x509_object = MISPObject("x509")
        for feature in ("serial", "sig_alg", "version"):
            if certificate.get(feature):
                attribute = {"value": certificate[feature]}
                attribute.update(self.x509_mapping[feature])
                x509_object.add_attribute(**attribute)
        # Parse issuer and subject value
        for feature in ("issuer", "subject"):
            if certificate.get(feature):
                attribute_value = (f"{identifier}={value}" for identifier, value in certificate[feature].items())
                attribute = {"value": f'/{"/".join(attribute_value)}'}
                attribute.update(self.x509_mapping[feature])
                x509_object.add_attribute(**attribute)
        # Parse datetime attributes
        for feature in ("expires", "issued"):
            if certificate.get(feature):
                attribute = {"value": datetime.strptime(certificate[feature], "%Y%m%d%H%M%SZ")}
                attribute.update(self.x509_mapping[feature])
                x509_object.add_attribute(**attribute)
        # Parse fingerprints
        if certificate.get("fingerprint"):
            for hash_type, hash_value in certificate["fingerprint"].items():
                x509_object.add_attribute(
                    **{
                        "type": f"x509-fingerprint-{hash_type}",
                        "object_relation": f"x509-fingerprint-{hash_type}",
                        "value": hash_value,
                    }
                )
        # Parse public key related info
        if certificate.get("pubkey"):
            for feature, value in certificate["pubkey"].items():
                attribute = {"value": value}
                attribute.update(self.x509_mapping[feature])
                x509_object.add_attribute(**attribute)
        x509_object.add_reference(self.attribute.uuid, "identifies")
        self.misp_event.add_object(x509_object)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("config", {}).get("apikey"):
        return {"error": "Shodan authentication is missing"}
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    shodan_parser = ShodanParser(attribute)
    shodan_parser.query_shodan(request["config"]["apikey"])
    return shodan_parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
