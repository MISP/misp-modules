import ipaddress
import json
import logging

from greynoise.api import APIConfig, GreyNoise
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

logger = logging.getLogger("greynoise")
logger.setLevel(logging.INFO)

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["ip-src", "ip-dst", "vulnerability"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "2.0",
    "author": "Brad Chiappetta <brad@greynoise.io>",
    "description": "Module to query IP and CVE information from GreyNoise",
    "module-type": ["expansion", "hover"],
    "name": "GreyNoise Lookup",
    "logo": "greynoise.png",
    "requirements": [
        "A Greynoise API key. Both Enterprise (Paid) and Community (Free) API keys are supported, however Community API"
        " users will only be able to perform IP lookups."
    ],
    "features": (
        "This module supports: 1) Query an IP from GreyNoise to see if it is internet background noise or a common"
        " business service 2) Query a CVE from GreyNoise to see the total number of internet scanners looking for the"
        " CVE in the last 7 days."
    ),
    "references": [
        "https://greynoise.io/",
        "https://docs.greyniose.io/",
        "https://www.greynoise.io/viz/account/",
    ],
    "input": "An IP address or CVE ID",
    "output": "IP Lookup information or CVE scanning profile for past 7 days",
}
moduleconfig = ["api_key"]


class GreyNoiseParser:
    def __init__(self, attribute):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.attribute)
        self.ip_address_enrich_mapping = {
            "noise": {"type": "boolean", "object_relation": "noise"},
            "riot": {"type": "boolean", "object_relation": "riot"},
            "classification": {"type": "text", "object_relation": "classification"},
            "actor": {"type": "text", "object_relation": "actor"},
            "trust_level": {"type": "text", "object_relation": "trust-level"},
            "name": {"type": "text", "object_relation": "provider"},
            "first_seen": {"type": "datetime", "object_relation": "first-seen"},
            "last_seen_timestamp": {"type": "datetime", "object_relation": "last-seen"},
            "link": {"type": "url", "object_relation": "link"},
            "last_updated": {"type": "datetime", "object_relation": "last-seen"},
        }
        self.ip_address_hover_mapping = {
            "noise": {"type": "boolean", "object_relation": "noise"},
            "riot": {"type": "boolean", "object_relation": "riot"},
            "classification": {"type": "text", "object_relation": "classification"},
            "actor": {"type": "text", "object_relation": "actor"},
            "tags": {"type": "text", "object_relation": "tags"},
            "cves": {"type": "text", "object_relation": "cve"},
            "vpn": {"type": "text", "object_relation": "vpn"},
            "vpn_service": {"type": "text", "object_relation": "vpn_service"},
            "tor": {"type": "text", "object_relation": "tor"},
            "first_seen": {"type": "datetime", "object_relation": "first-seen"},
            "last_seen_timestamp": {"type": "datetime", "object_relation": "last-seen"},
            "spoofable": {"type": "datetime", "object_relation": "spoofable"},
            "link": {"type": "url", "object_relation": "link"},
            "category": {"type": "text", "object_relation": "category"},
            "name": {"type": "text", "object_relation": "provider"},
            "trust_level": {"type": "text", "object_relation": "trust-level"},
            "last_updated": {"type": "datetime", "object_relation": "last_updated"},
        }
        self.ip_address_metadata_mapping = {
            "asn": {"type": "AS", "object_relation": "asn"},
            "source_city": {"type": "text", "object_relation": "city"},
            "source_country_code": {"type": "text", "object_relation": "country-code"},
            "source_country": {"type": "text", "object_relation": "country"},
            "organization": {"type": "text", "object_relation": "organization"},
            "destination_country_codes": {
                "type": "text",
                "object_relation": "destination-country-codes",
            },
            "destination_countries": {
                "type": "text",
                "object_relation": "destination-countries",
            },
            "category": {"type": "text", "object_relation": "category"},
            "rdns": {"type": "text", "object_relation": "rdns"},
        }
        self.vulnerability_mapping = {
            "id": {"type": "text", "object_relation": "id"},
            "details": {"type": "text", "object_relation": "details"},
            "count": {"type": "text", "object_relation": "total-count"},
            "benign": {"type": "text", "object_relation": "benign-count"},
            "malicious": {"type": "text", "object_relation": "malicious-count"},
            "suspicious": {"type": "text", "object_relation": "suspicious-count"},
            "unknown": {"type": "text", "object_relation": "unknown-count"},
        }

    def query_greynoise_ip_hover(self, api_key):
        logger.info(f"Starting hover enrichment for: {self.attribute.value} via GreyNoise v3 API")
        integration_name = "greynoise-misp-module-{}".format(moduleinfo["version"])
        config = APIConfig(api_key=api_key, integration_name=integration_name)
        session = GreyNoise(config=config)
        try:
            response = session.ip(self.attribute.value)
            if response.get("error", "") != "":
                misperrors["error"] = f"An error occurred while querying GreyNoise: {response.get('error')}"
                return misperrors

            if response.get("business_services_intelligenice", {}).get("trust_level"):
                if response.get("business_services_intelligenice", {}).get("trust_level") == "1":
                    response["business_services_intelligenice"]["trust_level"] = "1 - Reasonably Ignore"
                if response.get("business_services_intelligenice", {}).get("trust_level") == "2":
                    response["business_services_intelligenice"]["trust_level"] = "2 - Commonly Seen"

            response["internet_scanner_intelligence"]["link"] = "https://viz.greynoise.io/ip/" + self.attribute.value
            response["internet_scanner_intelligence"]["noise"] = response["internet_scanner_intelligence"]["found"]
            response["internet_scanner_intelligence"]["riot"] = response["business_service_intelligence"]["found"]
            response["internet_scanner_intelligence"]["trust_level"] = response["business_service_intelligence"][
                "trust_level"
            ]
            response["internet_scanner_intelligence"]["last_updated"] = response["business_service_intelligence"][
                "last_updated"
            ]
            response["internet_scanner_intelligence"]["name"] = response["business_service_intelligence"]["name"]
            response["internet_scanner_intelligence"]["category"] = response["business_service_intelligence"][
                "category"
            ]

            ip_address_attributes = []
            for feature, mapping in self.ip_address_hover_mapping.items():
                logger.debug(f"Checking feature {feature}")
                if response.get("internet_scanner_intelligence", {}).get(feature):
                    if feature == "tags":
                        tag_list = []
                        for tag in response.get("internet_scanner_intelligence", {}).get(feature):
                            tag_list.append(tag["name"])
                        response["internet_scanner_intelligence"][feature] = ", ".join(tag_list)
                    if feature in ["cves"]:
                        response["internet_scanner_intelligence"][feature] = ", ".join(
                            response.get("internet_scanner_intelligence", {}).get(feature)
                        )
                    if (
                        feature == "vpn_service"
                        and response.get("internet_scanner_intelligence", {}).get(feature, "N/A") == "N/A"
                    ):
                        continue
                    if (
                        feature == "actor"
                        and response.get("internet_scanner_intelligence", {}).get(feature, "unknown") == "unknown"
                    ):
                        continue
                    attribute = {"value": response["internet_scanner_intelligence"][feature]}
                    logger.debug(f"Adding Feature: {feature}, Attribute: {attribute}")
                    attribute.update(mapping)
                    ip_address_attributes.append(attribute)
            if "metadata" in response.get("internet_scanner_intelligence", {}):
                for feature, mapping in self.ip_address_metadata_mapping.items():
                    logger.debug(f"Checking metadata feature {feature}")
                    if response.get("internet_scanner_intelligence", {}).get("metadata", {}).get(feature):
                        if feature in [
                            "destination_countries",
                            "destination_country_codes",
                        ]:
                            response["internet_scanner_intelligence"][feature] = ", ".join(
                                response.get("internet_scanner_intelligence", {}).get("metadata", {}).get(feature)
                            )
                        attribute = {
                            "value": response.get("internet_scanner_intelligence", {}).get("metadata", {}).get(feature)
                        }
                        logger.debug(f"Adding Feature: {feature}, Attribute: {attribute}")
                        attribute.update(mapping)
                        ip_address_attributes.append(attribute)
            if ip_address_attributes:
                logger.debug("creating greynoise ip object")
                gn_ip_object = MISPObject("greynoise-ip-details")
                for attribute in ip_address_attributes:
                    logger.debug(f"adding attribute {attribute}")
                    gn_ip_object.add_attribute(**attribute)
                logger.debug(f"attribute id: {self.attribute.uuid}")
                gn_ip_object.add_reference(self.attribute.uuid, "describes")
                self.misp_event.add_object(gn_ip_object)
        except Exception as e:
            logger.error(f"Error querying GreyNoise: {e}")
            misperrors["error"] = f"Error querying GreyNoise: {e}"
            return misperrors

    def query_greynoise_ip_expansion(self, api_key):
        logger.info(f"Starting expansion enrichment for: {self.attribute.value} via GreyNoise ENT API")
        integration_name = "greynoise-misp-module-{}".format(moduleinfo["version"])
        config = APIConfig(api_key=api_key, integration_name=integration_name)
        session = GreyNoise(config=config)
        try:
            response = session.ip(self.attribute.value)
            if response.get("error", "") != "":
                misperrors["error"] = f"An error occurred while querying GreyNoise: {response.get('error')}"
                return misperrors

            if response.get("business_services_intelligenice", {}).get("trust_level"):
                if response.get("business_services_intelligenice", {}).get("trust_level") == "1":
                    response["business_services_intelligenice"]["trust_level"] = "1 - Reasonably Ignore"
                if response.get("business_services_intelligenice", {}).get("trust_level") == "2":
                    response["business_services_intelligenice"]["trust_level"] = "2 - Commonly Seen"

            response["internet_scanner_intelligence"]["link"] = "https://viz.greynoise.io/ip/" + self.attribute.value
            response["internet_scanner_intelligence"]["noise"] = response["internet_scanner_intelligence"]["found"]
            response["internet_scanner_intelligence"]["riot"] = response["business_service_intelligence"]["found"]
            response["internet_scanner_intelligence"]["trust_level"] = response["business_service_intelligence"][
                "trust_level"
            ]
            response["internet_scanner_intelligence"]["last_updated"] = response["business_service_intelligence"][
                "last_updated"
            ]
            response["internet_scanner_intelligence"]["name"] = response["business_service_intelligence"]["name"]

            ip_address_attributes = []
            for feature, mapping in self.ip_address_enrich_mapping.items():
                logger.debug(f"Checking feature {feature}")
                if response.get("internet_scanner_intelligence", {}).get(feature):
                    if (
                        feature == "actor"
                        and response.get("internet_scanner_intelligence", {}).get(feature, "unknown") == "unknown"
                    ):
                        continue
                    attribute = {"value": response["internet_scanner_intelligence"][feature]}
                    logger.debug(f"Adding Feature: {feature}, Attribute: {attribute}")
                    attribute.update(mapping)
                    ip_address_attributes.append(attribute)
            if ip_address_attributes:
                logger.debug("creating greynoise ip object")
                gn_ip_object = MISPObject("greynoise-ip")
                for attribute in ip_address_attributes:
                    logger.debug(f"adding attribute {attribute}")
                    gn_ip_object.add_attribute(**attribute)
                logger.debug(f"attribute id: {self.attribute.uuid}")
                gn_ip_object.add_reference(self.attribute.uuid, "describes")
                self.misp_event.add_object(gn_ip_object)
        except Exception as e:
            logger.error(f"Error querying GreyNoise: {e}")
            misperrors["error"] = f"Error querying GreyNoise: {e}"
            return misperrors

    def query_greynoise_vulnerability(self, api_key):
        logger.info(f"Starting expansion enrichment for: {self.attribute.value} via GreyNoise ENT API")
        integration_name = "greynoise-misp-module-{}".format(moduleinfo["version"])
        config = APIConfig(api_key=api_key, integration_name=integration_name)
        session = GreyNoise(config=config)
        querystring = f"last_seen:1w cve:{self.attribute.value}"
        try:
            response = session.stats(querystring)
            if response.get("error", "") != "":
                misperrors["error"] = "Vulnerability Not Supported with Community API Key"
                return misperrors

            if "stats" in response:
                response["details"] = (
                    "The IP count below reflects the number of IPs seen "
                    "by GreyNoise in the last 7 days scanning for this CVE."
                )
                response["id"] = self.attribute.value
                classifications = response["stats"].get("classifications")
                for item in classifications:
                    if item["classification"] == "benign":
                        value = item["count"]
                        response["benign"] = value
                    if item["classification"] == "unknown":
                        value = item["count"]
                        response["unknown"] = value
                    if item["classification"] == "malicious":
                        value = item["count"]
                        response["malicious"] = value
                    if item["classification"] == "suspicious":
                        value = item["count"]
                        response["suspicious"] = value
                vulnerability_attributes = []
                for feature, mapping in self.vulnerability_mapping.items():
                    if response.get(feature):
                        attribute = {"value": response[feature]}
                        attribute.update(mapping)
                        vulnerability_attributes.append(attribute)
                if vulnerability_attributes:
                    vulnerability_object = MISPObject("greynoise-vuln-info")
                    for attribute in vulnerability_attributes:
                        vulnerability_object.add_attribute(**attribute)
                    vulnerability_object.add_reference(self.attribute.uuid, "describes")
                    self.misp_event.add_object(vulnerability_object)
        except Exception as e:
            logger.error(f"Error querying GreyNoise: {e}")
            misperrors["error"] = f"Error querying GreyNoise: {e}"
            return misperrors

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": results}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("config", {}).get("api_key"):
        return {"error": "GreyNoise API Key required, but missing"}
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    greynoise_parser = GreyNoiseParser(attribute)

    if attribute["type"] in ["ip-dst", "ip-src"]:
        try:
            ipaddress.IPv4Address(attribute["value"])
            if "persistent" in request:
                greynoise_parser.query_greynoise_ip_hover(request["config"]["api_key"])
            else:
                greynoise_parser.query_greynoise_ip_expansion(request["config"]["api_key"])
        except ValueError:
            return {"error": "Not a valid IPv4 address"}

    if attribute["type"] == "vulnerability":
        greynoise_parser.query_greynoise_vulnerability(request["config"]["api_key"])

    return greynoise_parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
