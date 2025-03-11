import ipaddress
import json
import logging

from greynoise import GreyNoise
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
    "version": "1.2",
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
moduleconfig = ["api_key", "api_type"]


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
            "last_seen": {"type": "datetime", "object_relation": "last-seen"},
            "link": {"type": "url", "object_relation": "link"},
            "last_updated": {"type": "datetime", "object_relation": "last-seen"},
        }
        self.ip_address_hover_mapping = {
            "noise": {"type": "boolean", "object_relation": "noise"},
            "riot": {"type": "boolean", "object_relation": "riot"},
            "classification": {"type": "text", "object_relation": "classification"},
            "actor": {"type": "text", "object_relation": "actor"},
            "tags": {"type": "text", "object_relation": "tags"},
            "cve": {"type": "text", "object_relation": "cve"},
            "vpn": {"type": "text", "object_relation": "vpn"},
            "vpn_service": {"type": "text", "object_relation": "vpn_service"},
            "bot": {"type": "text", "object_relation": "bot"},
            "first_seen": {"type": "datetime", "object_relation": "first-seen"},
            "last_seen": {"type": "datetime", "object_relation": "last-seen"},
            "spoofable": {"type": "datetime", "object_relation": "spoofable"},
            "link": {"type": "url", "object_relation": "link"},
            "category": {"type": "text", "object_relation": "category"},
            "name": {"type": "text", "object_relation": "provider"},
            "trust_level": {"type": "text", "object_relation": "trust-level"},
            "last_updated": {"type": "datetime", "object_relation": "last_updated"},
        }
        self.ip_address_metadata_mapping = {
            "tor": {"type": "text", "object_relation": "tor"},
            "asn": {"type": "AS", "object_relation": "asn"},
            "city": {"type": "text", "object_relation": "city"},
            "country_code": {"type": "text", "object_relation": "country-code"},
            "country": {"type": "text", "object_relation": "country"},
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
            "unknown": {"type": "text", "object_relation": "unknown-count"},
        }

    def query_greynoise_ip_hover(self, api_key, api_type):
        if api_type == "enterprise":
            logger.info(f"Starting hover enrichment for: {self.attribute.value} via GreyNoise ENT API")
            integration_name = "greynoise-misp-module-{}".format(moduleinfo["version"])
            session = GreyNoise(api_key=api_key, integration_name=integration_name)
            quick_response = session.quick(self.attribute.value)
            if len(quick_response) != 1:
                misperrors["error"] = "Quick IP lookup returned unexpected response"
                return misperrors
            else:
                quick_response = quick_response[0]
            context_response = session.ip(self.attribute.value)
            riot_response = session.riot(self.attribute.value)

            if riot_response and "trust_level" in riot_response:
                if riot_response["trust_level"] == "1":
                    riot_response["trust_level"] = "1 - Reasonably Ignore"
                if riot_response["trust_level"] == "2":
                    riot_response["trust_level"] = "2 - Commonly Seen"

            if context_response and riot_response:
                response = context_response.copy()
                response.update(riot_response)
                response.update(quick_response)
            elif context_response:
                response = context_response.copy()
                response.update(quick_response)
            elif riot_response:
                response = riot_response.copy()
                response.update(quick_response)

            response["link"] = "https://viz.greynoise.io/ip/" + self.attribute.value

            ip_address_attributes = []
            for feature, mapping in self.ip_address_hover_mapping.items():
                logger.debug(f"Checking feature {feature}")
                if response.get(feature):
                    if feature in ["cve", "tags"]:
                        response[feature] = ", ".join(response[feature])
                    if feature == "vpn_service" and response[feature] == "N/A":
                        continue
                    if feature == "actor" and response[feature] == "unknown":
                        continue
                    attribute = {"value": response[feature]}
                    logger.debug(f"Adding Feature: {feature}, Attribute: {attribute}")
                    attribute.update(mapping)
                    ip_address_attributes.append(attribute)
            if "metadata" in context_response:
                for feature, mapping in self.ip_address_metadata_mapping.items():
                    logger.debug(f"Checking metadata feature {feature}")
                    if response["metadata"].get(feature):
                        if feature in [
                            "destination_countries",
                            "destination_country_codes",
                        ]:
                            response["metadata"][feature] = ", ".join(response["metadata"][feature])
                        attribute = {"value": response["metadata"][feature]}
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
        else:
            logger.info(f"Starting hover enrichment for: {self.attribute.value} via GreyNoise Community API")
            integration_name = "greynoise-community-misp-module-{}".format(moduleinfo["version"])
            session = GreyNoise(api_key=api_key, integration_name=integration_name, offering="community")
            community_response = session.ip(self.attribute.value)

            if "noise" in community_response and community_response["noise"]:
                community_response["actor"] = community_response["name"]
                community_response.pop("name")

            ip_address_attributes = []
            for feature, mapping in self.ip_address_hover_mapping.items():
                if community_response.get(feature):
                    if feature == "actor" and community_response[feature] == "unknown":
                        continue
                    attribute = {"value": community_response[feature]}
                    attribute.update(mapping)
                    ip_address_attributes.append(attribute)
            if ip_address_attributes:
                ip_address_object = MISPObject("greynoise-ip-details")
                for attribute in ip_address_attributes:
                    ip_address_object.add_attribute(**attribute)
                ip_address_object.add_reference(self.attribute.uuid, "describes")
                self.misp_event.add_object(ip_address_object)

    def query_greynoise_ip_expansion(self, api_key, api_type):
        if api_type == "enterprise":
            logger.info(f"Starting expansion enrichment for: {self.attribute.value} via GreyNoise ENT API")
            integration_name = "greynoise-misp-module-{}".format(moduleinfo["version"])
            session = GreyNoise(api_key=api_key, integration_name=integration_name)
            quick_response = session.quick(self.attribute.value)
            if len(quick_response) != 1:
                misperrors["error"] = "Quick IP lookup returned unexpected response"
                return misperrors
            else:
                quick_response = quick_response[0]
            context_response = session.ip(self.attribute.value)
            riot_response = session.riot(self.attribute.value)

            if riot_response and "trust_level" in riot_response:
                if riot_response["trust_level"] == "1":
                    riot_response["trust_level"] = "1 - Reasonably Ignore"
                if riot_response["trust_level"] == "2":
                    riot_response["trust_level"] = "2 - Commonly Seen"

            if context_response and riot_response:
                response = context_response.copy()
                response.update(riot_response)
                response.update(quick_response)
            elif context_response:
                response = context_response.copy()
                response.update(quick_response)
            elif riot_response:
                response = riot_response.copy()
                response.update(quick_response)

            response["link"] = "https://viz.greynoise.io/ip/" + self.attribute.value

            ip_address_attributes = []
            for feature, mapping in self.ip_address_enrich_mapping.items():
                logger.debug(f"Checking feature {feature}")
                if response.get(feature):
                    if feature == "actor" and response[feature] == "unknown":
                        continue
                    attribute = {"value": response[feature]}
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
        else:
            logger.info(f"Starting expansion enrichment for: {self.attribute.value} via GreyNoise Community API")
            integration_name = "greynoise-community-misp-module-{}".format(moduleinfo["version"])
            session = GreyNoise(api_key=api_key, integration_name=integration_name, offering="community")
            community_response = session.ip(self.attribute.value)

            if "noise" in community_response and community_response["noise"]:
                community_response["actor"] = community_response["name"]
                community_response.pop("name")

            ip_address_attributes = []
            for feature, mapping in self.ip_address_enrich_mapping.items():
                if community_response.get(feature):
                    if feature == "actor" and community_response[feature] == "unknown":
                        continue
                    attribute = {"value": community_response[feature]}
                    attribute.update(mapping)
                    ip_address_attributes.append(attribute)
            if ip_address_attributes:
                ip_address_object = MISPObject("greynoise-ip")
                for attribute in ip_address_attributes:
                    ip_address_object.add_attribute(**attribute)
                ip_address_object.add_reference(self.attribute.uuid, "describes")
                self.misp_event.add_object(ip_address_object)

    def query_greynoise_vulnerability(self, api_key, api_type):
        if api_type == "enterprise":
            logger.info(f"Starting expansion enrichment for: {self.attribute.value} via GreyNoise ENT API")
            integration_name = "greynoise-misp-module-{}".format(moduleinfo["version"])
            session = GreyNoise(api_key=api_key, integration_name=integration_name)
            querystring = f"last_seen:1w cve:{self.attribute.value}"
        else:
            misperrors["error"] = "Vulnerability Not Supported with Community API Key"
            return misperrors

        response = session.stats(querystring)

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
    if not request.get("config", {}).get("api_type"):
        return {"error": "GreyNoise API type of enterprise or community required, but missing"}
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
                greynoise_parser.query_greynoise_ip_hover(request["config"]["api_key"], request["config"]["api_type"])
            else:
                greynoise_parser.query_greynoise_ip_expansion(
                    request["config"]["api_key"], request["config"]["api_type"]
                )
        except ValueError:
            return {"error": "Not a valid IPv4 address"}

    if attribute["type"] == "vulnerability":
        greynoise_parser.query_greynoise_vulnerability(request["config"]["api_key"], request["config"]["api_type"])

    return greynoise_parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
