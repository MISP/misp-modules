import json
import logging
import os
import platform
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject, MISPTag
from requests.exceptions import ConnectionError, ConnectTimeout, HTTPError, InvalidURL, ProxyError

from . import check_input_attribute, checking_error, standard_error_message

moduleinfo = {
    "version": "2.0.0",
    "author": "Recorded Future",
    "description": "Module to enrich attributes with threat intelligence from Recorded Future.",
    "module-type": ["expansion", "hover"],
    "name": "Recorded Future Enrich",
    "logo": "recordedfuture.png",
    "requirements": ["A Recorded Future API token."],
    "features": (
        "Enrich an attribute to add a custom enrichment object to the event. The object contains a copy of the enriched"
        " attribute with added tags presenting risk score and triggered risk rules from Recorded Future. Malware and"
        " Threat Actors related to the enriched indicator in Recorded Future is matched against MISP's galaxy clusters"
        " and applied as galaxy tags. The custom enrichment object also includes a list of related indicators from"
        " Recorded Future (IP's, domains, hashes, URL's and vulnerabilities) added as additional attributes."
    ),
    "references": ["https://www.recordedfuture.com/"],
    "input": (
        "A MISP attribute of one of the following types: ip, ip-src, ip-dst, domain, hostname, md5, sha1, sha256, uri,"
        " url, vulnerability, weakness."
    ),
    "output": (
        "A MISP object containing a copy of the enriched attribute with added tags from Recorded Future and a list of"
        " new attributes related to the enriched attribute."
    ),
}

moduleconfig = ["token", "proxy_host", "proxy_port", "proxy_username", "proxy_password"]

misperrors = {"error": "Error"}

GALAXY_FILE_PATH = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/"

ATTRIBUTESTYPES = [
    "ip",
    "ip-src",
    "ip-dst",
    "ip-src|port",
    "ip-dst|port",
    "domain",
    "hostname",
    "md5",
    "sha1",
    "sha256",
    "uri",
    "url",
    "vulnerability",
    "weakness",
]

OUTPUTATTRIBUTESTYPES = ATTRIBUTESTYPES + [
    "email-src",
    "malware-sample",
    "text",
    "target-org",
    "threat-actor",
    "target-user",
]

mispattributes = {
    "input": ATTRIBUTESTYPES,
    "output": OUTPUTATTRIBUTESTYPES,
    "format": "misp_standard",
}

LOGGER = logging.getLogger("recorded_future")
LOGGER.setLevel(logging.INFO)


class RequestHandler:
    """A class for handling any outbound requests from this module."""

    def __init__(self):
        self.session = requests.Session()
        self.app_id = (
            f'{os.path.basename(__file__)}/{moduleinfo["version"]} ({platform.platform()}) '
            f'misp_enrichment/{moduleinfo["version"]} python-requests/{requests.__version__}'
        )
        self.proxies = None
        self.rf_token = None

    def get(self, url: str, headers: dict = None) -> requests.Response:
        """General get method with proxy error handling."""
        try:
            timeout = 7 if self.proxies else None
            response = self.session.get(url, headers=headers, proxies=self.proxies, timeout=timeout)
            response.raise_for_status()
            return response
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            msg = "Error connecting with proxy, please check the Recorded Future app proxy settings."
            LOGGER.error(f"{msg} Error: {error}")
            misperrors["error"] = msg
            raise

    def rf_lookup(self, category: str, ioc: str) -> requests.Response:
        """Do a lookup call using Recorded Future's ConnectAPI."""
        parsed_ioc = quote(ioc, safe="")
        url = f"https://api.recordedfuture.com/gw/misp/lookup/{category}/{parsed_ioc}"
        headers = {"X-RFToken": self.rf_token, "User-Agent": self.app_id}
        try:
            response = self.get(url, headers)
        except HTTPError as error:
            msg = f"Error when requesting data from Recorded Future. {error.response}: {error.response.reason}"
            LOGGER.error(msg)
            misperrors["error"] = msg
            raise
        return response


GLOBAL_REQUEST_HANDLER = RequestHandler()


class GalaxyFinder:
    """A class for finding MISP galaxy matches to Recorded Future data."""

    def __init__(self):
        self.session = requests.Session()
        # There are duplicates values for different keys because Links entities and Related entities
        # have have different naming for the same types
        self.sources = {
            "RelatedThreatActor": [f"{GALAXY_FILE_PATH}threat-actor.json"],
            "Threat Actor": [f"{GALAXY_FILE_PATH}threat-actor.json"],
            "RelatedMalware": [
                f"{GALAXY_FILE_PATH}banker.json",
                f"{GALAXY_FILE_PATH}botnet.json",
                f"{GALAXY_FILE_PATH}exploit-kit.json",
                f"{GALAXY_FILE_PATH}rat.json",
                f"{GALAXY_FILE_PATH}ransomware.json",
                f"{GALAXY_FILE_PATH}malpedia.json",
            ],
            "Malware": [
                f"{GALAXY_FILE_PATH}banker.json",
                f"{GALAXY_FILE_PATH}botnet.json",
                f"{GALAXY_FILE_PATH}exploit-kit.json",
                f"{GALAXY_FILE_PATH}rat.json",
                f"{GALAXY_FILE_PATH}ransomware.json",
                f"{GALAXY_FILE_PATH}malpedia.json",
            ],
            "MitreAttackIdentifier": [
                f"{GALAXY_FILE_PATH}mitre-attack-pattern.json",
                f"{GALAXY_FILE_PATH}mitre-course-of-action.json",
                f"{GALAXY_FILE_PATH}mitre-enterprise-attack-attack-pattern.json",
                f"{GALAXY_FILE_PATH}mitre-enterprise-attack-course-of-action.json",
                f"{GALAXY_FILE_PATH}mitre-enterprise-attack-intrusion-set.json",
                f"{GALAXY_FILE_PATH}mitre-enterprise-attack-malware.json",
                f"{GALAXY_FILE_PATH}mitre-enterprise-attack-tool.json",
                f"{GALAXY_FILE_PATH}mitre-intrusion-set.json",
                f"{GALAXY_FILE_PATH}mitre-malware.json",
                f"{GALAXY_FILE_PATH}mitre-mobile-attack-attack-pattern.json",
                f"{GALAXY_FILE_PATH}mitre-mobile-attack-course-of-action.json",
                f"{GALAXY_FILE_PATH}mitre-mobile-attack-intrusion-set.json",
                f"{GALAXY_FILE_PATH}mitre-mobile-attack-malware.json",
                f"{GALAXY_FILE_PATH}mitre-mobile-attack-tool.json",
                f"{GALAXY_FILE_PATH}mitre-pre-attack-attack-pattern.json",
                f"{GALAXY_FILE_PATH}mitre-pre-attack-intrusion-set.json",
                f"{GALAXY_FILE_PATH}mitre-tool.json",
            ],
        }
        self.galaxy_clusters = {}

    def pull_galaxy_cluster(self, related_type: str) -> None:
        """Fetches galaxy clusters for the related_type from the remote json files specified as self.sources."""
        # Only fetch clusters if not fetched previously
        if not self.galaxy_clusters.get(related_type):
            for source in self.sources.get(related_type):
                try:
                    response = GLOBAL_REQUEST_HANDLER.get(source)
                    name = source.split("/")[-1].split(".")[0]
                    self.galaxy_clusters.setdefault(related_type, {}).update({name: response.json()})
                except ConnectionError as error:
                    LOGGER.warning(f"pull_galaxy_cluster failed for source: {source}, with error: {error}.")

    def find_galaxy_match(self, indicator: str, related_type: str) -> str:
        """Searches the clusters of the related_type for a match with the indicator.
        :returns the first matching galaxy string or an empty string if no galaxy match is found.
        """
        self.pull_galaxy_cluster(related_type)
        for cluster_name, cluster in self.galaxy_clusters.get(related_type, {}).items():
            for value in cluster["values"]:
                if indicator in value.get("meta", {}).get("synonyms", "") or indicator in value.get("value", ""):
                    value = value["value"]
                    return f'misp-galaxy:{cluster_name}="{value}"'
        return ""


class RFColors:
    """Class for setting signature RF-colors."""

    def __init__(self):
        self.rf_white = "#CCCCCC"
        self.rf_grey = " #CDCDCD"
        self.rf_yellow = "#FFCF00"
        self.rf_red = "#D10028"

    def riskscore_color(self, risk_score: int) -> str:
        """Returns appropriate hex-colors according to risk score."""
        risk_score = int(risk_score)
        if risk_score < 25:
            return self.rf_white
        elif risk_score < 65:
            return self.rf_yellow
        else:
            return self.rf_red

    def riskrule_color(self, risk_rule_criticality: int) -> str:
        """Returns appropriate hex-colors according to risk rule criticality."""
        risk_rule_criticality = int(risk_rule_criticality)
        if risk_rule_criticality == 1:
            return self.rf_white
        elif risk_rule_criticality == 2:
            return self.rf_yellow
        else:  # risk_rule_criticality == 3 or 4
            return self.rf_red

    def criticality_color(self, criticality) -> str:
        mapper = {
            "None": self.rf_grey,
            "Low": self.rf_grey,
            "Unusual": self.rf_grey,
            "Informational": self.rf_grey,
            "Medium": self.rf_yellow,
            "Suspicious": self.rf_yellow,
            "High": self.rf_red,
            "Critical": self.rf_red,
            "Very Critical": self.rf_red,
            "Malicious": self.rf_red,
            "Very Malicious": self.rf_red,
        }
        return mapper.get(criticality, self.rf_white)


class RFEnricher:
    """Class for enriching an attribute with data from Recorded Future.
    The enrichment data is returned as a custom MISP object.
    """

    def __init__(self, attribute_props: dict):
        self.event = MISPEvent()
        self.enrichment_object = MISPObject("Recorded Future Enrichment")
        self.enrichment_object.template_uuid = "cbe0ffda-75e5-4c49-833f-093f057652ba"
        self.enrichment_object.template_id = "1"
        self.enrichment_object.description = "Recorded Future Enrichment"
        setattr(self.enrichment_object, "meta-category", "network")
        description = "An object containing the enriched attribute and related entities from Recorded Future."
        self.enrichment_object.from_dict(**{"meta-category": "misc", "description": description, "distribution": 0})

        # Create a copy of enriched attribute to add tags to
        temp_attr = MISPAttribute()
        temp_attr.from_dict(**attribute_props)
        self.enriched_attribute = MISPAttribute()
        self.enriched_attribute.from_dict(**{"value": temp_attr.value, "type": temp_attr.type, "distribution": 0})

        self.related_attributes: List[Tuple[str, MISPAttribute]] = []
        self.color_picker = RFColors()
        self.galaxy_finder = GalaxyFinder()

        # Mapping from MISP-type to RF-type
        self.type_to_rf_category = {
            "ip": "ip",
            "ip-src": "ip",
            "ip-dst": "ip",
            "ip-src|port": "ip",
            "ip-dst|port": "ip",
            "domain": "domain",
            "hostname": "domain",
            "md5": "hash",
            "sha1": "hash",
            "sha256": "hash",
            "uri": "url",
            "url": "url",
            "vulnerability": "vulnerability",
            "weakness": "vulnerability",
        }

        # Related entities have 'Related' as part of the word and Links entities from RF
        # portrayed as related attributes in MISP
        self.related_attribute_types = [
            "RelatedIpAddress",
            "RelatedInternetDomainName",
            "RelatedHash",
            "RelatedEmailAddress",
            "RelatedCyberVulnerability",
            "IpAddress",
            "InternetDomainName",
            "Hash",
            "EmailAddress",
            "CyberVulnerability",
        ]
        # Related entities have 'Related' as part of the word and and Links entities from RF portrayed as tags in MISP
        self.galaxy_tag_types = [
            "RelatedMalware",
            "RelatedThreatActor",
            "Threat Actor",
            "MitreAttackIdentifier",
            "Malware",
        ]

    def enrich(self) -> None:
        """Run the enrichment."""
        category = self.type_to_rf_category.get(self.enriched_attribute.type, "")
        enriched_attribute_value = self.enriched_attribute.value
        # If enriched attribute has a port we need to remove that port
        # since RF do not support enriching ip addresses with port
        if self.enriched_attribute.type in ["ip-src|port", "ip-dst|port"]:
            enriched_attribute_value = enriched_attribute_value.split("|")[0]
        json_response = GLOBAL_REQUEST_HANDLER.rf_lookup(category, enriched_attribute_value)
        response = json.loads(json_response.content)

        try:
            # Add risk score and risk rules as tags to the enriched attribute
            risk_score = response["data"]["risk"]["score"]
            hex_color = self.color_picker.riskscore_color(risk_score)
            tag_name = f'recorded-future:risk-score="{risk_score}"'
            self.add_tag(tag_name, hex_color)
            risk_criticality = response["data"]["risk"]["criticalityLabel"]
            hex_color = self.color_picker.criticality_color(risk_criticality)
            tag_name = f'recorded-future:criticality="{risk_criticality}"'
            self.add_tag(tag_name, hex_color)

            for evidence in response["data"]["risk"]["evidenceDetails"]:
                risk_rule = evidence["rule"]
                criticality = evidence["criticality"]
                hex_color = self.color_picker.riskrule_color(criticality)
                tag_name = f'recorded-future:risk-rule="{risk_rule}"'
                self.add_tag(tag_name, hex_color)

            links_data = response["data"].get("links", {}).get("hits")
            # Check if we have error in links response. If yes, then user do not have right module enabled in token
            links_access_error = response["data"].get("links", {}).get("error")
            galaxy_tags = []
            if not links_access_error:
                for hit in links_data:
                    for section in hit["sections"]:
                        for sec_list in section["lists"]:
                            entity_type = sec_list["type"]["name"]
                            for entity in sec_list["entities"]:
                                if entity_type in self.galaxy_tag_types:
                                    galaxy = self.galaxy_finder.find_galaxy_match(entity["name"], entity_type)
                                    if galaxy and galaxy not in galaxy_tags:
                                        galaxy_tags.append(galaxy)
                                else:
                                    self.add_attribute(entity["name"], entity_type)

            else:
                # Retrieve related entities
                for related_entity in response["data"]["relatedEntities"]:
                    related_type = related_entity["type"]
                    if related_type in self.related_attribute_types:
                        # Related entities returned as additional attributes
                        for related in related_entity["entities"]:
                            # filter those entities that have count bigger than 4, to reduce noise
                            # because there can be a huge list of related entities
                            if int(related["count"]) > 4:
                                indicator = related["entity"]["name"]
                                self.add_attribute(indicator, related_type)
                    elif related_type in self.galaxy_tag_types:
                        # Related entities added as galaxy-tags to the enriched attribute
                        galaxy_tags = []
                        for related in related_entity["entities"]:
                            # filter those entities that have count bigger than 4, to reduce noise
                            # because there can be a huge list of related entities
                            if int(related["count"]) > 4:
                                indicator = related["entity"]["name"]
                                galaxy = self.galaxy_finder.find_galaxy_match(indicator, related_type)
                                # Handle deduplication of galaxy tags
                                if galaxy and galaxy not in galaxy_tags:
                                    galaxy_tags.append(galaxy)
            for galaxy in galaxy_tags:
                self.add_tag(galaxy)

        except KeyError:
            misperrors["error"] = "Unexpected format in Recorded Future api response."
            raise

    def add_attribute(self, indicator: str, indicator_type: str) -> None:
        """Helper method for adding an indicator to the attribute list."""
        out_type = self.get_output_type(indicator_type, indicator)
        attribute = MISPAttribute()
        attribute.from_dict(**{"value": indicator, "type": out_type, "distribution": 0})
        self.related_attributes.append((indicator_type, attribute))

    def add_tag(self, tag_name: str, hex_color: str = None) -> None:
        """Helper method for adding a tag to the enriched attribute."""
        tag = MISPTag()
        tag_properties = {"name": tag_name}
        if hex_color:
            tag_properties["colour"] = hex_color
        tag.from_dict(**tag_properties)
        self.enriched_attribute.add_tag(tag)

    def get_output_type(self, related_type: str, indicator: str) -> str:
        """Helper method for translating a Recorded Future related type to a MISP output type."""
        output_type = "text"
        if related_type in ["RelatedIpAddress", "IpAddress"]:
            output_type = "ip-dst"
        elif related_type in ["RelatedInternetDomainName", "InternetDomainName"]:
            output_type = "domain"
        elif related_type in ["RelatedHash", "Hash"]:
            hash_len = len(indicator)
            if hash_len == 64:
                output_type = "sha256"
            elif hash_len == 40:
                output_type = "sha1"
            elif hash_len == 32:
                output_type = "md5"
        elif related_type in ["RelatedEmailAddress", "EmailAddress"]:
            output_type = "email-src"
        elif related_type in ["RelatedCyberVulnerability", "CyberVulnerability"]:
            signature = indicator.split("-")[0]
            if signature == "CVE":
                output_type = "vulnerability"
            elif signature == "CWE":
                output_type = "weakness"
        elif related_type == "MalwareSignature":
            output_type = "malware-sample"
        elif related_type == "Organization":
            output_type = "target-org"
        elif related_type == "Username":
            output_type = "target-user"
        return output_type

    def get_results(self) -> dict:
        """Build and return the enrichment results."""
        self.enrichment_object.add_attribute("Enriched attribute", **self.enriched_attribute)
        for related_type, attribute in self.related_attributes:
            self.enrichment_object.add_attribute(related_type, **attribute)
        self.event.add_object(**self.enrichment_object)
        event = json.loads(self.event.to_json())
        result = {key: event[key] for key in ["Object"] if key in event}
        return {"results": result}


def get_proxy_settings(config: dict) -> Optional[Dict[str, str]]:
    """Returns proxy settings in the requests format.
    If no proxy settings are set, return None."""
    proxies = None
    host = config.get("proxy_host")
    port = config.get("proxy_port")
    username = config.get("proxy_username")
    password = config.get("proxy_password")

    if host:
        if not port:
            misperrors["error"] = (
                "The recordedfuture_proxy_host config is set, please also set the recordedfuture_proxy_port."
            )
            raise KeyError
        parsed = urlparse(host)
        if "http" in parsed.scheme:
            scheme = "http"
        else:
            scheme = parsed.scheme
        netloc = parsed.netloc
        host = f"{netloc}:{port}"

        if username:
            if not password:
                misperrors["error"] = (
                    "The recordedfuture_proxy_username config is set, "
                    "please also set the recordedfuture_proxy_password."
                )
                raise KeyError
            auth = f"{username}:{password}"
            host = auth + "@" + host

        proxies = {"http": f"{scheme}://{host}", "https": f"{scheme}://{host}"}

    LOGGER.info(f"Proxy settings: {proxies}")
    return proxies


def handler(q=False):
    """Handle enrichment."""
    if q is False:
        return False
    request = json.loads(q)

    config = request.get("config")
    if config and config.get("token"):
        GLOBAL_REQUEST_HANDLER.rf_token = config.get("token")
    else:
        misperrors["error"] = "Missing Recorded Future token."
        return misperrors
    if not request.get("attribute") or not check_input_attribute(request["attribute"], requirements=("type", "value")):
        return {"error": f"{standard_error_message}, {checking_error}."}
    if request["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    try:
        GLOBAL_REQUEST_HANDLER.proxies = get_proxy_settings(config)
    except KeyError:
        return misperrors

    input_attribute = request.get("attribute")
    rf_enricher = RFEnricher(input_attribute)

    try:
        rf_enricher.enrich()
    except (HTTPError, ConnectTimeout, ProxyError, InvalidURL, KeyError):
        return misperrors

    return rf_enricher.get_results()


def introspection():
    """Returns a dict of the supported attributes."""
    return mispattributes


def version():
    """Returns a dict with the version and the associated meta-data
    including potential configurations required of the module."""
    moduleinfo["config"] = moduleconfig
    return moduleinfo
