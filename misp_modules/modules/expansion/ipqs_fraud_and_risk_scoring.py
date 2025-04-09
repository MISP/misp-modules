import json
import logging

import requests
from pymisp import Distribution, MISPAttribute, MISPEvent, MISPObject, MISPTag
from requests.exceptions import ConnectTimeout, HTTPError, InvalidURL, ProxyError

from . import check_input_attribute, standard_error_message

ip_query_input_type = ["ip-src", "ip-dst"]
url_query_input_type = ["hostname", "domain", "url", "uri"]
email_query_input_type = [
    "email",
    "email-src",
    "email-dst",
    "target-email",
    "whois-registrant-email",
]
phone_query_input_type = ["phone-number", "whois-registrant-phone"]

misperrors = {"error": "Error"}
mispattributes = {
    "input": ip_query_input_type + url_query_input_type + email_query_input_type + phone_query_input_type,
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.1",
    "author": "David Mackler",
    "description": (
        "IPQualityScore MISP Expansion Module for IP reputation, Email Validation, Phone Number Validation, Malicious"
        " Domain and Malicious URL Scanner."
    ),
    "module-type": ["expansion", "hover"],
    "name": "IPQualityScore Lookup",
    "logo": "ipqualityscore.png",
    "requirements": ["A IPQualityScore API Key."],
    "features": (
        "This Module takes the IP Address, Domain, URL, Email and Phone Number MISP Attributes as input to query the"
        " IPQualityScore API.\n The results of the IPQualityScore API are than returned as IPQS Fraud and Risk Scoring"
        " Object. \n The object contains a copy of the enriched attribute with added tags presenting the verdict based"
        " on fraud score,risk score and other attributes from IPQualityScore."
    ),
    "references": ["https://www.ipqualityscore.com/"],
    "input": (
        "A MISP attribute of type IP Address(ip-src, ip-dst), Domain(hostname, domain), URL(url, uri), Email"
        " Address(email, email-src, email-dst, target-email, whois-registrant-email) and Phone Number(phone-number,"
        " whois-registrant-phone)."
    ),
    "output": "IPQualityScore object, resulting from the query on the IPQualityScore API.",
}
moduleconfig = ["apikey"]

logger = logging.getLogger("ipqualityscore")
logger.setLevel(logging.DEBUG)
BASE_URL = "https://ipqualityscore.com/api/json"
DEFAULT_DISTRIBUTION_SETTING = Distribution.your_organisation_only.value
IP_ENRICH = "ip"
URL_ENRICH = "url"
EMAIL_ENRICH = "email"
PHONE_ENRICH = "phone"


class RequestHandler:
    """A class for handling any outbound requests from this module."""

    def __init__(self, apikey):
        self.session = requests.Session()
        self.api_key = apikey

    def get(self, url: str, headers: dict = None, params: dict = None) -> requests.Response:
        """General get method to fetch the response from IPQualityScore."""
        try:
            response = self.session.get(url, headers=headers, params=params).json()
            if str(response["success"]) != "True":
                msg = response["message"]
                logger.error(f"Error: {msg}")
                misperrors["error"] = msg
            else:
                return response
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            msg = "Error connecting with the IPQualityScore."
            logger.error(f"{msg} Error: {error}")
            misperrors["error"] = msg

    def ipqs_lookup(self, reputation_type: str, ioc: str) -> requests.Response:
        """Do a lookup call."""
        url = f"{BASE_URL}/{reputation_type}"
        payload = {reputation_type: ioc}
        headers = {"IPQS-KEY": self.api_key}
        try:
            response = self.get(url, headers, payload)
        except HTTPError as error:
            msg = f"Error when requesting data from IPQualityScore. {error.response}: {error.response.reason}"
            logger.error(msg)
            misperrors["error"] = msg
            raise
        return response


def parse_attribute(comment, feature, value):
    """Generic Method for parsing the attributes in the object"""
    attribute = {
        "type": "text",
        "value": value,
        "comment": comment,
        "distribution": DEFAULT_DISTRIBUTION_SETTING,
        "object_relation": feature,
    }
    return attribute


class IPQualityScoreParser:
    """A class for handling the enrichment objects"""

    def __init__(self, attribute):
        self.rf_white = "#CCCCCC"
        self.rf_grey = " #CDCDCD"
        self.rf_yellow = "#FFCF00"
        self.rf_red = "#D10028"
        self.clean = "CLEAN"
        self.low = "LOW RISK"
        self.medium = "MODERATE RISK"
        self.high = "HIGH RISK"
        self.critical = "CRITICAL"
        self.invalid = "INVALID"
        self.suspicious = "SUSPICIOUS"
        self.malware = "CRITICAL"
        self.phishing = "CRITICAL"
        self.disposable = "CRITICAL"
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.ipqs_object = MISPObject("IPQS Fraud and Risk Scoring Object")
        self.ipqs_object.template_uuid = "57d066e6-6d66-42a7-a1ad-e075e39b2b5e"
        self.ipqs_object.template_id = "1"
        self.ipqs_object.description = "IPQS Fraud and Risk Scoring Data"
        setattr(self.ipqs_object, "meta-category", "network")
        description = "An object containing the enriched attribute and related entities from IPQualityScore."
        self.ipqs_object.from_dict(
            **{
                "meta-category": "misc",
                "description": description,
                "distribution": DEFAULT_DISTRIBUTION_SETTING,
            }
        )

        temp_attr = MISPAttribute()
        temp_attr.from_dict(**attribute)
        self.enriched_attribute = MISPAttribute()
        self.enriched_attribute.from_dict(
            **{
                "value": temp_attr.value,
                "type": temp_attr.type,
                "distribution": DEFAULT_DISTRIBUTION_SETTING,
            }
        )
        self.ipqs_object.distribution = DEFAULT_DISTRIBUTION_SETTING
        self.ip_data_items = [
            "fraud_score",
            "country_code",
            "region",
            "city",
            "zip_code",
            "ISP",
            "ASN",
            "organization",
            "is_crawler",
            "timezone",
            "mobile",
            "host",
            "proxy",
            "vpn",
            "tor",
            "active_vpn",
            "active_tor",
            "recent_abuse",
            "bot_status",
            "connection_type",
            "abuse_velocity",
            "latitude",
            "longitude",
        ]
        self.ip_data_items_friendly_names = {
            "fraud_score": "IPQS: Fraud Score",
            "country_code": "IPQS: Country Code",
            "region": "IPQS: Region",
            "city": "IPQS: City",
            "zip_code": "IPQS: Zip Code",
            "ISP": "IPQS: ISP",
            "ASN": "IPQS: ASN",
            "organization": "IPQS: Organization",
            "is_crawler": "IPQS: Is Crawler",
            "timezone": "IPQS: Timezone",
            "mobile": "IPQS: Mobile",
            "host": "IPQS: Host",
            "proxy": "IPQS: Proxy",
            "vpn": "IPQS: VPN",
            "tor": "IPQS: TOR",
            "active_vpn": "IPQS: Active VPN",
            "active_tor": "IPQS: Active TOR",
            "recent_abuse": "IPQS: Recent Abuse",
            "bot_status": "IPQS: Bot Status",
            "connection_type": "IPQS: Connection Type",
            "abuse_velocity": "IPQS: Abuse Velocity",
            "latitude": "IPQS: Latitude",
            "longitude": "IPQS: Longitude",
        }
        self.url_data_items = [
            "unsafe",
            "domain",
            "ip_address",
            "server",
            "domain_rank",
            "dns_valid",
            "parking",
            "spamming",
            "malware",
            "phishing",
            "suspicious",
            "adult",
            "risk_score",
            "category",
            "domain_age",
        ]
        self.url_data_items_friendly_names = {
            "unsafe": "IPQS: Unsafe",
            "domain": "IPQS: Domain",
            "ip_address": "IPQS: IP Address",
            "server": "IPQS: Server",
            "domain_rank": "IPQS: Domain Rank",
            "dns_valid": "IPQS: DNS Valid",
            "parking": "IPQS: Parking",
            "spamming": "IPQS: Spamming",
            "malware": "IPQS: Malware",
            "phishing": "IPQS: Phishing",
            "suspicious": "IPQS: Suspicious",
            "adult": "IPQS: Adult",
            "risk_score": "IPQS: Risk Score",
            "category": "IPQS: Category",
            "domain_age": "IPQS: Domain Age",
        }
        self.email_data_items = [
            "valid",
            "disposable",
            "smtp_score",
            "overall_score",
            "first_name",
            "generic",
            "common",
            "dns_valid",
            "honeypot",
            "deliverability",
            "frequent_complainer",
            "spam_trap_score",
            "catch_all",
            "timed_out",
            "suspect",
            "recent_abuse",
            "fraud_score",
            "suggested_domain",
            "leaked",
            "sanitized_email",
            "domain_age",
            "first_seen",
        ]
        self.email_data_items_friendly_names = {
            "valid": "IPQS: Valid",
            "disposable": "IPQS: Disposable",
            "smtp_score": "IPQS: SMTP Score",
            "overall_score": "IPQS: Overall Score",
            "first_name": "IPQS: First Name",
            "generic": "IPQS: Generic",
            "common": "IPQS: Common",
            "dns_valid": "IPQS: DNS Valid",
            "honeypot": "IPQS: Honeypot",
            "deliverability": "IPQS: Deliverability",
            "frequent_complainer": "IPQS: Frequent Complainer",
            "spam_trap_score": "IPQS: Spam Trap Score",
            "catch_all": "IPQS: Catch All",
            "timed_out": "IPQS: Timed Out",
            "suspect": "IPQS: Suspect",
            "recent_abuse": "IPQS: Recent Abuse",
            "fraud_score": "IPQS: Fraud Score",
            "suggested_domain": "IPQS: Suggested Domain",
            "leaked": "IPQS: Leaked",
            "sanitized_email": "IPQS: Sanitized Email",
            "domain_age": "IPQS: Domain Age",
            "first_seen": "IPQS: First Seen",
        }
        self.phone_data_items = [
            "formatted",
            "local_format",
            "valid",
            "fraud_score",
            "recent_abuse",
            "VOIP",
            "prepaid",
            "risky",
            "active",
            "carrier",
            "line_type",
            "country",
            "city",
            "zip_code",
            "region",
            "dialing_code",
            "active_status",
            "leaked",
            "name",
            "timezone",
            "do_not_call",
        ]
        self.phone_data_items_friendly_names = {
            "formatted": "IPQS: Formatted",
            "local_format": "IPQS: Local Format",
            "valid": "IPQS: Valid",
            "fraud_score": "IPQS: Fraud Score",
            "recent_abuse": "IPQS: Recent Abuse",
            "VOIP": "IPQS: VOIP",
            "prepaid": "IPQS: Prepaid",
            "risky": "IPQS: Risky",
            "active": "IPQS: Active",
            "carrier": "IPQS: Carrier",
            "line_type": "IPQS: Line Type",
            "country": "IPQS: Country",
            "city": "IPQS: City",
            "zip_code": "IPQS: Zip Code",
            "region": "IPQS: Region",
            "dialing_code": "IPQS: Dialing Code",
            "active_status": "IPQS: Active Status",
            "leaked": "IPQS: Leaked",
            "name": "IPQS: Name",
            "timezone": "IPQS: Timezone",
            "do_not_call": "IPQS: Do Not Call",
        }
        self.timestamp_items_friendly_name = {
            "human": " Human",
            "timestamp": " Timestamp",
            "iso": " ISO",
        }
        self.timestamp_items = ["human", "timestamp", "iso"]

    def criticality_color(self, criticality) -> str:
        """method which maps the color to the criticality level"""
        mapper = {
            self.clean: self.rf_grey,
            self.low: self.rf_grey,
            self.medium: self.rf_yellow,
            self.suspicious: self.rf_yellow,
            self.high: self.rf_red,
            self.critical: self.rf_red,
            self.invalid: self.rf_red,
            self.disposable: self.rf_red,
            self.malware: self.rf_red,
            self.phishing: self.rf_red,
        }
        return mapper.get(criticality, self.rf_white)

    def add_tag(self, tag_name: str, hex_color: str = None) -> None:
        """Helper method for adding a tag to the enriched attribute."""
        tag = MISPTag()
        tag_properties = {"name": tag_name}
        if hex_color:
            tag_properties["colour"] = hex_color
        tag.from_dict(**tag_properties)
        self.enriched_attribute.add_tag(tag)

    def ipqs_parser(self, query_response, enrich_type):
        """helper method to call the enrichment function according to the type"""
        if enrich_type == IP_ENRICH:
            self.ip_reputation_data(query_response)
        elif enrich_type == URL_ENRICH:
            self.url_reputation_data(query_response)
        elif enrich_type == EMAIL_ENRICH:
            self.email_reputation_data(query_response)
        elif enrich_type == PHONE_ENRICH:
            self.phone_reputation_data(query_response)

    def ip_reputation_data(self, query_response):
        """method to create object for IP address"""
        comment = "Results from IPQualityScore IP Reputation API"
        for ip_data_item in self.ip_data_items:
            if ip_data_item in query_response:
                data_item = self.ip_data_items_friendly_names[ip_data_item]
                data_item_value = str(query_response[ip_data_item])
                self.ipqs_object.add_attribute(**parse_attribute(comment, data_item, data_item_value))
                if ip_data_item == "fraud_score":
                    fraud_score = int(data_item_value)
                    self.ip_address_risk_scoring(fraud_score)

        self.ipqs_object.add_attribute("Enriched attribute", **self.enriched_attribute)
        self.ipqs_object.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(self.ipqs_object)

    def ip_address_risk_scoring(self, score):
        """method to create calculate verdict for IP Address"""
        risk_criticality = ""
        if score == 100:
            risk_criticality = self.critical
        elif 85 <= score <= 99:
            risk_criticality = self.high
        elif 75 <= score <= 84:
            risk_criticality = self.medium
        elif 60 <= score <= 74:
            risk_criticality = self.suspicious
        elif score <= 59:
            risk_criticality = self.clean

        hex_color = self.criticality_color(risk_criticality)
        tag_name = f'IPQS:VERDICT="{risk_criticality}"'
        self.add_tag(tag_name, hex_color)

    def url_reputation_data(self, query_response):
        """method to create object for URL/Domain"""
        malware = False
        phishing = False
        risk_score = 0
        comment = "Results from IPQualityScore Malicious URL Scanner API"
        for url_data_item in self.url_data_items:
            if url_data_item in query_response:
                data_item_value = ""
                if url_data_item == "domain_age":
                    for timestamp_item in self.timestamp_items:
                        data_item = (
                            self.url_data_items_friendly_names[url_data_item]
                            + self.timestamp_items_friendly_name[timestamp_item]
                        )
                        data_item_value = str(query_response[url_data_item][timestamp_item])
                        self.ipqs_object.add_attribute(**parse_attribute(comment, data_item, data_item_value))
                else:
                    data_item = self.url_data_items_friendly_names[url_data_item]
                    data_item_value = str(query_response[url_data_item])
                    self.ipqs_object.add_attribute(**parse_attribute(comment, data_item, data_item_value))

                if url_data_item == "malware":
                    malware = data_item_value
                if url_data_item == "phishing":
                    phishing = data_item_value
                if url_data_item == "risk_score":
                    risk_score = int(data_item_value)

        self.url_risk_scoring(risk_score, malware, phishing)
        self.ipqs_object.add_attribute("Enriched attribute", **self.enriched_attribute)
        self.ipqs_object.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(self.ipqs_object)

    def url_risk_scoring(self, score, malware, phishing):
        """method to create calculate verdict for URL/Domain"""
        risk_criticality = ""
        if malware == "True":
            risk_criticality = self.malware
        elif phishing == "True":
            risk_criticality = self.phishing
        elif score >= 90:
            risk_criticality = self.high
        elif 80 <= score <= 89:
            risk_criticality = self.medium
        elif 70 <= score <= 79:
            risk_criticality = self.low
        elif 55 <= score <= 69:
            risk_criticality = self.suspicious
        elif score <= 54:
            risk_criticality = self.clean

        hex_color = self.criticality_color(risk_criticality)
        tag_name = f'IPQS:VERDICT="{risk_criticality}"'
        self.add_tag(tag_name, hex_color)

    def email_reputation_data(self, query_response):
        """method to create object for Email Address"""
        comment = "Results from IPQualityScore Email Verification API"
        disposable = False
        valid = False
        fraud_score = 0
        for email_data_item in self.email_data_items:
            if email_data_item in query_response:
                data_item_value = ""
                if email_data_item not in ("domain_age", "first_seen"):
                    data_item = self.email_data_items_friendly_names[email_data_item]
                    data_item_value = str(query_response[email_data_item])
                    self.ipqs_object.add_attribute(**parse_attribute(comment, data_item, data_item_value))
                else:
                    for timestamp_item in self.timestamp_items:
                        data_item = (
                            self.email_data_items_friendly_names[email_data_item]
                            + self.timestamp_items_friendly_name[timestamp_item]
                        )
                        data_item_value = str(query_response[email_data_item][timestamp_item])
                        self.ipqs_object.add_attribute(**parse_attribute(comment, data_item, data_item_value))

                if email_data_item == "disposable":
                    disposable = data_item_value
                if email_data_item == "valid":
                    valid = data_item_value
                if email_data_item == "fraud_score":
                    fraud_score = int(data_item_value)

        self.email_address_risk_scoring(fraud_score, disposable, valid)
        self.ipqs_object.add_attribute("Enriched attribute", **self.enriched_attribute)
        self.ipqs_object.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(self.ipqs_object)

    def email_address_risk_scoring(self, score, disposable, valid):
        """method to create calculate verdict for Email Address"""
        risk_criticality = ""
        if disposable == "True":
            risk_criticality = self.disposable
        elif valid == "False":
            risk_criticality = self.invalid
        elif score == 100:
            risk_criticality = self.high
        elif 88 <= score <= 99:
            risk_criticality = self.medium
        elif 80 <= score <= 87:
            risk_criticality = self.low
        elif score <= 79:
            risk_criticality = self.clean
        hex_color = self.criticality_color(risk_criticality)
        tag_name = f'IPQS:VERDICT="{risk_criticality}"'

        self.add_tag(tag_name, hex_color)

    def phone_reputation_data(self, query_response):
        """method to create object for Phone Number"""
        fraud_score = 0
        valid = False
        active = False
        comment = "Results from IPQualityScore Phone Number Validation API"
        for phone_data_item in self.phone_data_items:
            if phone_data_item in query_response:
                data_item = self.phone_data_items_friendly_names[phone_data_item]
                data_item_value = str(query_response[phone_data_item])
                self.ipqs_object.add_attribute(**parse_attribute(comment, data_item, data_item_value))
                if phone_data_item == "active":
                    active = data_item_value
                if phone_data_item == "valid":
                    valid = data_item_value
                if phone_data_item == "fraud_score":
                    fraud_score = int(data_item_value)

        self.phone_address_risk_scoring(fraud_score, valid, active)
        self.ipqs_object.add_attribute("Enriched attribute", **self.enriched_attribute)
        self.ipqs_object.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(self.ipqs_object)

    def phone_address_risk_scoring(self, score, valid, active):
        """method to create calculate verdict for Phone Number"""
        risk_criticality = ""
        if valid == "False":
            risk_criticality = self.medium
        elif active == "False":
            risk_criticality = self.medium
        elif 90 <= score <= 100:
            risk_criticality = self.high
        elif 80 <= score <= 89:
            risk_criticality = self.low
        elif 50 <= score <= 79:
            risk_criticality = self.suspicious
        elif score <= 49:
            risk_criticality = self.clean
        hex_color = self.criticality_color(risk_criticality)
        tag_name = f'IPQS:VERDICT="{risk_criticality}"'
        self.add_tag(tag_name, hex_color)

    def get_results(self):
        """returns the dictionary object to MISP Instance"""
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object")}
        return {"results": results}


def handler(q=False):
    """The function which accepts a JSON document to expand the values and return a dictionary of the expanded
    values."""
    if q is False:
        return False
    request = json.loads(q)
    # check if the apikey is provided
    if not request.get("config") or not request["config"].get("apikey"):
        misperrors["error"] = "IPQualityScore apikey is missing"
        return misperrors
    apikey = request["config"].get("apikey")
    # check attribute is added to the event
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}

    attribute = request["attribute"]
    attribute_type = attribute["type"]
    attribute_value = attribute["value"]

    # check if the attribute type is supported by IPQualityScore
    if attribute_type not in mispattributes["input"]:
        return {"error": "Unsupported attributes type for IPqualityScore Enrichment"}
    request_handler = RequestHandler(apikey)
    enrich_type = ""
    if attribute_type in ip_query_input_type:
        enrich_type = IP_ENRICH
        json_response = request_handler.ipqs_lookup(IP_ENRICH, attribute_value)
    elif attribute_type in url_query_input_type:
        enrich_type = URL_ENRICH
        json_response = request_handler.ipqs_lookup(URL_ENRICH, attribute_value)
    elif attribute_type in email_query_input_type:
        enrich_type = EMAIL_ENRICH
        json_response = request_handler.ipqs_lookup(EMAIL_ENRICH, attribute_value)
    elif attribute_type in phone_query_input_type:
        enrich_type = PHONE_ENRICH
        json_response = request_handler.ipqs_lookup(PHONE_ENRICH, attribute_value)

    parser = IPQualityScoreParser(attribute)
    parser.ipqs_parser(json_response, enrich_type)
    return parser.get_results()


def introspection():
    """The function that returns a dict of the supported attributes (input and output) by your expansion module."""
    return mispattributes


def version():
    """The function that returns a dict with the version and the associated meta-data including potential
    configurations required of the module."""
    moduleinfo["config"] = moduleconfig
    return moduleinfo
