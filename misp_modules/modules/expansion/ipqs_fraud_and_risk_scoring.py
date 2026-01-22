"""IPQualityScore expansion module for MISP.

Provides IPQualityScore lookup and enrichment for IPs, URLs, emails, phones,
usernames, passwords, and files. Implements RequestHandler and
IPQualityScoreParser to call the IPQualityScore API and build MISP objects.
"""

# pylint: disable=too-many-lines

import base64
import io
import json
import logging
import time
import zipfile

import requests
from pymisp import Distribution, MISPAttribute, MISPEvent, MISPObject, MISPTag
from requests.exceptions import (ConnectTimeout, HTTPError, InvalidURL,
                                 ProxyError)

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
username_query_input_type = ["first-name", "last-name", "middle-name", "github-username"]
password_query_input_type = ["text"]
file_query_input_type = ["attachment", "malware-sample"]

misperrors = {"error": "Error"}
mispattributes = {
    "input": (
        ip_query_input_type
        + url_query_input_type
        + email_query_input_type
        + username_query_input_type
        + password_query_input_type
        + phone_query_input_type
        + file_query_input_type
    ),
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.1",
    "author": "David Mackler",
    "description": (
        "IPQualityScore MISP Expansion Module for IP reputation,\
        Email Validation, Phone Number Validation,"
        " Malicious Domain,Malicious URL Scanner,Malicious File Scanner & Compromised username, Password, Email  "
    ),
    "module-type": ["expansion", "hover"],
    "name": "IPQualityScore Lookup",
    "logo": "ipqualityscore.png",
    "requirements": ["A IPQualityScore API Key."],
    "features": (
        """This Module takes the IP Address, Domain, URL, Email, Phone Number, Username,
        Password, and MISP Attributes as input to query the IPQualityScore API.
        The results of the IPQualityScore API are then returned as an IPQS Fraud, Risk,
        and Exposure Scoring Object. 
        The object contains a copy of the enriched attribute with added tags presenting
        the verdict based on fraud score, risk score, darkweb exposure status, and
        other attributes from IPQualityScore.
        This module also contains IPQS Darkweb Leak, IPQS Malware File Scanner API's
        IPQS Darkweb Leak - Monitor Dark Web Activity & Compromised User Accounts,
        IPQS Malware File Scanner - Detect malicious files.
        """
    ),
    "references": ["https://www.ipqualityscore.com/"],
    "input": (
        "A MISP attribute of type IP Address(ip-src, ip-dst),             Domain(hostname, domain), URL(url, uri),"
        " Email Address(email, email-src, email-dst, target-email,             whois-registrant-email) and Phone"
        " Number(phone-number, whois-registrant-phone), Username(first-name, last-name,             middle-name,"
        " github-username), Password(text)."
    ),
    "output": "IPQualityScore object, resulting from the query on the                 IPQualityScore API.",
}
moduleconfig = ["apikey", "base_url", "poll_delay"]

logger = logging.getLogger("ipqualityscore")
logger.setLevel(logging.DEBUG)
DEFAULT_DISTRIBUTION_SETTING = Distribution.your_organisation_only.value
IP_ENRICH = "ip"
URL_ENRICH = "url"
EMAIL_ENRICH = "email"
PHONE_ENRICH = "phone"
USERNAME_ENRICH = "username"
PASSWORD_ENRICH = "password"


class RequestHandler:
    """A class for handling any outbound requests from this module."""

    def __init__(self, apikey, base_url):
        self.session = requests.Session()
        self.api_key = apikey
        self.base_url = base_url

    def get(self, url: str, headers: dict = None, params: dict = None) -> requests.Response:
        """General get method to fetch the response from IPQualityScore."""
        try:
            response = self.session.get(url, headers=headers, params=params).json()
            if str(response["success"]) != "True":
                msg = response["message"]
                logger.error("Error: %s", {msg})
                misperrors["error"] = msg
                raise
            else:
                return response
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            msg = "Error connecting with the IPQualityScore."
            logger.error("%s Error: %s", msg, error)
            misperrors["error"] = msg

    def ipqs_lookup(self, reputation_type: str, ioc: str) -> requests.Response:
        """Do a lookup call."""
        url = f"{self.base_url.rstrip('/')}/{reputation_type}"
        payload = {reputation_type: ioc}
        headers = {"IPQS-KEY": self.api_key}
        try:
            response = self.get(url, headers, payload)
        except HTTPError as error:
            msg = (
                f"Error when requesting data from IPQualityScore.                 {error.response}:"
                f" {error.response.reason}"
            )
            logger.error(msg)
            misperrors["error"] = msg
            raise
        if response is None:
            return {}
        return response

    def ipqs_darkweb_lookup(self, reputation_type: str, ioc: str) -> requests.Response:
        """Do a lookup call for darkweb."""
        url = f"{self.base_url.rstrip('/')}/leaked/{reputation_type}"
        payload = {reputation_type: ioc}
        headers = {"IPQS-KEY": self.api_key}
        try:
            response = self.get(url, headers, payload)
        except HTTPError as error:
            msg = (
                f"Error when requesting data from IPQualityScore.                 {error.response}:"
                f" {error.response.reason}"
            )
            logger.error(msg)
            misperrors["error"] = msg
            raise
        if response is None:
            return {}
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
        description = (
            "An object containing the enriched attribute and related entities from IPQualityScore."
        )
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

        self.username_data_items = [
            "success",
            "message",
            "request_hash",
            "source",
            "exposed",
            "first_seen.human",
            "first_seen.timestamp",
            "first_seen.iso",
            "request_id",
        ]

        self.username_data_items_friendly_names = {
            "success": "IPQS Darkweb Leak: Success",
            "message": "IPQS Darkweb Leak: Message",
            "request_hash": "IPQS Darkweb Leak: Request Hash",
            "source": "IPQS Darkweb Leak: Source",
            "exposed": "IPQS Darkweb Leak: Exposed",
            "first_seen.human": "IPQS Darkweb Leak: First Seen Human",
            "first_seen.timestamp": "IPQS Darkweb Leak: First Seen Timestamp",
            "first_seen.iso": "IPQS Darkweb Leak: First Seen ISO",
            "request_id": "IPQS Darkweb Leak: Request ID",
        }

        self.password_data_items = [
            "success",
            "message",
            "request_hash",
            "source",
            "exposed",
            "first_seen.human",
            "first_seen.timestamp",
            "first_seen.iso",
            "request_id",
        ]

        self.password_data_items_friendly_names = {
            "success": "IPQS Darkweb Leak: Success",
            "message": "IPQS Darkweb Leak: Message",
            "request_hash": "IPQS Darkweb Leak: Request Hash",
            "source": "IPQS Darkweb Leak: Source",
            "exposed": "IPQS Darkweb Leak: Exposed",
            "first_seen.human": "IPQS Darkweb Leak: First Seen Human",
            "first_seen.timestamp": "IPQS Darkweb Leak: First Seen Timestamp",
            "first_seen.iso": "IPQS Darkweb Leak: First Seen ISO",
            "request_id": "IPQS Darkweb Leak: Request ID",
        }

        self.leaked_email_data_items = [
            "success",
            "message",
            "request_hash",
            "source",
            "exposed",
            "first_seen.human",
            "first_seen.timestamp",
            "first_seen.iso",
            "plain_text_password",
            "request_id",
        ]

        self.leaked_email_data_items_friendly_names = {
            "success": "IPQS Darkweb Leak: Success",
            "message": "IPQS Darkweb Leak: Message",
            "request_hash": "IPQS Darkweb Leak: Request Hash",
            "source": "IPQS Darkweb Leak: Source",
            "exposed": "IPQS Darkweb Leak: Exposed",
            "first_seen.human": "IPQS Darkweb Leak: First Seen Human",
            "first_seen.timestamp": "IPQS Darkweb Leak: First Seen Timestamp",
            "first_seen.iso": "IPQS Darkweb Leak: First Seen ISO",
            "plain_text_password": "IPQS Darkweb Leak: Plain Text Password",
            "request_id": "IPQS Darkweb Leak: Request ID",
        }

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
            "shared_connection",
            "dynamic_connection",
            "frequent_abuser",
            "high_risk_attacks",
            "security_scanner",
            "trusted_network",
            "abuse_events",
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
            "shared_connection": "IPQS: Shared Connection",
            "dynamic_connection": "IPQS: Dynamic Connection",
            "frequent_abuser": "IPQS: Frequent Abuser",
            "high_risk_attacks": "IPQS: High Risk Attacks",
            "security_scanner": "IPQS: Security Scanner",
            "trusted_network": "IPQS: Trusted Network",
            "abuse_events": "IPQS: Abuse Events",
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
            "root_domain",
            "ip_address",
            "server",
            "domain_rank",
            "content_type",
            "status_code",
            "page_size",
            "dns_valid",
            "parking",
            "country_code",
            "language_code",
            "domain_trust",
            "redirected",
            "short_link_redirect",
            "hosted_content",
            "page_title",
            "risky_tld",
            "spf_record",
            "dmarc_record",
            "technologies",
            "a_records",
            "mx_records",
            "ns_records",
            "final_url",
            "scanned_url",
            "spamming",
            "malware",
            "phishing",
            "suspicious",
            "adult",
            "risk_score",
            "category",
            "domain_age.human",
            "domain_age.timestamp",
            "domain_age.iso",
        ]
        self.url_data_items_friendly_names = {
            "unsafe": "IPQS: Unsafe",
            "domain": "IPQS: Domain",
            "root_domain": "IPQS: Root Domain",
            "ip_address": "IPQS: IP Address",
            "server": "IPQS: Server",
            "domain_rank": "IPQS: Domain Rank",
            "content_type": "IPQS: Content Type",
            "status_code": "IPQS: Status Code",
            "page_size": "IPQS: Page Size",
            "dns_valid": "IPQS: DNS Valid",
            "parking": "IPQS: Parking",
            "country_code": "IPQS: Country Code",
            "language_code": "IPQS: Language Code",
            "domain_trust": "IPQS: Domain Trust",
            "redirected": "IPQS: Redirected",
            "short_link_redirect": "IPQS: Short Link Redirect",
            "hosted_content": "IPQS: Hosted Content",
            "page_title": "IPQS: Page Title",
            "risky_tld": "IPQS: Risky TLD",
            "spf_record": "IPQS: SPF Record",
            "dmarc_record": "IPQS: DMARC Record",
            "technologies": "IPQS: Technologies",
            "a_records": "IPQS: A Records",
            "mx_records": "IPQS: MX Records",
            "ns_records": "IPQS: NS Records",
            "final_url": "IPQS: Final URL",
            "scanned_url": "IPQS: Scanned URL",
            "spamming": "IPQS: Spamming",
            "malware": "IPQS: Malware",
            "phishing": "IPQS: Phishing",
            "suspicious": "IPQS: Suspicious",
            "adult": "IPQS: Adult",
            "risk_score": "IPQS: Risk Score",
            "category": "IPQS: Category",
            "domain_age.human": "IPQS: Domain Age Human",
            "domain_age.timestamp": "IPQS: Domain Age Timestamp",
            "domain_age.iso": "IPQS: Domain Age ISO",
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
            "domain_trust",
            "domain_velocity",
            "user_activity",
            "associated_names.status",
            "associated_names.names",
            "associated_phone_numbers.status",
            "associated_phone_numbers.phone_numbers",
            "risky_tld",
            "spf_record",
            "dmarc_record",
            "mx_records",
            "a_records",
            "spam_trap_score",
            "catch_all",
            "timed_out",
            "suspect",
            "recent_abuse",
            "fraud_score",
            "suggested_domain",
            "leaked",
            "sanitized_email",
            "domain_age.human",
            "domain_age.timestamp",
            "domain_age.iso",
            "first_seen.human",
            "first_seen.timestamp",
            "first_seen.iso",
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
            "domain_trust": "IPQS: Domain Trust",
            "domain_velocity": "IPQS: Domain Velocity",
            "user_activity": "IPQS: User Activity",
            "associated_names.status": "IPQS: Associated Names Status",
            "associated_names.names": "IPQS: Associated Names",
            "associated_phone_numbers.status": "IPQS: Associated Phone Number Status",
            "associated_phone_numbers.phone_numbers": "IPQS: Associated Phone Numbers",
            "risky_tld": "IPQS: Risky TLD",
            "spf_record": "IPQS: SPF Record",
            "dmarc_record": "IPQS: DMARC Record",
            "mx_records": "IPQS: MX Record",
            "a_records": "IPQS: A Records",
            "domain_age.human": "IPQS: Domain Age",
            "domain_age.timestamp": "IPQS: Domain Age Timestamp",
            "domain_age.iso": "IPQS: Domain Age ISO",
            "first_seen.human": "IPQS: First Seen Human",
            "first_seen.timestamp": "IPQS: First Seen Timestamp",
            "first_seen.iso": "IPQS: First Seen ISO",
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
            "sms_domain",
            "associated_email_addresses.status",
            "associated_email_addresses.emails",
            "user_activity",
            "mnc",
            "mcc",
            "spammer",
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
            "tcpa_blacklist",
            "accurate_country_code",
            "sms_email",
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
            "sms_domain": "IPQS: SMS Domain",
            "associated_email_addresses.status": "IPQS: Associated Email Addresses Status",
            "associated_email_addresses.emails": "IPQS: Associated Email Addresses",
            "user_activity": "IPQS: User Activity",
            "mnc": "IPQS: MNC",
            "mcc": "IPQS: MCC",
            "spammer": "IPQS: Spammer",
            "tcpa_blacklist": "IPQS: TCPA Blacklist",
            "accurate_country_code": "IPQS: Accurate Country Code",
            "sms_email": "IPQS: SMS Email",
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
        flatten_json_response = self.flatten_json(query_response)
        if enrich_type == IP_ENRICH:
            self.ip_reputation_data(flatten_json_response)
        elif enrich_type == URL_ENRICH:
            self.url_reputation_data(flatten_json_response)
        elif enrich_type == EMAIL_ENRICH:
            email_reputation = self.flatten_json(query_response.get("email_reputation", {}))
            leaked_email = self.flatten_json(query_response.get("leaked_email", {}))
            self.email_reputation_data(email_reputation, leaked_email)
        elif enrich_type == PHONE_ENRICH:
            self.phone_reputation_data(flatten_json_response)
        elif enrich_type == USERNAME_ENRICH:
            self.username_reputation_data(flatten_json_response)
        elif enrich_type == PASSWORD_ENRICH:
            self.password_reputation_data(flatten_json_response)

    def flatten_json(self, data, parent_key="", sep="."):
        """Flatten only dicts; lists become comma-joined values."""
        items = {}
        for key, value in data.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key
            if isinstance(value, dict):
                # If value is a dict → recurse
                items.update(self.flatten_json(value, new_key, sep))
            elif isinstance(value, list):
                # If value is a list → join values as comma-separated string
                items[new_key] = ", ".join(map(str, value))
            else:
                # Normal values
                items[new_key] = value
        return items

    def username_reputation_data(self, query_response):
        """method to create object for Username"""
        comment = "Results from IPQualityScore Username Exposure API"
        for username_data_item in self.username_data_items:
            if username_data_item in query_response:
                data_item = self.username_data_items_friendly_names[username_data_item]
                data_item_value = str(query_response[username_data_item])
                if len(data_item_value) > 0:
                    self.ipqs_object.add_attribute(**parse_attribute(comment, data_item, data_item_value))

        self.ipqs_object.add_attribute("Enriched attribute", **self.enriched_attribute)
        self.ipqs_object.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(self.ipqs_object)

    def password_reputation_data(self, query_response):
        """method to create object for Password"""
        comment = "Results from IPQualityScore Password Exposure API"
        for password_data_item in self.password_data_items:
            if password_data_item in query_response:
                data_item = self.password_data_items_friendly_names[password_data_item]
                data_item_value = str(query_response[password_data_item])
                if len(data_item_value) > 0:
                    self.ipqs_object.add_attribute(**parse_attribute(comment, data_item, data_item_value))

        self.ipqs_object.add_attribute("Enriched attribute", **self.enriched_attribute)
        self.ipqs_object.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(self.ipqs_object)

    def ip_reputation_data(self, query_response):
        """method to create object for IP address"""
        comment = "Results from IPQualityScore IP Reputation API"
        for ip_data_item in self.ip_data_items:
            if ip_data_item in query_response:
                data_item = self.ip_data_items_friendly_names[ip_data_item]
                data_item_value = str(query_response[ip_data_item])
                if len(data_item_value) > 0:
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

                data_item = self.url_data_items_friendly_names[url_data_item]
                data_item_value = str(query_response[url_data_item])
                if len(data_item_value) > 0:
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

    def email_reputation_data(self, email_reputation_resp, leaked_email_resp):
        """method to create object for Email Address"""
        comment = "Results from IPQualityScore Email Verification API"
        disposable = False
        valid = False
        fraud_score = 0
        for email_data_item in self.email_data_items:
            if email_data_item in email_reputation_resp:
                data_item = self.email_data_items_friendly_names[email_data_item]
                data_item_value = str(email_reputation_resp[email_data_item])
                if len(data_item_value) > 0:
                    self.ipqs_object.add_attribute(**parse_attribute(comment, data_item, data_item_value))
                if email_data_item == "disposable":
                    disposable = data_item_value
                if email_data_item == "valid":
                    valid = data_item_value
                if email_data_item == "fraud_score":
                    fraud_score = int(data_item_value)
        self.email_address_risk_scoring(fraud_score, disposable, valid)
        for leaked_email_data_item in self.leaked_email_data_items:
            if leaked_email_data_item in leaked_email_resp:
                data_item = self.leaked_email_data_items_friendly_names[leaked_email_data_item]
                data_item_value = str(leaked_email_resp[leaked_email_data_item])
                if len(data_item_value) > 0:
                    self.ipqs_object.add_attribute(**parse_attribute(comment, data_item, data_item_value))

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
                if len(data_item_value) > 0:
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
    """The function which accepts a JSON document to expand the\
          values and return a dictionary of the expanded
    values."""
    if q is False:
        return False
    request = json.loads(q)
    # check if the apikey is provided
    if not request.get("config") or not request["config"].get("apikey"):
        misperrors["error"] = "IPQualityScore apikey is missing"
        return misperrors
    apikey = request["config"].get("apikey")
    base_url = request.get("config").get("base_url")

    # check attribute is added to the event
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {
            "error": (
                f"{standard_error_message}, which should contain at                 least a type, a value and an uuid."
            )
        }

    attribute = request["attribute"]
    attribute_type = attribute["type"]
    attribute_value = attribute["value"]

    headers = {"IPQS-KEY": apikey}

    # check if the attribute type is supported by IPQualityScore
    if attribute_type not in mispattributes["input"]:
        return {"error": "Unsupported attributes type for IPqualityScore Enrichment"}
    request_handler = RequestHandler(apikey, base_url)
    enrich_type = ""
    json_response = {}
    if attribute_type in ip_query_input_type:
        enrich_type = IP_ENRICH
        json_response = request_handler.ipqs_lookup(IP_ENRICH, attribute_value)
    elif attribute_type in url_query_input_type:
        enrich_type = URL_ENRICH
        json_response = request_handler.ipqs_lookup(URL_ENRICH, attribute_value)
    elif attribute_type in email_query_input_type:
        enrich_type = EMAIL_ENRICH
        json_response1 = request_handler.ipqs_lookup(EMAIL_ENRICH, attribute_value)
        json_response2 = request_handler.ipqs_darkweb_lookup(EMAIL_ENRICH, attribute_value)
        json_response = {"email_reputation": json_response1, "leaked_email": json_response2}
    elif attribute_type in phone_query_input_type:
        enrich_type = PHONE_ENRICH
        json_response = request_handler.ipqs_lookup(PHONE_ENRICH, attribute_value)
    elif attribute_type in username_query_input_type:
        enrich_type = USERNAME_ENRICH
        json_response = request_handler.ipqs_darkweb_lookup(USERNAME_ENRICH, attribute_value)
    elif attribute_type in password_query_input_type:
        enrich_type = PASSWORD_ENRICH
        json_response = request_handler.ipqs_darkweb_lookup(PASSWORD_ENRICH, attribute_value)
    elif attribute_type in file_query_input_type:
        try:
            data = request.get("attribute").get("data", "")
            if "malware-sample" in attribute_type:
                sample_filename = attribute_value.split("|")[0]
                logger.info("Processing malware-sample: %s", sample_filename)
                decoded = base64.b64decode(data)
                with zipfile.ZipFile(io.BytesIO(decoded)) as zf:
                    zipped_file = zf.namelist()[0]
                    data = zf.read(zipped_file, pwd=b"infected")
            elif "attachment" in attribute_type:
                sample_filename = request["attachment"]
                logger.info("Processing attachment: %s", sample_filename)
                data = base64.b64decode(data)
            else:
                logger.warning("No file supplied in request")
                misperrors["error"] = "No malware sample or attachment supplied"
                return misperrors
        except Exception:
            logger.exception("Sample processing failed")
            misperrors["error"] = "Unable to process submitted sample data"
            return misperrors

        poll_delay = request.get("config", {}).get("poll_delay", "1")
        try:
            poll_delay = int(poll_delay)
        except Exception:
            poll_delay = 1
        try:
            files = {"file": (sample_filename, io.BytesIO(data))}
            max_retries = 3
            retries = 0
            headers = {"IPQS-KEY": apikey}
            try:
                if base_url and apikey:
                    if not base_url:
                        misperrors["error"] = (
                            "IPQS configuration missing: "
                            "Please check the Base URL."
                        )
                        return misperrors
                    if not apikey:
                        misperrors["error"] = (
                            "IPQS configuration missing: "
                            "Please check the API Key."
                        )
                        return misperrors
                    response = requests.post(
                        f"{base_url.strip('/')}/malware/lookup/", headers=headers, files=files, timeout=30
                    )
                    json_response = response.json()
                    if json_response.get("success") is True:
                        if json_response.get("status", False) == "cached":
                            return ipqs_process(json_response)
                    response = requests.post(
                        f"{base_url.strip('/')}/malware/scan/", headers=headers, files=files, timeout=30
                    )
                    json_response = response.json()
                    payload = {"request_id": json_response.get("request_id")}
                    while retries <= max_retries and json_response.get("status") == "pending":
                        retries += 1
                        time.sleep(poll_delay)
                        response = requests.get(
                            f"{base_url.strip('/')}/postback/", headers=headers, json=payload, timeout=30
                        )
                        json_response = response.json()
                return ipqs_process(json_response)
            except requests.exceptions.RequestException:
                time.sleep(poll_delay)
                logger.info("IPQS response status: %s", response.status_code)

        except Exception:
            logger.exception("IPQS submission or polling failed")
            misperrors["error"] = "IPQS submission failed"
            return misperrors

    parser = IPQualityScoreParser(attribute)
    parser.ipqs_parser(json_response, enrich_type)
    return parser.get_results()


def introspection():
    """The function that returns a dict of the supported \
        attributes (input and output) by your expansion module."""
    return mispattributes


def version():
    """The function that returns a dict with the version and \
        the associated meta-data including potential
    configurations required of the module."""
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def ipqs_process(ipqsdata):
    """Process the JSON file returned by IPQS where 'result' is a list"""
    if not ipqsdata:
        misperrors["error"] = "Unable to parse results."
        return misperrors

    try:
        sample = ipqsdata
        r = {"results": []}

        # 1. Determine Tags by checking the results list
        # We look for any entry that is 'detected' to mark the whole sample
        results_list = sample.get("result", [])
        # 2. Extract Base File Metadata
        # We apply the tags here so the MD5/SHA256 are categorized in MISP/SOAR
        field_map = {
            "md5": "md5",
            "sha1": "sha1",
            "file_name": "filename",
            "file_hash": "sha256",
            "file_size": "size-in-bytes",
            "file_type": "mime-type",
        }

        for key, misp_type in field_map.items():
            if sample.get(key):
                r["results"].append(
                    {
                        "types": misp_type,
                        "values": sample[key],
                    }
                )

        # 3. Process the results list (Threat Names / Detections)
        for res in results_list:
            tags = [
                f"Detected:{res.get('detected', 'none')}",
                f"Error:{res.get('error', '')}",
            ]
            if res.get("name"):
                r["results"].append(
                    {"types": "text", "values": res["name"], "tags": tags}
                )
        
        logger.info("IPQS submission processed successfully")
        return r
        

    except Exception as e:
        logger.error("Error processing IPQS data: %s", str(e))
        misperrors["error"] = f"Processing error: {str(e)}"
        return misperrors
