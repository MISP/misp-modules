import json
import logging
import re
from typing import Any, Dict, List

import requests
from pymisp import Distribution, MISPEvent, MISPObject
from requests.exceptions import ConnectTimeout, HTTPError, InvalidURL, ProxyError

from . import check_input_attribute, standard_error_message

ip_query_input_type = ["ip-src", "ip-dst"]
domain_query_input_type = ["hostname", "domain"]
email_query_input_type = [
    "email",
    "email-src",
    "email-dst",
    "target-email",
    "whois-registrant-email",
]
phone_query_input_type = ["phone-number", "whois-registrant-phone"]

md5_query_input_type = [
    "md5",
    "x509-fingerprint-md5",
    "ja3-fingerprint-md5",
    "hassh-md5",
    "hasshserver-md5",
]

sha1_query_input_type = ["sha1", "x509-fingerprint-sha1"]

sha256_query_input_type = ["sha256", "x509-fingerprint-sha256"]

sha512_query_input_type = ["sha512"]

misperrors = {"error": "Error"}
mispattributes = {
    "input": (
        ip_query_input_type
        + domain_query_input_type
        + email_query_input_type
        + phone_query_input_type
        + md5_query_input_type
        + sha1_query_input_type
        + sha256_query_input_type
        + sha512_query_input_type
    ),
    "format": "misp_standard",
}

moduleinfo = {
    "version": "0.1",
    "author": "Mike Champ",
    "description": (
        "HYAS Insight integration to MISP provides direct, high volume access to HYAS Insight data. It enables"
        " investigators and analysts to understand and defend against cyber adversaries and their infrastructure."
    ),
    "module-type": ["expansion", "hover"],
    "name": "HYAS Insight Lookup",
    "logo": "hyas.png",
    "requirements": ["A HYAS Insight API Key."],
    "features": (
        "This Module takes the IP Address, Domain, URL, Email, Phone Number, MD5, SHA1, Sha256, SHA512 MISP Attributes"
        " as input to query the HYAS Insight API.\n The results of the HYAS Insight API are than are then returned and"
        " parsed into Hyas Insight Objects. \n\nAn API key is required to submit queries to the HYAS Insight API.\n"
    ),
    "references": ["https://www.hyas.com/hyas-insight/"],
    "input": (
        "A MISP attribute of type IP Address(ip-src, ip-dst), Domain(hostname, domain), Email Address(email, email-src,"
        " email-dst, target-email, whois-registrant-email), Phone Number(phone-number, whois-registrant-phone),"
        " MDS(md5, x509-fingerprint-md5, ja3-fingerprint-md5, hassh-md5, hasshserver-md5), SHA1(sha1,"
        " x509-fingerprint-sha1), SHA256(sha256, x509-fingerprint-sha256), SHA512(sha512)"
    ),
    "output": "Hyas Insight objects, resulting from the query on the HYAS Insight API.",
}
moduleconfig = ["apikey"]
TIMEOUT = 60
logger = logging.getLogger("hyasinsight")
logger.setLevel(logging.DEBUG)
HYAS_API_BASE_URL = "https://insight.hyas.com/api/ext/"
WHOIS_CURRENT_BASE_URL = "https://api.hyas.com/"
DEFAULT_DISTRIBUTION_SETTING = Distribution.your_organisation_only.value
IPV4_REGEX = r"\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b([^\/]|$)"
IPV6_REGEX = r"\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:(?:(:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b"  # noqa: E501
# Enrichment Types
# HYAS API endpoints
PASSIVE_DNS_ENDPOINT = "passivedns"
DYNAMIC_DNS_ENDPOINT = "dynamicdns"
PASSIVE_HASH_ENDPOINT = "passivehash"
SINKHOLE_ENDPOINT = "sinkhole"
SSL_CERTIFICATE_ENDPOINT = "ssl_certificate"
DEVICE_GEO_ENDPOINT = "device_geo"
WHOIS_HISTORIC_ENDPOINT = "whois"
WHOIS_CURRENT_ENDPOINT = "whois/v1"
MALWARE_RECORDS_ENDPOINT = "sample"
MALWARE_INFORMATION_ENDPOINT = "sample/information"
C2ATTRIBUTION_ENDPOINT = "c2attribution"
OPEN_SOURCE_INDICATORS_ENDPOINT = "os_indicators"

# HYAS API endpoint params
DOMAIN_PARAM = "domain"
IP_PARAM = "ip"
IPV4_PARAM = "ipv4"
IPV6_PARAM = "ipv6"
EMAIL_PARAM = "email"
PHONE_PARAM = "phone"
MD5_PARAM = "md5"
SHA256_PARAM = "sha256"
SHA512_PARAM = "sha512"
HASH_PARAM = "hash"
SHA1_PARAM = "sha1"

HYAS_IP_ENRICHMENT_ENDPOINTS_LIST = [
    DYNAMIC_DNS_ENDPOINT,
    PASSIVE_DNS_ENDPOINT,
    PASSIVE_HASH_ENDPOINT,
    SINKHOLE_ENDPOINT,
    SSL_CERTIFICATE_ENDPOINT,
    DEVICE_GEO_ENDPOINT,
    C2ATTRIBUTION_ENDPOINT,
    MALWARE_RECORDS_ENDPOINT,
    OPEN_SOURCE_INDICATORS_ENDPOINT,
]
HYAS_DOMAIN_ENRICHMENT_ENDPOINTS_LIST = [
    PASSIVE_DNS_ENDPOINT,
    DYNAMIC_DNS_ENDPOINT,
    WHOIS_HISTORIC_ENDPOINT,
    MALWARE_RECORDS_ENDPOINT,
    WHOIS_CURRENT_ENDPOINT,
    PASSIVE_HASH_ENDPOINT,
    C2ATTRIBUTION_ENDPOINT,
    SSL_CERTIFICATE_ENDPOINT,
    OPEN_SOURCE_INDICATORS_ENDPOINT,
]
HYAS_EMAIL_ENRICHMENT_ENDPOINTS_LIST = [
    DYNAMIC_DNS_ENDPOINT,
    WHOIS_HISTORIC_ENDPOINT,
    C2ATTRIBUTION_ENDPOINT,
]
HYAS_PHONE_ENRICHMENT_ENDPOINTS_LIST = [WHOIS_HISTORIC_ENDPOINT]
HYAS_SHA1_ENRICHMENT_ENDPOINTS_LIST = [
    SSL_CERTIFICATE_ENDPOINT,
    MALWARE_INFORMATION_ENDPOINT,
    OPEN_SOURCE_INDICATORS_ENDPOINT,
]
HYAS_SHA256_ENRICHMENT_ENDPOINTS_LIST = [
    C2ATTRIBUTION_ENDPOINT,
    MALWARE_INFORMATION_ENDPOINT,
    OPEN_SOURCE_INDICATORS_ENDPOINT,
]
HYAS_SHA512_ENRICHMENT_ENDPOINTS_LIST = [MALWARE_INFORMATION_ENDPOINT]
HYAS_MD5_ENRICHMENT_ENDPOINTS_LIST = [
    MALWARE_RECORDS_ENDPOINT,
    MALWARE_INFORMATION_ENDPOINT,
    OPEN_SOURCE_INDICATORS_ENDPOINT,
]

HYAS_OBJECT_NAMES = {
    DYNAMIC_DNS_ENDPOINT: "Dynamic DNS Information",
    PASSIVE_HASH_ENDPOINT: "Passive Hash Information",
    SINKHOLE_ENDPOINT: "Sinkhole Information",
    SSL_CERTIFICATE_ENDPOINT: "SSL Certificate Information",
    DEVICE_GEO_ENDPOINT: "Mobile Geolocation Information",
    C2ATTRIBUTION_ENDPOINT: "C2 Attribution Information",
    PASSIVE_DNS_ENDPOINT: "Passive DNS Information",
    WHOIS_HISTORIC_ENDPOINT: "Whois Related Information",
    WHOIS_CURRENT_ENDPOINT: "Whois Current Related Information",
    MALWARE_INFORMATION_ENDPOINT: "Malware Sample Information",
    OPEN_SOURCE_INDICATORS_ENDPOINT: "Open Source Intel for malware, ssl certificates and other indicators Information",
    MALWARE_RECORDS_ENDPOINT: "Malware Sample Records Information",
}


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


def misp_object(endpoint, attribute_value):
    object_name = HYAS_OBJECT_NAMES[endpoint]
    hyas_object = MISPObject(object_name)
    hyas_object.distribution = DEFAULT_DISTRIBUTION_SETTING
    hyas_object.template_uuid = "d69d3d15-7b4d-49b1-9e0a-bb29f3d421d9"
    hyas_object.template_id = "1"
    hyas_object.description = "HYAS INSIGHT " + object_name
    hyas_object.comment = "HYAS INSIGHT " + object_name + " for " + attribute_value
    setattr(hyas_object, "meta-category", "network")
    description = "An object containing the enriched attribute and related entities from HYAS Insight."
    hyas_object.from_dict(
        **{
            "meta-category": "misc",
            "description": description,
            "distribution": DEFAULT_DISTRIBUTION_SETTING,
        }
    )
    return hyas_object


def flatten_json(y: Dict) -> Dict[str, Any]:
    """
    :param y: raw_response from HYAS api
    :return: Flatten json response
    """
    out = {}

    def flatten(x, name=""):
        # If the Nested key-value
        # pair is of dict type
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + "_")
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


def get_flatten_json_response(raw_api_response: List[Dict]) -> List[Dict]:
    """
    :param raw_api_response: raw_api response from the API
    :return: Flatten Json response
    """
    flatten_json_response = []
    if raw_api_response:
        for obj in raw_api_response:
            flatten_json_response.append(flatten_json(obj))

    return flatten_json_response


def request_body(query_input, query_param, current):
    """
    This Method returns the request body for specific endpoint.
    """

    if current:
        return {"applied_filters": {query_input: query_param, "current": True}}
    else:
        return {"applied_filters": {query_input: query_param}}


def malware_info_lookup_to_markdown(results: Dict) -> list:
    scan_results = results.get("scan_results", [])
    out = []
    if scan_results:
        for res in scan_results:
            malware_info_data = {
                "avscan_score": results.get("avscan_score", ""),
                "md5": results.get("md5", ""),
                "av_name": res.get("av_name", ""),
                "def_time": res.get("def_time", ""),
                "threat_found": res.get("threat_found", ""),
                "scan_time": results.get("scan_time", ""),
                "sha1": results.get("sha1", ""),
                "sha256": results.get("sha256", ""),
                "sha512": results.get("sha512", ""),
            }
            out.append(malware_info_data)
    else:
        malware_info_data = {
            "avscan_score": results.get("avscan_score", ""),
            "md5": results.get("md5", ""),
            "av_name": "",
            "def_time": "",
            "threat_found": "",
            "scan_time": results.get("scan_time", ""),
            "sha1": results.get("sha1", ""),
            "sha256": results.get("sha256", ""),
            "sha512": results.get("sha512", ""),
        }
        out.append(malware_info_data)
    return out


class RequestHandler:
    """A class for handling any outbound requests from this module."""

    def __init__(self, apikey):
        self.session = requests.Session()
        self.api_key = apikey

    def get(self, url: str, headers: dict = None, req_body=None) -> requests.Response:
        """General post method to fetch the response from HYAS Insight."""
        response = []
        try:
            response = self.session.post(url, headers=headers, json=req_body)
            if response:
                response = response.json()
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            msg = "Error connecting with the HYAS Insight."
            logger.error(f"{msg} Error: {error}")
            misperrors["error"] = msg
        return response

    def hyas_lookup(self, end_point: str, query_input, query_param, current=False) -> requests.Response:
        """Do a lookup call."""
        # Building the request
        if current:
            url = f"{WHOIS_CURRENT_BASE_URL}{WHOIS_CURRENT_ENDPOINT}"
        else:
            url = f"{HYAS_API_BASE_URL}{end_point}"
        headers = {
            "Content-type": "application/json",
            "X-API-Key": self.api_key,
            "User-Agent": "Misp Modules",
        }
        req_body = request_body(query_input, query_param, current)
        try:
            response = self.get(url, headers, req_body)
        except HTTPError as error:
            msg = f"Error when requesting data from HYAS Insight. {error.response}: {error.response.reason}"
            logger.error(msg)
            misperrors["error"] = msg
            raise
        return response


class HyasInsightParser:
    """A class for handling the enrichment objects"""

    def __init__(self, attribute):
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)

        self.c2_attribution_data_items = [
            "actor_ipv4",
            "c2_domain",
            "c2_ip",
            "c2_url",
            "datetime",
            "email",
            "email_domain",
            "referrer_domain",
            "referrer_ipv4",
            "referrer_url",
            "sha256",
        ]
        self.c2_attribution_data_items_friendly_names = {
            "actor_ipv4": "Actor IPv4",
            "c2_domain": "C2 Domain",
            "c2_ip": "C2 IP",
            "c2_url": "C2 URL",
            "datetime": "DateTime",
            "email": "Email",
            "email_domain": "Email Domain",
            "referrer_domain": "Referrer Domain",
            "referrer_ipv4": "Referrer IPv4",
            "referrer_url": "Referrer URL",
            "sha256": "SHA256",
        }

        self.device_geo_data_items = [
            "datetime",
            "device_user_agent",
            "geo_country_alpha_2",
            "geo_horizontal_accuracy",
            "ipv4",
            "ipv6",
            "latitude",
            "longitude",
            "wifi_bssid",
        ]

        self.device_geo_data_items_friendly_names = {
            "datetime": "DateTime",
            "device_user_agent": "Device User Agent",
            "geo_country_alpha_2": "Alpha-2 Code",
            "geo_horizontal_accuracy": "GPS Horizontal Accuracy",
            "ipv4": "IPv4 Address",
            "ipv6": "IPv6 Address",
            "latitude": "Latitude",
            "longitude": "Longitude",
            "wifi_bssid": "WIFI BSSID",
        }

        self.dynamic_dns_data_items = [
            "a_record",
            "account",
            "created",
            "created_ip",
            "domain",
            "domain_creator_ip",
            "email",
        ]

        self.dynamic_dns_data_items_friendly_names = {
            "a_record": "A Record",
            "account": "Account Holder",
            "created": "Created Date",
            "created_ip": "Account Holder IP Address",
            "domain": "Domain",
            "domain_creator_ip": "Domain Creator IP Address",
            "email": "Email Address",
        }

        self.os_indicators_data_items = [
            "context",
            "datetime",
            "domain",
            "domain_2tld",
            "first_seen",
            "ipv4",
            "ipv6",
            "last_seen",
            "md5",
            "sha1",
            "sha256",
            "source_name",
            "source_url",
            "url",
        ]

        self.os_indicators_data_items_friendly_names = {
            "context": "Context",
            "datetime": "DateTime",
            "domain": "Domain",
            "domain_2tld": "Domain 2TLD",
            "first_seen": "First Seen",
            "ipv4": "IPv4 Address",
            "ipv6": "IPv6 Address",
            "last_seen": "Last Seen",
            "md5": "MD5",
            "sha1": "SHA1",
            "sha256": "SHA256",
            "source_name": "Source Name",
            "source_url": "Source URL",
            "url": "URL",
        }

        self.passive_dns_data_items = [
            "cert_name",
            "count",
            "domain",
            "first_seen",
            "ip_geo_city_name",
            "ip_geo_country_iso_code",
            "ip_geo_country_name",
            "ip_geo_location_latitude",
            "ip_geo_location_longitude",
            "ip_geo_postal_code",
            "ip_ip",
            "ip_isp_autonomous_system_number",
            "ip_isp_autonomous_system_organization",
            "ip_isp_ip_address",
            "ip_isp_isp",
            "ip_isp_organization",
            "ipv4",
            "ipv6",
            "last_seen",
        ]

        self.passive_dns_data_items_friendly_names = {
            "cert_name": "Certificate Provider Name",
            "count": "Passive DNS Count",
            "domain": "Domain",
            "first_seen": "First Seen",
            "ip_geo_city_name": "IP Organization City",
            "ip_geo_country_iso_code": "IP Organization Country ISO Code",
            "ip_geo_country_name": "IP Organization Country Name",
            "ip_geo_location_latitude": "IP Organization Latitude",
            "ip_geo_location_longitude": "IP Organization Longitude",
            "ip_geo_postal_code": "IP Organization Postal Code",
            "ip_ip": "IP Address",
            "ip_isp_autonomous_system_number": "ASN IP",
            "ip_isp_autonomous_system_organization": "ASO IP",
            "ip_isp_ip_address": "IP Address",
            "ip_isp_isp": "ISP",
            "ip_isp_organization": "ISP Organization",
            "ipv4": "IPv4 Address",
            "ipv6": "IPv6 Address",
            "last_seen": "Last Seen",
        }

        self.passive_hash_data_items = ["domain", "md5_count"]

        self.passive_hash_data_items_friendly_names = {
            "domain": "Domain",
            "md5_count": "Passive DNS Count",
        }

        self.malware_records_data_items = [
            "datetime",
            "domain",
            "ipv4",
            "ipv6",
            "md5",
            "sha1",
            "sha256",
        ]

        self.malware_records_data_items_friendly_names = {
            "datetime": "DateTime",
            "domain": "Domain",
            "ipv4": "IPv4 Address",
            "ipv6": "IPv6 Address",
            "md5": "MD5",
            "sha1": "SHA1",
            "sha256": "SHA256",
        }

        self.malware_information_data_items = [
            "avscan_score",
            "md5",
            "av_name",
            "def_time",
            "threat_found",
            "scan_time",
            "sha1",
            "sha256",
            "sha512",
        ]

        self.malware_information_data_items_friendly_names = {
            "avscan_score": "AV Scan Score",
            "md5": "MD5",
            "av_name": "AV Name",
            "def_time": "AV DateTime",
            "threat_found": "Source",
            "scan_time": "Scan DateTime",
            "sha1": "SHA1",
            "sha256": "SHA256",
            "sha512": "SHA512",
        }

        self.sinkhole_data_items = [
            "count",
            "country_name",
            "country_code",
            "data_port",
            "datetime",
            "ipv4",
            "last_seen",
            "organization_name",
            "sink_source",
        ]

        self.sinkhole_data_items_friendly_names = {
            "count": "Sinkhole Count",
            "country_name": "IP Address Country",
            "country_code": "IP Address Country Code",
            "data_port": "Data Port",
            "datetime": "First Seen",
            "ipv4": "IP Address",
            "last_seen": "Last Seen",
            "organization_name": "ISP Organization",
            "sink_source": "Sink Source IP",
        }

        self.ssl_certificate_data_items = [
            "ip",
            "ssl_cert_cert_key",
            "ssl_cert_expire_date",
            "ssl_cert_issue_date",
            "ssl_cert_issuer_commonName",
            "ssl_cert_issuer_countryName",
            "ssl_cert_issuer_localityName",
            "ssl_cert_issuer_organizationName",
            "ssl_cert_issuer_organizationalUnitName",
            "ssl_cert_issuer_stateOrProvinceName",
            "ssl_cert_md5",
            "ssl_cert_serial_number",
            "ssl_cert_sha1",
            "ssl_cert_sha_256",
            "ssl_cert_sig_algo",
            "ssl_cert_ssl_version",
            "ssl_cert_subject_commonName",
            "ssl_cert_subject_countryName",
            "ssl_cert_subject_localityName",
            "ssl_cert_subject_organizationName",
            "ssl_cert_subject_organizationalUnitName",
            "ssl_cert_timestamp",
        ]

        self.ssl_certificate_data_items_friendly_names = {
            "ip": "IP Address",
            "ssl_cert_cert_key": "Certificate Key",
            "ssl_cert_expire_date": "Certificate Expiration Date",
            "ssl_cert_issue_date": "Certificate Issue Date",
            "ssl_cert_issuer_commonName": "Issuer Common Name",
            "ssl_cert_issuer_countryName": "Issuer Country Name",
            "ssl_cert_issuer_localityName": "Issuer City Name",
            "ssl_cert_issuer_organizationName": "Issuer Organization Name",
            "ssl_cert_issuer_organizationalUnitName": "Issuer Organization Unit Name",
            "ssl_cert_issuer_stateOrProvinceName": "Issuer State or Province Name",
            "ssl_cert_md5": "Certificate MD5",
            "ssl_cert_serial_number": "Certificate Serial Number",
            "ssl_cert_sha1": "Certificate SHA1",
            "ssl_cert_sha_256": "Certificate SHA256",
            "ssl_cert_sig_algo": "Certificate Signature Algorithm",
            "ssl_cert_ssl_version": "SSL Version",
            "ssl_cert_subject_commonName": "Reciever Subject Name",
            "ssl_cert_subject_countryName": "Receiver Country Name",
            "ssl_cert_subject_localityName": "Receiver City Name",
            "ssl_cert_subject_organizationName": "Receiver Organization Name",
            "ssl_cert_subject_organizationalUnitName": "Receiver Organization Unit Name",
            "ssl_cert_timestamp": "Certificate DateTime",
        }

        self.whois_historic_data_items = [
            "abuse_emails",
            "address",
            "city",
            "country",
            "datetime",
            "domain",
            "domain_2tld",
            "domain_created_datetime",
            "domain_expires_datetime",
            "domain_updated_datetime",
            "email",
            "idn_name",
            "name",
            "nameserver",
            "organization",
            "phone",
            "privacy_punch",
            "registrar",
        ]

        self.whois_historic_data_items_friendly_names = {
            "abuse_emails": "Abuse Emails",
            "address": "Address",
            "city": "City",
            "country": "Country",
            "datetime": "Datetime",
            "domain": "Domain",
            "domain_2tld": "Domain 2tld",
            "domain_created_datetime": "Domain Created Time",
            "domain_expires_datetime": "Domain Expires Time",
            "domain_updated_datetime": "Domain Updated Time",
            "email": "Email Address",
            "idn_name": "IDN Name",
            "name": "Name",
            "nameserver": "Nameserver",
            "organization": "Organization",
            "phone": "Phone Info",
            "privacy_punch": "Privacy Punch",
            "registrar": "Registrar",
        }

        self.whois_current_data_items = [
            "abuse_emails",
            "address",
            "city",
            "country",
            "datetime",
            "domain",
            "domain_2tld",
            "domain_created_datetime",
            "domain_expires_datetime",
            "domain_updated_datetime",
            "email",
            "idn_name",
            "name",
            "nameserver",
            "organization",
            "phone",
            "privacy_punch",
            "registrar",
            "state",
        ]

        self.whois_current_data_items_friendly_names = {
            "abuse_emails": "Abuse Emails",
            "address": "Address",
            "city": "City",
            "country": "Country",
            "datetime": "Datetime",
            "domain": "Domain",
            "domain_2tld": "Domain 2tld",
            "domain_created_datetime": "Domain Created Time",
            "domain_expires_datetime": "Domain Expires Time",
            "domain_updated_datetime": "Domain Updated Time",
            "email": "Email Address",
            "idn_name": "IDN Name",
            "name": "Name",
            "nameserver": "Nameserver",
            "organization": "Organization",
            "phone": "Phone",
            "privacy_punch": "Privacy Punch",
            "registrar": "Registrar",
            "state": "State",
        }

    def create_misp_attributes_and_objects(self, response, endpoint, attribute_value):
        flatten_json_response = get_flatten_json_response(response)
        data_items: List[str] = []
        data_items_friendly_names: Dict[str, str] = {}
        if endpoint == DEVICE_GEO_ENDPOINT:
            data_items: List[str] = self.device_geo_data_items
            data_items_friendly_names: Dict[str, str] = self.device_geo_data_items_friendly_names
        elif endpoint == DYNAMIC_DNS_ENDPOINT:
            data_items: List[str] = self.dynamic_dns_data_items
            data_items_friendly_names: Dict[str, str] = self.dynamic_dns_data_items_friendly_names
        elif endpoint == PASSIVE_DNS_ENDPOINT:
            data_items: List[str] = self.passive_dns_data_items
            data_items_friendly_names: Dict[str, str] = self.passive_dns_data_items_friendly_names
        elif endpoint == PASSIVE_HASH_ENDPOINT:
            data_items: List[str] = self.passive_hash_data_items
            data_items_friendly_names: Dict[str, str] = self.passive_hash_data_items_friendly_names
        elif endpoint == SINKHOLE_ENDPOINT:
            data_items: List[str] = self.sinkhole_data_items
            data_items_friendly_names: Dict[str, str] = self.sinkhole_data_items_friendly_names
        elif endpoint == WHOIS_HISTORIC_ENDPOINT:
            data_items = self.whois_historic_data_items
            data_items_friendly_names = self.whois_historic_data_items_friendly_names
        elif endpoint == WHOIS_CURRENT_ENDPOINT:
            data_items: List[str] = self.whois_current_data_items
            data_items_friendly_names: Dict[str, str] = self.whois_current_data_items_friendly_names
        elif endpoint == SSL_CERTIFICATE_ENDPOINT:
            data_items: List[str] = self.ssl_certificate_data_items
            data_items_friendly_names: Dict[str, str] = self.ssl_certificate_data_items_friendly_names
        elif endpoint == MALWARE_INFORMATION_ENDPOINT:
            data_items: List[str] = self.malware_information_data_items
            data_items_friendly_names = self.malware_information_data_items_friendly_names
        elif endpoint == MALWARE_RECORDS_ENDPOINT:
            data_items: List[str] = self.malware_records_data_items
            data_items_friendly_names = self.malware_records_data_items_friendly_names
        elif endpoint == OPEN_SOURCE_INDICATORS_ENDPOINT:
            data_items: List[str] = self.os_indicators_data_items
            data_items_friendly_names = self.os_indicators_data_items_friendly_names
        elif endpoint == C2ATTRIBUTION_ENDPOINT:
            data_items: List[str] = self.c2_attribution_data_items
            data_items_friendly_names = self.c2_attribution_data_items_friendly_names

        for result in flatten_json_response:
            hyas_object = misp_object(endpoint, attribute_value)
            for data_item in result.keys():
                if data_item in data_items:
                    data_item_text = data_items_friendly_names[data_item]
                    data_item_value = str(result[data_item])
                    hyas_object.add_attribute(**parse_attribute(hyas_object.comment, data_item_text, data_item_value))
            hyas_object.add_reference(self.attribute["uuid"], "related-to")
            self.misp_event.add_object(hyas_object)

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
        misperrors["error"] = "HYAS Insight apikey is missing"
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
        return {"error": "Unsupported attributes type for HYAS Insight Enrichment"}
    request_handler = RequestHandler(apikey)
    parser = HyasInsightParser(attribute)
    has_results = False
    if attribute_type in ip_query_input_type:
        ip_param = ""
        for endpoint in HYAS_IP_ENRICHMENT_ENDPOINTS_LIST:
            if endpoint == DEVICE_GEO_ENDPOINT:
                if re.match(IPV4_REGEX, attribute_value):
                    ip_param = IPV4_PARAM
                elif re.match(IPV6_REGEX, attribute_value):
                    ip_param = IPV6_PARAM
            elif endpoint == PASSIVE_HASH_ENDPOINT:
                ip_param = IPV4_PARAM
            elif endpoint == SINKHOLE_ENDPOINT:
                ip_param = IPV4_PARAM
            elif endpoint == MALWARE_RECORDS_ENDPOINT:
                ip_param = IPV4_PARAM
            else:
                ip_param = IP_PARAM
            enrich_response = request_handler.hyas_lookup(endpoint, ip_param, attribute_value)
            if endpoint == SSL_CERTIFICATE_ENDPOINT:
                enrich_response = enrich_response.get("ssl_certs")
            if enrich_response:
                has_results = True
                parser.create_misp_attributes_and_objects(enrich_response, endpoint, attribute_value)
    elif attribute_type in domain_query_input_type:
        for endpoint in HYAS_DOMAIN_ENRICHMENT_ENDPOINTS_LIST:
            if not endpoint == WHOIS_CURRENT_ENDPOINT:
                enrich_response = request_handler.hyas_lookup(endpoint, DOMAIN_PARAM, attribute_value)
            else:
                enrich_response = request_handler.hyas_lookup(
                    endpoint,
                    DOMAIN_PARAM,
                    attribute_value,
                    endpoint == WHOIS_CURRENT_ENDPOINT,
                )
                enrich_response = enrich_response.get("items")
            if enrich_response:
                has_results = True
                parser.create_misp_attributes_and_objects(enrich_response, endpoint, attribute_value)
    elif attribute_type in email_query_input_type:
        for endpoint in HYAS_EMAIL_ENRICHMENT_ENDPOINTS_LIST:
            enrich_response = request_handler.hyas_lookup(endpoint, EMAIL_PARAM, attribute_value)
            if enrich_response:
                has_results = True
                parser.create_misp_attributes_and_objects(enrich_response, endpoint, attribute_value)
    elif attribute_type in phone_query_input_type:
        for endpoint in HYAS_PHONE_ENRICHMENT_ENDPOINTS_LIST:
            enrich_response = request_handler.hyas_lookup(endpoint, PHONE_PARAM, attribute_value)
            if enrich_response:
                has_results = True
                parser.create_misp_attributes_and_objects(enrich_response, endpoint, attribute_value)
    elif attribute_type in md5_query_input_type:
        md5_param = MD5_PARAM
        for endpoint in HYAS_MD5_ENRICHMENT_ENDPOINTS_LIST:
            if endpoint == MALWARE_INFORMATION_ENDPOINT:
                md5_param = HASH_PARAM
            enrich_response = request_handler.hyas_lookup(endpoint, md5_param, attribute_value)
            if enrich_response:
                has_results = True
                if endpoint == MALWARE_INFORMATION_ENDPOINT:
                    enrich_response = malware_info_lookup_to_markdown(enrich_response)
                parser.create_misp_attributes_and_objects(enrich_response, endpoint, attribute_value)
    elif attribute_type in sha1_query_input_type:
        sha1_param = SHA1_PARAM
        for endpoint in HYAS_SHA1_ENRICHMENT_ENDPOINTS_LIST:
            if endpoint == MALWARE_INFORMATION_ENDPOINT:
                sha1_param = HASH_PARAM
            elif endpoint == SSL_CERTIFICATE_ENDPOINT:
                sha1_param = HASH_PARAM
            enrich_response = request_handler.hyas_lookup(endpoint, sha1_param, attribute_value)

            if enrich_response:
                has_results = True
                if endpoint == MALWARE_INFORMATION_ENDPOINT:
                    enrich_response = malware_info_lookup_to_markdown(enrich_response)
                parser.create_misp_attributes_and_objects(enrich_response, endpoint, attribute_value)
    elif attribute_type in sha256_query_input_type:
        sha256_param = SHA256_PARAM
        for endpoint in HYAS_SHA256_ENRICHMENT_ENDPOINTS_LIST:
            if endpoint == MALWARE_INFORMATION_ENDPOINT:
                sha256_param = HASH_PARAM
            enrich_response = request_handler.hyas_lookup(endpoint, sha256_param, attribute_value)
            if enrich_response:
                has_results = True
                if endpoint == MALWARE_INFORMATION_ENDPOINT:
                    enrich_response = malware_info_lookup_to_markdown(enrich_response)
                parser.create_misp_attributes_and_objects(enrich_response, endpoint, attribute_value)
    elif attribute_type in sha512_query_input_type:
        sha512_param = ""
        for endpoint in HYAS_SHA512_ENRICHMENT_ENDPOINTS_LIST:
            if endpoint == MALWARE_INFORMATION_ENDPOINT:
                sha512_param = HASH_PARAM
            enrich_response = request_handler.hyas_lookup(endpoint, sha512_param, attribute_value)
            if enrich_response:
                has_results = True
                if endpoint == MALWARE_INFORMATION_ENDPOINT:
                    enrich_response = malware_info_lookup_to_markdown(enrich_response)
                parser.create_misp_attributes_and_objects(enrich_response, endpoint, attribute_value)

    if has_results:
        return parser.get_results()
    else:
        return {"error": "No records found in HYAS Insight for the provided attribute."}


def introspection():
    """The function that returns a dict of the supported attributes (input and output) by your expansion module."""
    return mispattributes


def version():
    """The function that returns a dict with the version and the associated meta-data including potential
    configurations required of the module."""
    moduleinfo["config"] = moduleconfig
    return moduleinfo
