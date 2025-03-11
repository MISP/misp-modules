import json

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "domain",
        "hostname",
        "email",
        "email-src",
        "email-dst",
        "email-reply-to",
        "dns-soa-email",
        "target-email",
        "whois-registrant-email",
    ],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.2",
    "author": "Christian Studer",
    "description": "Module to query APIVoid with some domain attributes.",
    "module-type": ["expansion", "hover"],
    "name": "APIVoid",
    "logo": "apivoid.png",
    "requirements": ["A valid APIVoid API key with enough credits to proceed 2 queries"],
    "features": (
        "This module takes a domain name and queries API Void to get the related DNS records and the SSL certificates."
        " It returns then those pieces of data as MISP objects that can be added to the event.\n\nTo make it work, a"
        " valid API key and enough credits to proceed 2 queries (0.06 + 0.07 credits) are required."
    ),
    "references": ["https://www.apivoid.com/"],
    "input": "A domain attribute.",
    "output": "DNS records and SSL certificates related to the domain.",
}
moduleconfig = ["apikey"]


class APIVoidParser:
    def __init__(self, attribute):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.attribute)
        self.url = "https://endpoint.apivoid.com/{}/v1/pay-as-you-go/?key={}&"

    def get_results(self):
        if hasattr(self, "result"):
            return self.result
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object")}
        return {"results": results}

    def parse_domain(self, apikey):
        feature = "dnslookup"
        if requests.get(f"{self.url.format(feature, apikey)}stats").json()["credits_remained"] < 0.13:
            self.result = {"error": "You do not have enough APIVoid credits to proceed your request."}
            return
        mapping = {"A": "resolution-of", "MX": "mail-server-of", "NS": "server-name-of"}
        dnslookup = requests.get(f"{self.url.format(feature, apikey)}action=dns-any&host={self.attribute.value}").json()
        for item in dnslookup["data"]["records"]["items"]:
            record_type = item["type"]
            try:
                relationship = mapping[record_type]
            except KeyError:
                continue
            self._handle_dns_record(item, record_type, relationship)
        ssl = requests.get(f'{self.url.format("sslinfo", apikey)}host={self.attribute.value}').json()
        self._parse_ssl_certificate(ssl["data"]["certificate"])

    def handle_email(self, apikey):
        feature = "emailverify"
        if requests.get(f"{self.url.format(feature, apikey)}stats").json()["credits_remained"] < 0.06:
            self.result = {"error": "You do not have enough APIVoid credits to proceed your request."}
            return
        emaillookup = requests.get(f"{self.url.format(feature, apikey)}email={self.attribute.value}").json()
        email_verification = MISPObject("apivoid-email-verification")
        boolean_attributes = [
            "valid_format",
            "suspicious_username",
            "suspicious_email",
            "dirty_words_username",
            "suspicious_email",
            "valid_tld",
            "disposable",
            "has_a_records",
            "has_mx_records",
            "has_spf_records",
            "is_spoofable",
            "dmarc_configured",
            "dmarc_enforced",
            "free_email",
            "russian_free_email",
            "china_free_email",
            "suspicious_domain",
            "dirty_words_domain",
            "domain_popular",
            "risky_tld",
            "police_domain",
            "government_domain",
            "educational_domain",
            "should_block",
        ]
        for boolean_attribute in boolean_attributes:
            email_verification.add_attribute(
                boolean_attribute,
                **{"type": "boolean", "value": emaillookup["data"][boolean_attribute]},
            )
        email_verification.add_attribute("email", **{"type": "email", "value": emaillookup["data"]["email"]})
        email_verification.add_attribute("username", **{"type": "text", "value": emaillookup["data"]["username"]})
        email_verification.add_attribute(
            "role_address",
            **{"type": "boolean", "value": emaillookup["data"]["role_address"]},
        )
        email_verification.add_attribute("domain", **{"type": "domain", "value": emaillookup["data"]["domain"]})
        email_verification.add_attribute("score", **{"type": "float", "value": emaillookup["data"]["score"]})
        email_verification.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(email_verification)

    def _handle_dns_record(self, item, record_type, relationship):
        dns_record = MISPObject("dns-record")
        dns_record.add_attribute("queried-domain", type="domain", value=item["host"])
        attribute_type, feature = ("ip-dst", "ip") if record_type == "A" else ("domain", "target")
        dns_record.add_attribute(f"{record_type.lower()}-record", type=attribute_type, value=item[feature])
        dns_record.add_reference(self.attribute.uuid, relationship)
        self.misp_event.add_object(**dns_record)

    def _parse_ssl_certificate(self, certificate):
        x509 = MISPObject("x509")
        fingerprint = "x509-fingerprint-sha1"
        x509.add_attribute(fingerprint, type=fingerprint, value=certificate["fingerprint"])
        x509_mapping = {
            "subject": {"name": ("text", "subject")},
            "issuer": {"common_name": ("text", "issuer")},
            "signature": {"serial": ("text", "serial-number")},
            "validity": {
                "valid_from": ("datetime", "validity-not-before"),
                "valid_to": ("datetime", "validity-not-after"),
            },
        }
        certificate = certificate["details"]
        for feature, subfeatures in x509_mapping.items():
            for subfeature, mapping in subfeatures.items():
                attribute_type, relation = mapping
                x509.add_attribute(
                    relation,
                    type=attribute_type,
                    value=certificate[feature][subfeature],
                )
        x509.add_reference(self.attribute.uuid, "seen-by")
        self.misp_event.add_object(**x509)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("config", {}).get("apikey"):
        return {"error": "An API key for APIVoid is required."}
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    apikey = request["config"]["apikey"]
    apivoid_parser = APIVoidParser(attribute)
    if attribute["type"] in ["domain", "hostname"]:
        apivoid_parser.parse_domain(apikey)
    else:
        apivoid_parser.handle_email(apikey)
    return apivoid_parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
