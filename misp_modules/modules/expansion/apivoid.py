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
    "version": "0.3",
    "author": "Christian Studer",
    "description": "Query APIVoid v2 for DNS records, SSL certificates and email verification.",
    "module-type": ["expansion", "hover"],
    "name": "APIVoid",
    "logo": "apivoid.png",
    "requirements": ["An APIVoid v2 API key with 2 credits for domain lookups or 1 credit for email verification"],
    "features": (
        "This module queries APIVoid v2 for DNS records and SSL certificates of domains and hostnames, or verifies"
        " email addresses. Results are returned as MISP objects.\n\nConfigure `apikey` with a key from the APIVoid v2"
        " dashboard (https://dash.apivoid.com/); v1 keys must be replaced. Each successful API call costs 1 credit:"
        " domain and hostname enrichment uses 2 calls, and email verification uses 1. Account overage settings apply."
    ),
    "references": ["https://www.apivoid.com/", "https://docs.apivoid.com/"],
    "input": "A domain, hostname or email attribute.",
    "output": "DNS records, X.509 certificates or an APIVoid email verification object.",
}
moduleconfig = ["apikey"]


class APIVoidError(Exception):
    """An API failure that can be reported to the MISP user."""


class APIVoidParser:
    def __init__(self, attribute):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.attribute = self.misp_event.add_attribute(**self.attribute)
        self.url = "https://api.apivoid.com/v2/{}"

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event.get(key, []) for key in ("Attribute", "Object")}
        return {"results": results}

    def _query(self, service, apikey, payload, timeout=30):
        try:
            response = requests.post(
                self.url.format(service),
                headers={"X-API-Key": apikey},
                json=payload,
                timeout=timeout,
            )
        except requests.Timeout:
            raise APIVoidError(f"APIVoid {service} request timed out.") from None
        except requests.RequestException:
            raise APIVoidError(f"Unable to contact APIVoid {service}.") from None
        try:
            data = response.json()
        except ValueError:
            raise APIVoidError(f"APIVoid {service} returned invalid JSON (HTTP {response.status_code}).") from None
        if not isinstance(data, dict):
            raise APIVoidError(f"APIVoid {service} returned an unexpected response format.")
        if response.status_code != 200 or "error" in data:
            message = str(data.get("error") or "Request failed").replace(apikey, "[redacted]")
            if response.status_code == 429 and response.headers.get("Retry-After"):
                message += f" Retry after {response.headers['Retry-After']} seconds."
            raise APIVoidError(f"APIVoid {service} error (HTTP {response.status_code}): {message}")
        return data

    def parse_domain(self, apikey):
        mapping = {"a": "resolution-of", "aaaa": "resolution-of", "mx": "mail-server-of", "ns": "server-name-of"}
        dnslookup = self._query("dns-lookup", apikey, {"host": self.attribute.value, "dns_types": "A,AAAA,MX,NS"})
        records = dnslookup["records"]
        if not isinstance(records, dict):
            raise APIVoidError("APIVoid dns-lookup returned an unexpected response format.")
        for record_type, relationship in mapping.items():
            for item in records.get(record_type, []):
                self._handle_dns_record(dnslookup["host"], item, record_type, relationship)
        try:
            ssl = self._query("ssl-info", apikey, {"host": self.attribute.value}, timeout=60)
        except APIVoidError as error:
            if not self.misp_event.objects:
                raise
            # Keep DNS enrichment when only the SSL request fails, and make the partial result explicit.
            warning = str(error)
            comment = getattr(self.attribute, "comment", None)
            self.attribute.comment = f"{comment}\n{warning}" if comment else warning
            return
        if ssl["certificate"]["found"]:
            self._parse_ssl_certificate(ssl["certificate"])

    def handle_email(self, apikey):
        emaillookup = self._query("email-verify", apikey, {"email": self.attribute.value})
        email_verification = MISPObject("apivoid-email-verification")
        boolean_attributes = [
            "valid_format",
            "suspicious_username",
            "suspicious_email",
            "dirty_words_username",
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
                **{"type": "boolean", "value": emaillookup[boolean_attribute]},
            )
        email_verification.add_attribute("email", **{"type": "email", "value": emaillookup["email"]})
        email_verification.add_attribute("username", **{"type": "text", "value": emaillookup["username"]})
        email_verification.add_attribute(
            "role_address",
            **{"type": "boolean", "value": emaillookup["role_address"]},
        )
        email_verification.add_attribute("domain", **{"type": "domain", "value": emaillookup["domain"]})
        email_verification.add_attribute("score", **{"type": "float", "value": emaillookup["score"]})
        email_verification.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(email_verification)

    def _handle_dns_record(self, host, item, record_type, relationship):
        dns_record = MISPObject("dns-record")
        dns_record.add_attribute("queried-domain", type="domain", value=host)
        attribute_type = "ip-dst" if record_type in ("a", "aaaa") else "domain"
        dns_record.add_attribute(f"{record_type}-record", type=attribute_type, value=item["target"])
        dns_record.add_reference(self.attribute.uuid, relationship)
        self.misp_event.add_object(dns_record)

    def _parse_ssl_certificate(self, certificate):
        x509 = MISPObject("x509")
        for algorithm in ("sha1", "sha256"):
            fingerprint = f"x509-fingerprint-{algorithm}"
            x509.add_attribute(fingerprint, type=fingerprint, value=certificate[f"fingerprint_{algorithm}"])
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
        self.misp_event.add_object(x509)


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
    try:
        if attribute["type"] in ["domain", "hostname"]:
            apivoid_parser.parse_domain(apikey)
        else:
            apivoid_parser.handle_email(apikey)
    except APIVoidError as error:
        return {"error": str(error)}
    except (KeyError, TypeError, ValueError):
        return {"error": "APIVoid returned an unexpected response format."}
    return apivoid_parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
