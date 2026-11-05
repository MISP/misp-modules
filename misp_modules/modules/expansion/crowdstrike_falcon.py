import json
from datetime import datetime, timezone

from falconpy import Intel
from pymisp import MISPAttribute, MISPEvent
from pymisp.exceptions import PyMISPError

from . import check_input_attribute, standard_error_message

moduleinfo = {
    "version": "0.4",
    "author": "Christophe Vandeplas",
    "description": "Query CrowdStrike Falcon Intelligence indicators on demand.",
    "module-type": ["expansion", "hover"],
    "name": "CrowdStrike Falcon",
    "logo": "crowdstrike.png",
    "requirements": ["A Falcon OAuth2 API client with the Intel: Read scope and access to Falcon Intelligence"],
    "features": (
        "Run enrichment or hover on a supported attribute to query Falcon Intelligence and return related indicators"
        " and threat metadata. Set api_id to the OAuth2 client ID and apikey to the client secret. Publishing a MISP"
        " event does not run this lookup or create CrowdStrike sightings. See the [setup and verification"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/expansion/crowdstrike_falcon.md)."
    ),
    "references": ["https://www.falconpy.io/Service-Collections/Intel.html"],
    "input": (
        "A MISP attribute included in the following list:\n- domain\n- email-attachment\n- email-dst\n-"
        " email-reply-to\n- email-src\n- email-subject\n- filename\n- hostname\n- ip-src\n- ip-dst\n- md5\n- mutex\n-"
        " regkey\n- sha1\n- sha256\n- uri\n- url\n- user-agent\n- whois-registrant-email\n- x509-fingerprint-md5"
    ),
    "output": (
        "MISP attributes mapped after the CrowdStrike API has been queried, included in the following list:\n-"
        " hostname\n- email-src\n- email-subject\n- filename\n- md5\n- sha1\n- sha256\n- ip-dst\n- ip-dst\n- mutex\n-"
        " regkey\n- url\n- user-agent\n- x509-fingerprint-md5"
    ),
}
moduleconfig = ["api_id", "apikey"]
misp_type_in = [
    "domain",
    "email-attachment",
    "email-dst",
    "email-reply-to",
    "email-src",
    "email-subject",
    "filename",
    "hostname",
    "ip",
    "ip-src",
    "ip-dst",
    "md5",
    "mutex",
    "regkey",
    "sha1",
    "sha256",
    "uri",
    "url",
    "user-agent",
    "whois-registrant-email",
    "x509-fingerprint-md5",
]
mapping_out = {  # mapping between the MISP attributes type and the compatible CrowdStrike indicator types.
    "domain": {"type": "hostname", "to_ids": True},
    "email_address": {"type": "email-src", "to_ids": True},
    "email_subject": {"type": "email-subject", "to_ids": True},
    "file_name": {"type": "filename", "to_ids": True},
    "hash_md5": {"type": "md5", "to_ids": True},
    "hash_sha1": {"type": "sha1", "to_ids": True},
    "hash_sha256": {"type": "sha256", "to_ids": True},
    "ip_address": {"type": "ip-dst", "to_ids": True},
    "ip_address_block": {"type": "ip-dst", "to_ids": True},
    "mutex_name": {"type": "mutex", "to_ids": True},
    "registry": {"type": "regkey", "to_ids": True},
    "url": {"type": "url", "to_ids": True},
    "user_agent": {"type": "user-agent", "to_ids": True},
    "x509_serial": {"type": "x509-fingerprint-md5", "to_ids": True},
    "actors": {"type": "threat-actor", "category": "Attribution"},
    "malware_families": {"type": "text", "category": "Attribution"},
}
misp_type_out = [item["type"] for item in mapping_out.values()]
mispattributes = {"input": misp_type_in, "format": "misp_standard"}


class CrowdStrikeError(ValueError):
    """A diagnostic that does not expose credentials or raw service errors."""


API_ERROR_GUIDANCE = {
    400: "Check the indicator and request parameters.",
    401: "Check the OAuth2 client ID (api_id) and client secret (apikey).",
    403: "Check the Intel: Read API scope and the account's Falcon Intelligence access.",
    404: "Check Falcon Intelligence API availability for this account.",
    429: "Falcon API rate limit reached; retry later.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (ValueError, TypeError):
        return {"error": "The request must be a JSON object."}
    if not isinstance(request, dict):
        return {"error": "The request must be a JSON object."}
    config = request.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        return {"error": "CrowdStrike config must be an object."}
    for key, description in (("apikey", "OAuth2 client secret"), ("api_id", "OAuth2 client ID")):
        if not isinstance(config.get(key), str) or not config[key].strip():
            return {"error": f"CrowdStrike {key} is missing; configure the {description}."}

    # validate attribute
    if not isinstance(request.get("attribute"), dict) or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request.get("attribute")
    if not any(input_type == attribute.get("type") for input_type in misp_type_in):
        return {"error": "Unsupported attribute type."}

    try:
        attribute = MISPAttribute()
        attribute.from_dict(**request["attribute"])
    except (ValueError, TypeError, PyMISPError):
        return {"error": "Invalid MISP attribute; check its type, value and uuid."}
    try:
        client = CSIntelAPI(config["api_id"], config["apikey"])
        return {"results": lookup_indicator(client, attribute)}
    except CrowdStrikeError as exc:
        return {"error": str(exc)}
    except Exception:
        return {"error": "Unable to query or parse Falcon Intelligence; check API access and network connectivity."}


def lookup_indicator(client, ref_attribute):
    result = client.search_indicator(ref_attribute.value)
    misp_event = MISPEvent()
    misp_event.add_attribute(**ref_attribute)

    for item in result.get("resources", []):
        for relation in item.get("relations") or []:
            if mapping_out.get(relation.get("type")):
                r = mapping_out[relation.get("type")].copy()
                r["value"] = relation.get("indicator")
                attribute = MISPAttribute()
                attribute.from_dict(**r)
                misp_event.add_attribute(**attribute)
        for actor in item.get("actors") or []:
            r = mapping_out.get("actors").copy()
            r["value"] = actor
            attribute = MISPAttribute()
            attribute.from_dict(**r)
            misp_event.add_attribute(**attribute)
        if item.get("malware_families"):
            r = mapping_out.get("malware_families").copy()
            r["value"] = f"malware_families: {' | '.join(item.get('malware_families'))}"
            attribute = MISPAttribute()
            attribute.from_dict(**r)
            misp_event.add_attribute(**attribute)
        for ip_type in item.get("ip_address_types") or []:
            ip_type_attribute = {"type": "text", "category": "Other", "value": f"IP_Type: {ip_type}", "to_ids": False}
            attribute = MISPAttribute()
            attribute.from_dict(**ip_type_attribute)
            misp_event.add_attribute(**attribute)
        if item.get("malicious_confidence"):
            confidence_attribute = {
                "type": "text",
                "category": "Other",
                "value": f"Malicious_Confidence: {item.get('malicious_confidence')}",
                "to_ids": False,
            }
            attribute = MISPAttribute()
            attribute.from_dict(**confidence_attribute)
            misp_event.add_attribute(**attribute)
        for label in item.get("labels") or []:
            label_value = f"Label: {label.get('name')}"
            if label.get("created_on") and label.get("last_valid_on"):
                iso_created_on = datetime.fromtimestamp(label["created_on"], timezone.utc).isoformat()
                iso_last_valid_on = datetime.fromtimestamp(label["last_valid_on"], timezone.utc).isoformat()
                label_value += f" (created_on: {iso_created_on}, last_valid_on: {iso_last_valid_on})"
            label_attribute = {
                "type": "text",
                "category": "Other",
                "value": label_value,
                "to_ids": False,
            }
            attribute = MISPAttribute()
            attribute.from_dict(**label_attribute)
            misp_event.add_attribute(**attribute)
        if item.get("reports"):
            for report in item["reports"]:
                report_attribute = {
                    "type": "text",
                    "category": "Other",
                    "value": f"Report: {report}",
                    "to_ids": False,
                }
                attribute = MISPAttribute()
                attribute.from_dict(**report_attribute)
                misp_event.add_attribute(**attribute)
        if item.get("threat_types"):
            for threat in item["threat_types"]:
                threat_type_attribute = {
                    "type": "text",
                    "category": "Other",
                    "value": f"Threat_Type: {threat}",
                    "to_ids": False,
                }
                attribute = MISPAttribute()
                attribute.from_dict(**threat_type_attribute)
                misp_event.add_attribute(**attribute)
        if item.get("last_updated"):
            iso_last_updated = datetime.fromtimestamp(item["last_updated"], timezone.utc).isoformat()
            last_updated_attribute = {
                "type": "datetime",
                "category": "Other",
                "value": iso_last_updated,
                "to_ids": False,
            }
            attribute = MISPAttribute()
            attribute.from_dict(**last_updated_attribute)
            misp_event.add_attribute(**attribute)

    event = json.loads(misp_event.to_json())
    return {"Object": event.get("Object", []), "Attribute": event.get("Attribute", [])}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


class CSIntelAPI:
    def __init__(self, custid=None, custkey=None):
        # customer id and key should be passed when obj is created
        self.falcon = Intel(client_id=custid, client_secret=custkey)

    def search_indicator(self, query):
        r = self.falcon.query_indicator_entities(q=query)
        if not isinstance(r, dict) or not isinstance(r.get("status_code"), int):
            raise CrowdStrikeError("Falcon Intelligence returned an invalid API response.")
        status = r["status_code"]
        if status != 200:
            guidance = API_ERROR_GUIDANCE.get(status, "Check Falcon API availability and try again later.")
            raise CrowdStrikeError(f"HTTP Error: {status}. {guidance}")
        body = r.get("body")
        if not isinstance(body, dict):
            raise CrowdStrikeError("Falcon Intelligence returned an invalid API response body.")
        errors = body.get("errors") or []
        if errors:
            # Falcon errors are normally dictionaries. Do not join them as
            # strings or copy arbitrary service messages into MISP responses.
            for error in errors:
                if isinstance(error, dict):
                    code = error.get("code")
                    if isinstance(code, int) and code in API_ERROR_GUIDANCE:
                        raise CrowdStrikeError(f"API Error: {code}. {API_ERROR_GUIDANCE[code]}")
            raise CrowdStrikeError("API Error: Falcon Intelligence rejected the request.")
        resources = body.get("resources")
        if not isinstance(resources, list) or any(not isinstance(item, dict) for item in resources):
            raise CrowdStrikeError("Falcon Intelligence returned invalid or missing indicator resources.")
        return body
