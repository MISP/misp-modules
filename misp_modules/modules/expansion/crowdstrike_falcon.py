import json

from falconpy import Intel
from pymisp import MISPAttribute, MISPEvent

from . import check_input_attribute, standard_error_message

moduleinfo = {
    "version": "0.2",
    "author": "Christophe Vandeplas",
    "description": "Module to query CrowdStrike Falcon.",
    "module-type": ["expansion", "hover"],
    "name": "CrowdStrike Falcon",
    "logo": "crowdstrike.png",
    "requirements": ["A CrowdStrike API access (API id & key)"],
    "features": (
        "This module takes a MISP attribute as input to query a CrowdStrike Falcon API. The API returns then the result"
        " of the query with some types we map into compatible types we add as MISP attributes.\n\nPlease note that"
        " composite attributes composed by at least one of the input types mentionned below (domains, IPs, hostnames)"
        " are also supported."
    ),
    "references": ["https://www.crowdstrike.com/products/crowdstrike-falcon-faq/"],
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
misperrors = {"error": "Error"}
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


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    # validate CrowdStrike params
    if request.get("config"):
        if request["config"].get("apikey") is None:
            misperrors["error"] = "CrowdStrike apikey is missing"
            return misperrors
        if request["config"].get("api_id") is None:
            misperrors["error"] = "CrowdStrike api_id is missing"
            return misperrors

    # validate attribute
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request.get("attribute")
    if not any(input_type == attribute.get("type") for input_type in misp_type_in):
        return {"error": "Unsupported attribute type."}

    client = CSIntelAPI(request["config"]["api_id"], request["config"]["apikey"])

    attribute = MISPAttribute()
    attribute.from_dict(**request.get("attribute"))
    r = {"results": []}
    valid_type = False

    try:
        for k in misp_type_in:
            if attribute.type == k:
                # map the MISP type to the CrowdStrike type
                r["results"].append(lookup_indicator(client, attribute))
                valid_type = True
    except Exception as e:
        return {"error": f"{e}"}

    if not valid_type:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors
    return {"results": r.get("results").pop()}


def lookup_indicator(client, ref_attribute):
    result = client.search_indicator(ref_attribute.value)
    misp_event = MISPEvent()
    misp_event.add_attribute(**ref_attribute)

    for item in result.get("resources", []):
        for relation in item.get("relations"):
            if mapping_out.get(relation.get("type")):
                r = mapping_out[relation.get("type")].copy()
                r["value"] = relation.get("indicator")
                attribute = MISPAttribute()
                attribute.from_dict(**r)
                misp_event.add_attribute(**attribute)
        for actor in item.get("actors"):
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
        # 400 - bad request
        if r.get("status_code") == 400:
            raise Exception("HTTP Error 400 - Bad request.")

        # 404 - oh shit
        if r.get("status_code") == 404:
            raise Exception("HTTP Error 404 - awww snap.")

        # catch all?
        if r.get("status_code") != 200:
            raise Exception("HTTP Error: " + str(r.get("status_code")))

        if len(r.get("body").get("errors")):
            raise Exception("API Error: " + " | ".join(r.get("body").get("errors")))

        return r.get("body", {})
