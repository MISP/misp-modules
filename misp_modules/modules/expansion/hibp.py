# -*- coding: utf-8 -*-
import json

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["email-dst", "email-src"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.3",
    "author": "Corsin Camichel, Aurélien Schwab",
    "description": "Module to access haveibeenpwned.com API.",
    "module-type": ["hover"],
    "name": "Have I Been Pwned Lookup",
    "logo": "hibp.png",
    "requirements": [],
    "features": (
        "The module takes an email address as input and queries haveibeenpwned.com API to find additional information"
        " about it. This additional information actually tells if any account using the email address has already been"
        " compromised in a data breach, and returns one breach object per breach it appears in."
    ),
    "references": ["https://haveibeenpwned.com/"],
    "input": "An email address",
    "output": "One breach object per data breach the email address appears in.",
}
moduleconfig = ["api_key"]

haveibeenpwned_api_url = "https://haveibeenpwned.com/api/v3/breachedaccount/"
API_KEY = ""  # details at https://www.troyhunt.com/authentication-and-the-have-i-been-pwned-api/

# HIBP breach fields (v3) mapped to breach object relations and their types.
_FIELD_MAPPING = (
    ("Name", "name", "text"),
    ("Title", "title", "text"),
    ("Domain", "domain", "domain"),
    ("BreachDate", "breach-date", "datetime"),
    ("AddedDate", "added-date", "datetime"),
    ("ModifiedDate", "modification-date", "datetime"),
    ("PwnCount", "pwn-count", "counter"),
    ("Description", "description", "text"),
)


def _parse_breach(breach):
    """Build a MISP breach object from one HIBP v3 breach.

    Every relation is typed explicitly, because pymisp does not bundle the
    breach template yet."""
    misp_object = MISPObject("breach")
    for field, relation, attribute_type in _FIELD_MAPPING:
        value = breach.get(field)
        if value is not None and value != "":
            misp_object.add_attribute(relation, **{"type": attribute_type, "value": value})
    for data_class in breach.get("DataClasses") or []:
        misp_object.add_attribute("data-classes", **{"type": "text", "value": data_class})
    for field, relation in (("IsVerified", "verified"), ("IsSensitive", "sensitive")):
        if isinstance(breach.get(field), bool):
            misp_object.add_attribute(relation, **{"type": "boolean", "value": str(breach[field])})
    misp_object.add_attribute("source", **{"type": "text", "value": "Have I Been Pwned"})
    return misp_object


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attributes type"}
    email = attribute["value"]

    if request.get("config") is None or request["config"].get("api_key") is None:
        return {"error": "Have I Been Pwned authentication is incomplete (no API key)"}
    API_KEY = request["config"].get("api_key")

    # Without truncateResponse=false the v3 API answers with breach names only,
    # and there is nothing to fill a breach object with.
    r = requests.get(
        haveibeenpwned_api_url + email,
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": API_KEY},
    )
    if r.status_code == 404:
        # HIBP answers 404 when the address appears in no breach at all.
        return {"error": f"haveibeenpwned.com has no breach for {email}."}
    if r.status_code != 200:
        return {"error": f"haveibeenpwned.com API not accessible (HTTP {r.status_code})"}
    try:
        breaches = r.json()
    except ValueError:
        return {"error": "haveibeenpwned.com returned an invalid JSON response."}
    if not breaches:
        return {"error": f"haveibeenpwned.com has no breach for {email}."}

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    for breach in breaches:
        misp_object = _parse_breach(breach)
        misp_object.add_reference(input_attribute.uuid, "related-to")
        misp_event.add_object(misp_object)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
