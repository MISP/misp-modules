import json

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "onion-address",
        # 'domain',
        # 'ip-dst',
        # 'url',
        # Any other Attribute type...
    ],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "1",
    "author": "Sami Mokaddem",
    "name": "Onion Lookup",
    "description": (
        "MISP module using the MISP standard. Uses the onion-lookup service to get information about an onion."
    ),
    "module-type": [  # possible module-types: 'expansion', 'hover' or both
        "expansion",
        "hover",
    ],
    "references": ["https://onion.ail-project.org/"],
    "logo": "onion.png",
}

# config fields that your code expects from the site admin
moduleconfig = []


def getDetails(onion_address):
    url = f"https://onion.ail-project.org/api/lookup/{onion_address}"
    response = requests.get(url)
    return response.json()


"""
{
  "tags": [
    "infoleak:automatic-detection=\"base64\"",
    "infoleak:automatic-detection=\"credit-card\"",
    "infoleak:automatic-detection=\"onion\""
  ],
}
"""


def createObject(onion_details):
    misp_object = MISPObject("tor-hiddenservice")
    misp_object.comment = "custom-comment2"
    onion_address = misp_object.add_attribute("address", onion_details["id"])
    misp_object.add_attribute("first-seen", onion_details["first_seen"])
    misp_object.add_attribute("last-seen", onion_details["last_seen"])
    for lang in onion_details["languages"]:
        misp_object.add_attribute("language", lang)
    for title in onion_details["titles"]:
        misp_object.add_attribute("title", title)
    for tag in onion_details["tags"]:
        onion_address.add_tag(tag)
    return misp_object


def enrichOnion(misp_event, attribute):
    onion_address = attribute["value"]
    onion_details = getDetails(onion_address)
    misp_object = createObject(onion_details)
    misp_event.add_object(misp_object)
    original_attribute = MISPAttribute()
    original_attribute.from_dict(**attribute)
    original_attribute.comment = "custom comment"
    for tag in onion_details["tags"]:
        original_attribute.add_tag(tag)
    misp_event.attributes.append(original_attribute)
    misp_object.add_reference(attribute["uuid"], "expanded-from")
    return misp_event


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    # Input sanity check
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]

    # Make sure the Attribute's type is one of the expected type
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    # Use PyMISP to create compatible MISP Format
    misp_event = MISPEvent()
    enrichOnion(misp_event, attribute)

    # Convert to the format understood by MISP
    results = {}
    event = misp_event.to_dict()
    for key in ("Attribute", "Object", "EventReport"):
        if key in event:
            results[key] = event[key]
    return {"results": results}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
