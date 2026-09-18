import json

from dns.name import LabelTooLong
from dns.resolver import NXDOMAIN, Resolver
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

resolver = Resolver()
resolver.timeout = 1
resolver.lifetime = 1


misperrors = {"error": "Error"}
mispattributes = {"input": ["btc"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.2",
    "author": "Christian Studer",
    "description": (
        "An expansion hover module to query a special dns blacklist to check if a bitcoin address has been abused."
    ),
    "module-type": ["hover"],
    "name": "BTC Scam Check",
    "logo": "bitcoin.png",
    "requirements": ["dnspython3: dns python library"],
    "features": (
        "The module queries a dns blacklist directly with the bitcoin address and get a response if the address has"
        " been abused."
    ),
    "references": ["https://btcblack.it/"],
    "input": "btc address attribute.",
    "output": "A reputation object when the BTC address is listed as a scam address.",
}
moduleconfig = []

url = "bl.btcblack.it"


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] != "btc":
        return {"error": "Wrong input attribute type."}
    btc = attribute["value"]

    query = f"{btc}.{url}"
    try:
        listing = " - ".join([str(r) for r in resolver.resolve(query, "TXT")])[1:-1]
    except NXDOMAIN:
        # A clean negative: the list says nothing about this address.
        return {"error": f"{btc} is not known as a scam address."}
    except LabelTooLong:
        return {"error": f"{btc} is probably not a valid BTC address."}

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    # Typed explicitly, since pymisp does not bundle the reputation template
    # yet. The list exists to assert exactly one thing, so being on it is a
    # malicious verdict.
    misp_object = MISPObject("reputation")
    misp_object.add_attribute("classification", **{"type": "text", "value": "malicious"})
    misp_object.add_attribute("source", **{"type": "text", "value": "btcblack.it"})
    misp_object.add_attribute("list-name", **{"type": "text", "value": url})
    if listing:
        misp_object.add_attribute("text", **{"type": "text", "value": listing})
    misp_object.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(misp_object)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
