import json

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "version": 1,
    "author": "Christian Studer",
    "description": "An expansion module to query ipinfo.io to gather more information on a given IP address.",
    "module-type": ["expansion", "hover"],
    "name": "IPInfo.io Lookup",
    "logo": "ipinfo.png",
    "requirements": ["An ipinfo.io token"],
    "features": (
        "The module takes an IP address attribute as input and queries the ipinfo.io API.  \nThe geolocation"
        " information on the IP address is always returned.\n\nDepending on the subscription plan, the API returns"
        " different pieces of information then:\n- With a basic plan (free) you get the AS number and the AS"
        " organisation name concatenated in the `org` field.\n- With a paid subscription, the AS information is"
        " returned in the `asn` field with additional AS information, and depending on which plan the user has, you can"
        " also get information on the privacy method used to protect the IP address, the related domains, or the point"
        " of contact related to the IP address in case of an abuse.\n\nMore information on the responses content is"
        " available in the [documentation](https://ipinfo.io/developers)."
    ),
    "references": ["https://ipinfo.io/developers"],
    "input": "IP address attribute.",
    "output": (
        "Additional information on the IP address, like its geolocation, the autonomous system it is included in, and"
        " the related domain(s)."
    ),
}
moduleconfig = ["token"]

_GEOLOCATION_OBJECT_MAPPING = {
    "city": "city",
    "postal": "zipcode",
    "region": "region",
    "country": "countrycode",
}


def handler(q=False):
    # Input checks
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute.get("type") not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    if not request.get("config"):
        return {"error": "Missing ipinfo config."}
    if not request["config"].get("token"):
        return {"error": "Missing ipinfo token."}

    # Query ipinfo.io
    query = requests.get(f"https://ipinfo.io/{attribute['value']}/json?token={request['config']['token']}")
    if query.status_code != 200:
        return {"error": f"Error while querying ipinfo.io - {query.status_code}: {query.reason}"}
    ipinfo = query.json()

    # Check if the IP address is not reserved for special use
    if ipinfo.get("bogon", False):
        return {"error": "The IP address is reserved for special use"}

    # Initiate the MISP data structures
    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    # Parse the geolocation information related to the IP address
    geolocation = MISPObject("geolocation")
    for field, relation in _GEOLOCATION_OBJECT_MAPPING.items():
        geolocation.add_attribute(relation, ipinfo[field])
    for relation, value in zip(("latitude", "longitude"), ipinfo["loc"].split(",")):
        geolocation.add_attribute(relation, value)
    geolocation.add_reference(input_attribute.uuid, "locates")
    misp_event.add_object(geolocation)

    # Parse the domain information
    domain_ip = misp_event.add_object(name="domain-ip")
    for feature in ("hostname", "ip"):
        domain_ip.add_attribute(feature, ipinfo[feature])
    domain_ip.add_reference(input_attribute.uuid, "resolves")
    if ipinfo.get("domain") is not None:
        for domain in ipinfo["domain"]["domains"]:
            domain_ip.add_attribute("domain", domain)

    # Parse the AS information
    asn = MISPObject("asn")
    asn.add_reference(input_attribute.uuid, "includes")
    if ipinfo.get("asn") is not None:
        asn_info = ipinfo["asn"]
        asn.add_attribute("asn", asn_info["asn"])
        asn.add_attribute("description", asn_info["name"])
        misp_event.add_object(asn)
    elif ipinfo.get("org"):
        as_value, *description = ipinfo["org"].split(" ")
        asn.add_attribute("asn", as_value)
        asn.add_attribute("description", " ".join(description))
        misp_event.add_object(asn)

    # Return the results in MISP format
    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object")}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
