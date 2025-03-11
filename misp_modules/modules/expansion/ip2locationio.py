import json

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "version": 1,
    "author": "IP2Location.io",
    "description": "An expansion module to query IP2Location.io to gather more information on a given IP address.",
    "module-type": ["expansion", "hover"],
    "name": "IP2Location.io Lookup",
    "logo": "ip2locationio.png",
    "requirements": ["An IP2Location.io token"],
    "features": (
        "The module takes an IP address attribute as input and queries the IP2Location.io API.  \nFree plan user will"
        " get the basic geolocation informaiton, and different subsription plan will get more information on the IP"
        " address. \n Refer to [pricing page](https://www.ip2location.io/pricing) for more information on data"
        " available for each plan. \n\nMore information on the responses content is available in the"
        " [documentation](https://www.ip2location.io/ip2location-documentation)."
    ),
    "references": ["https://www.ip2location.io/ip2location-documentation"],
    "input": "IP address attribute.",
    "output": (
        "Additional information on the IP address, such as geolocation, proxy and so on. Refer to the Response Format"
        " section in https://www.ip2location.io/ip2location-documentation to find out the full format of the data"
        " returned."
    ),
}
moduleconfig = ["key"]

_GEOLOCATION_OBJECT_MAPPING = {
    "country_code": "countrycode",
    "country_name": "country",
    "region_name": "region",
    "city_name": "city",
    "zip_code": "zipcode",
    "latitude": "latitude",
    "longitude": "longitude",
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
        return {"error": "Missing ip2locationio config."}
    if not request["config"].get("key"):
        return {"error": "Missing ip2locationio API key."}

    # Query ip2location.io
    query = requests.get(f"https://api.ip2location.io/json?key={request['config']['key']}&ip={attribute['value']}")
    if query.status_code != 200:
        return {"error": f"Error while querying ip2location.io - {query.status_code}: {query.reason}"}
    iplio_result = query.json()

    # Check if the IP address is not reserved for special use
    # if ipinfo.get('bogon', False):
    if "" in iplio_result and iplio_result[""] == "RSV":
        return {"error": "The IP address is reserved for special use"}

    # Initiate the MISP data structures
    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    # Parse the geolocation information related to the IP address
    geolocation = MISPObject("geolocation")
    for field, relation in _GEOLOCATION_OBJECT_MAPPING.items():
        geolocation.add_attribute(relation, iplio_result[field])
    geolocation.add_reference(input_attribute.uuid, "locates")
    misp_event.add_object(geolocation)

    # Return the results in MISP format
    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object")}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
