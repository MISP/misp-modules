import json
import logging
import sys

import geoip2.database
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

log = logging.getLogger("geoip_city")
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["ip-src", "ip-dst", "domain|ip"],
    "format": "misp_standard",
}
moduleconfig = ["local_geolite_db"]
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "0.2",
    "author": "GlennHD",
    "description": (
        "An expansion module to query a local copy of Maxmind's Geolite database with an IP address, in order to get"
        " information about the city where it is located."
    ),
    "module-type": ["expansion", "hover"],
    "name": "GeoIP City Lookup",
    "logo": "maxmind.png",
    "requirements": ["A local copy of Maxmind's Geolite database"],
    "features": (
        "The module takes an IP address attribute as input and queries a local copy of the Maxmind's Geolite database"
        " to get information about the city where this IP address is located."
    ),
    "references": ["https://www.maxmind.com/en/home"],
    "input": "An IP address MISP attribute.",
    "output": "A geolocation object describing where the IP address is located.",
}


def _add_if(misp_object, relation, value):
    if value is not None and value != "":
        misp_object.add_attribute(relation, value)


def _parse_city(answer):
    """Build a MISP geolocation object from a geoip2 City response."""
    geolocation = MISPObject("geolocation")
    _add_if(geolocation, "country", answer.country.name)
    _add_if(geolocation, "countrycode", answer.country.iso_code)
    _add_if(geolocation, "region", answer.subdivisions.most_specific.name)
    _add_if(geolocation, "city", answer.city.name)
    _add_if(geolocation, "zipcode", answer.postal.code)
    _add_if(geolocation, "latitude", answer.location.latitude)
    _add_if(geolocation, "longitude", answer.location.longitude)
    _add_if(geolocation, "accuracy-radius", answer.location.accuracy_radius)
    # The geolocation template has no continent relation, and it is the one
    # field the old free-text answer carried that has nowhere else to go.
    if answer.continent.name:
        geolocation.add_attribute("text", f"continent: {answer.continent.name}")
    return geolocation


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if not request.get("config") or not request["config"].get("local_geolite_db"):
        return {"error": "Please specify the path of your local copy of Maxminds Geolite database"}
    path_to_geolite = request["config"]["local_geolite_db"]

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    toquery = attribute["value"].split("|")[1] if attribute["type"] == "domain|ip" else attribute["value"]

    try:
        reader = geoip2.database.Reader(path_to_geolite)
    except FileNotFoundError:
        return {"error": f"Unable to locate the GeoLite database you specified ({path_to_geolite})."}
    log.debug(toquery)
    try:
        answer = reader.city(toquery)
    except Exception as e:
        misperrors["error"] = f"GeoIP resolving error: {e}"
        return misperrors

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    geolocation = _parse_city(answer)
    geolocation.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(geolocation)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
