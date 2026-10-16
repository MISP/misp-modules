import json
import logging
import sys

import geoip2.database
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

log = logging.getLogger("geoip_asn")
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
    "description": "Query a local copy of the Maxmind Geolite ASN database (MMDB format)",
    "module-type": ["expansion", "hover"],
    "name": "GeoIP ASN Lookup",
    "logo": "maxmind.png",
    "requirements": ["A local copy of Maxmind's Geolite database"],
    "features": (
        "The module takes an IP address attribute as input and queries a local copy of the Maxmind's Geolite database"
        " to get information about the related AS number."
    ),
    "references": ["https://www.maxmind.com/en/home"],
    "input": "An IP address MISP attribute.",
    "output": "An asn object describing the AS the IP address is announced by.",
    "descrption": (
        "An expansion module to query a local copy of Maxmind's Geolite database with an IP address, in order to get"
        " information about its related AS number."
    ),
}


def _add_if(misp_object, relation, value, attribute_type=None):
    if value is None or value == "":
        return
    if attribute_type is None:
        misp_object.add_attribute(relation, value)
    else:
        misp_object.add_attribute(relation, **{"type": attribute_type, "value": value})


def _parse_asn(answer):
    """Build a MISP asn object from a geoip2 ASN response."""
    asn = MISPObject("asn")
    if answer.autonomous_system_number is not None:
        asn.add_attribute("asn", f"AS{answer.autonomous_system_number}")
    _add_if(asn, "organization", answer.autonomous_system_organization)
    _add_if(asn, "subnet-announced", str(answer.network) if answer.network else None)
    return asn


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if not request.get("config") or not request["config"].get("local_geolite_db"):
        return {"error": "Please specify the path of your local copy of the Maxmind Geolite ASN database"}
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
        answer = reader.asn(toquery)
    except Exception as e:
        misperrors["error"] = f"GeoIP resolving error: {e}"
        return misperrors

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    asn = _parse_asn(answer)
    asn.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(asn)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
