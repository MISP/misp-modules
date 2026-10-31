import json
import logging
import sys

import geoip2.database
from maxminddb import InvalidDatabaseError
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

log = logging.getLogger("geoip_country")
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
log.addHandler(ch)

mispattributes = {
    "input": ["ip-src", "ip-dst", "domain|ip"],
    "format": "misp_standard",
}
moduleconfig = ["local_geoip_db", "local_geolite_db"]
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "0.4",
    "author": "Andreas Muehlemann",
    "description": "Query a local MaxMind GeoIP2 or GeoLite2 Country database (MMDB format)",
    "module-type": ["expansion", "hover"],
    "name": "GeoIP Country Lookup",
    "logo": "maxmind.png",
    "requirements": ["A local MaxMind GeoIP2 or GeoLite2 Country database (.mmdb)"],
    "features": (
        "This module takes an IP address MISP attribute as input and queries a local copy of the MaxMind GeoIP2 or"
        " GeoLite2 database to get information about the location of this IP address.\n\nPlease note that composite"
        " attributes domain|ip are also supported."
    ),
    "references": ["https://www.maxmind.com/en/home"],
    "input": "An IP address MISP Attribute.",
    "output": "A geolocation object holding the country the IP address is located in.",
}


def _add_if(misp_object, relation, value):
    if value is not None and value != "":
        misp_object.add_attribute(relation, value)


def _parse_country(answer):
    """Build a MISP geolocation object from a geoip2 Country response."""
    geolocation = MISPObject("geolocation")
    _add_if(geolocation, "countrycode", answer.country.iso_code)
    _add_if(geolocation, "country", answer.country.name)
    if answer.continent.name:
        geolocation.add_attribute("text", f"continent: {answer.continent.name}")
    return geolocation


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    config = request.get("config") or {}
    if not isinstance(config, dict):
        return {"error": "Invalid GeoIP configuration: expected an object."}
    path_to_geoip = config.get("local_geoip_db") or config.get("local_geolite_db")
    if not isinstance(path_to_geoip, str) or not path_to_geoip.strip():
        return {
            "error": "Please set local_geoip_db (or local_geolite_db) to the path of a local MaxMind MMDB database."
        }

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    if attribute["type"] == "domain|ip":
        parts = attribute["value"].split("|")
        if len(parts) != 2:
            return {"error": "Invalid domain|ip composite attribute."}
        toquery = parts[1]
    else:
        toquery = attribute["value"]

    try:
        reader = geoip2.database.Reader(path_to_geoip)
    except FileNotFoundError:
        return {"error": f"Unable to locate the GeoIP database you specified ({path_to_geoip})."}
    except (OSError, ValueError, InvalidDatabaseError) as e:
        return {"error": f"Unable to load the GeoIP database ({path_to_geoip}): {e}"}
    log.debug(toquery)
    try:
        answer = reader.country(toquery)
    except Exception as e:
        return {"error": f"GeoIP resolving error: {e}"}
    finally:
        reader.close()

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    geolocation = _parse_country(answer)
    geolocation.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(geolocation)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
