import ipaddress
import json
import math
from uuid import UUID

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["ip-src", "ip-dst", "domain|ip"], "format": "misp_standard"}
moduleconfig = ["api_key"]
moduleinfo = {
    "version": 1,
    "author": "MISP Project",
    "description": "An expansion and hover module to geolocate an IP address with geoPlugin.",
    "module-type": ["expansion", "hover"],
    "name": "geoPlugin Lookup",
    "requirements": ["A geoPlugin API key", "requests"],
    "features": (
        "Queries the geoPlugin HTTPS API using the configured `api_key`. Returns available country, region, city,"
        " postal code, coordinates and accuracy radius in a geolocation object linked to the source attribute."
        " Continent and timezone are included as text. Empty fields are omitted. Only public IPv4 addresses are"
        " queried, following the API's documented address support. The IP component of domain|ip is used without"
        " resolving the domain. See documentation/expansion/geoplugin.md for configuration and an example request."
    ),
    "references": ["https://www.geoplugin.com/docs", "https://github.com/MISP/misp-modules/issues/438"],
    "input": "A public IPv4 address in an ip-src, ip-dst or domain|ip attribute.",
    "output": "A geolocation object referencing the original attribute. New attributes have to_ids=false.",
}

API_URL = "https://api.geoplugin.com/"
TIMEOUT = (5, 30)

_TEXT_MAPPING = {
    "geoplugin_countryName": "country",
    "geoplugin_countryCode": "countrycode",
    "geoplugin_regionName": "region",
    "geoplugin_city": "city",
    "geoplugin_postal_code": "zipcode",
}
_NUMBER_MAPPING = {
    "geoplugin_latitude": ("latitude", -90, 90),
    "geoplugin_longitude": ("longitude", -180, 180),
    "geoplugin_locationAccuracyRadius": ("accuracy-radius", 0, math.inf),
}


def _text(value):
    if isinstance(value, str) and value.strip() and value.strip().lower() != "null":
        return value.strip()
    return None


def _geolocation(data):
    geolocation = MISPObject("geolocation")
    for field, relation in _TEXT_MAPPING.items():
        value = _text(data.get(field))
        if relation == "region" and value is None:
            value = _text(data.get("geoplugin_region"))
        if value is not None:
            geolocation.add_attribute(relation, value, to_ids=False)
    for field, (relation, minimum, maximum) in _NUMBER_MAPPING.items():
        value = data.get(field)
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            continue
        try:
            number = float(value)
        except (ValueError, OverflowError):
            continue
        if math.isfinite(number) and minimum <= number <= maximum:
            geolocation.add_attribute(relation, number, to_ids=False)
    # Require an actual location before attaching auxiliary text fields.
    if not any(
        a.object_relation in ("country", "countrycode", "region", "city", "latitude", "longitude")
        for a in geolocation.attributes
    ):
        return None
    for field, label in (("geoplugin_continentName", "continent"), ("geoplugin_timezone", "timezone")):
        value = _text(data.get(field))
        if value is not None:
            geolocation.add_attribute("text", f"{label}: {value}", to_ids=False)
    credit = _text(data.get("geoplugin_credit"))
    geolocation.comment = f"Source: geoPlugin. {credit}" if credit else "Source: geoPlugin."
    return geolocation


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "Invalid request: expected a JSON object."}
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    value = attribute["value"]
    if not isinstance(value, str):
        return {"error": "Invalid IP address."}
    if attribute["type"] == "domain|ip":
        parts = value.split("|")
        if len(parts) != 2 or not parts[0].strip():
            return {"error": "Invalid domain|ip value."}
        value = parts[1]
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return {"error": "Invalid IP address."}
    if address.version != 4:
        return {"error": "The geoPlugin API supports IPv4 addresses only."}
    if not address.is_global or address.is_multicast:
        return {"error": "Only public IPv4 addresses can be geolocated."}
    config = request.get("config")
    api_key = _text(config.get("api_key")) if isinstance(config, dict) else None
    if api_key is None:
        return {"error": "Please configure a geoPlugin api_key."}
    if not isinstance(attribute["uuid"], str):
        return {"error": "Invalid MISP input attribute UUID."}
    try:
        UUID(attribute["uuid"])
    except ValueError:
        return {"error": "Invalid MISP input attribute UUID."}
    try:
        input_attribute = MISPAttribute()
        input_attribute.from_dict(**attribute)
    except (PyMISPError, TypeError, ValueError):
        return {"error": "Invalid MISP input attribute."}

    try:
        response = requests.get(
            API_URL,
            params={"ip": str(address), "auth": api_key},
            headers={"Accept": "application/json", "User-Agent": "misp-modules-geoplugin/1"},
            timeout=TIMEOUT,
            allow_redirects=False,
        )
    except requests.Timeout:
        return {"error": "The geoPlugin request timed out."}
    except requests.RequestException:
        # Exceptions may contain the request URL, including the API key.
        return {"error": "Unable to contact the geoPlugin API."}
    if response.status_code not in (200, 206):
        return {"error": f"geoPlugin HTTP error {response.status_code}."}
    try:
        data = response.json()
    except ValueError:
        return {"error": "The geoPlugin API returned invalid JSON."}
    if not isinstance(data, dict):
        return {"error": "The geoPlugin API returned an invalid response."}
    status = data.get("geoplugin_status")
    if str(status) not in ("200", "206"):
        return {"error": "The geoPlugin lookup failed or returned no location."}
    try:
        returned_address = ipaddress.ip_address(data.get("geoplugin_request"))
    except ValueError:
        returned_address = None
    if returned_address != address:
        return {"error": "The geoPlugin response does not match the queried IP address."}

    geolocation = _geolocation(data)
    if geolocation is None:
        return {"error": "No geolocation data found for this IP address."}
    geolocation.add_reference(input_attribute.uuid, "related-to")
    event = MISPEvent()
    event.add_attribute(**input_attribute)
    event.add_object(geolocation)
    result = json.loads(event.to_json())
    return {"results": {key: result[key] for key in ("Attribute", "Object")}}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
