import ipaddress
import json

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "version": 1,
    "author": "ipapi.is",
    "description": (
        "An expansion and hover module to enrich an IP address with geolocation, ASN, company and abuse contact data,"
        " and VPN (with the provider), proxy, Tor and datacenter detection from ipapi.is."
    ),
    "module-type": ["expansion", "hover"],
    "name": "ipapi.is Lookup",
    "logo": "ipapi_is.png",
    "requirements": [
        "An ipapi.is API key (optional: without one the API returns location and network owner only, 30 requests a day)"
    ],
    "features": (
        "The module takes an IP address attribute as input and looks it up with the"
        " [ipapi.is API](https://ipapi.is/developers.html). It returns a geolocation object, an asn object and an ipapi-is-ip"
        " object with the detection flags that are set (VPN, proxy, Tor, datacenter, abuser, crawler, mobile, satellite"
        " and anycast), the VPN provider, the hosting provider, the organisation the address is registered to with its"
        " abuser score, and the abuse contact.\n\nThe `api_key` is optional: a free ipapi.is account includes 1,000"
        " requests a day. Without a key the API answers 30 requests a day per IP address with the location and the"
        " network owner only, without detection flags. The key is sent in the body of a POST request, never in the"
        " URL. Private and reserved addresses are not looked up."
    ),
    "references": ["https://ipapi.is/developers.html"],
    "input": "An IP address attribute (ip-src or ip-dst).",
    "output": (
        "geolocation and asn objects, and an ipapi-is-ip object with the detection flags, the VPN and hosting"
        " providers, the company with its abuser score, and the abuse contact."
    ),
}
moduleconfig = ["api_key"]

API_URL = "https://api.ipapi.is/"
TIMEOUT = 10
USER_AGENT = "misp-modules-ipapi_is/1"

# The ipapi-is-ip template (MISP/misp-objects), described here for PyMISP releases that do not ship it yet:
# MISP refuses to create an object without its meta-category and template UUID.
IPAPI_IS_TEMPLATE = {
    "uuid": "2961a5dc-0c3c-4e68-8d65-1565c118c723",
    "version": 1,
    "meta-category": "network",
    "description": (
        "IP address intelligence from ipapi.is: VPN (with the provider), proxy, Tor, datacenter, abuser, crawler,"
        " mobile, satellite and anycast detection, the organisation the address is registered to with its abuser"
        " score, and the abuse contact."
    ),
}
# Without a key no flag is set, which must not read as a clean address.
KEYLESS_COMMENT = "ipapi.is lookup without an API key: detection flags are not included"

_GEOLOCATION_MAPPING = (
    ("location.country_code", "countrycode"),
    ("location.country", "country"),
    ("location.state", "region"),
    ("location.city", "city"),
    ("location.zip", "zipcode"),
    ("location.latitude", "latitude"),
    ("location.longitude", "longitude"),
)
_ASN_MAPPING = (
    ("asn.org", "organization"),
    ("asn.descr", "description"),
    ("asn.route", "subnet-announced"),
    ("asn.country", "country"),
)
_FLAGS = (
    "is_vpn",
    "is_proxy",
    "is_tor",
    "is_datacenter",
    "is_abuser",
    "is_crawler",
    "is_mobile",
    "is_satellite",
    "is_anycast",
)
# Types and correlation are given explicitly so the object is right even where the template is not installed yet.
_IPAPI_IS_MAPPING = (
    ("is_crawler", "crawler", "text"),
    ("vpn.service", "vpn-service", "text"),
    ("vpn.type", "vpn-type", "text"),
    ("vpn.last_seen_str", "vpn-last-seen", "datetime"),
    ("datacenter.datacenter", "datacenter", "text"),
    ("company.name", "company-name", "text"),
    ("company.type", "company-type", "text"),
    ("company.domain", "company-domain", "domain"),
    ("company.abuser_score", "company-abuser-score", "text"),
    ("asn.abuser_score", "asn-abuser-score", "text"),
    ("abuse.name", "abuse-name", "text"),
    ("abuse.email", "abuse-email", "email"),
    ("abuse.phone", "abuse-phone", "phone-number"),
    ("abuse.address", "abuse-address", "text"),
    ("rir", "rir", "text"),
)


class IpapiIsError(Exception):
    """A lookup failed with a message that can be shown to the MISP user."""


def _value(data, path):
    """Return the value at a dotted path of the response, or None when it is missing, empty or not a scalar."""
    for key in path.split("."):
        data = data.get(key) if isinstance(data, dict) else None
    return None if data == "" or isinstance(data, (bool, dict, list)) else data


def _add(misp_object, data, mapping):
    for path, relation in mapping:
        value = _value(data, path)
        if value is not None:
            misp_object.add_attribute(relation, value)


def _expand_keyless(data):
    """Rewrite the reduced response to a keyless lookup in the shape of the full one."""
    number, _, org = (data.get("asn") or "").partition(" ")  # "AS212238 Datacamp Limited"
    return {
        "company": {"name": data.get("company")},
        "asn": {"asn": number.removeprefix("AS"), "org": org},
        "location": {
            "country": data.get("country"),
            "state": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
        },
    }


def lookup(ip, api_key):
    body = {"q": ip}
    if api_key:
        body["key"] = api_key  # never in the URL, where it would end up in logs
    try:
        response = requests.post(API_URL, json=body, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise IpapiIsError(f"Could not reach the ipapi.is API: {e}")
    try:
        data = response.json()
    except ValueError:
        data = None
    message = data.get("error") if isinstance(data, dict) else None
    if message or response.status_code != 200:
        raise IpapiIsError(f"ipapi.is API error {response.status_code}: {message or response.reason}")
    if not isinstance(data, dict):
        raise IpapiIsError("The ipapi.is API returned a response that is not JSON.")
    return data


def build_results(attribute, ip, data):
    keyless = "location" not in data
    if keyless:
        data = _expand_keyless(data)
    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    geolocation = MISPObject("geolocation")
    _add(geolocation, data, _GEOLOCATION_MAPPING)
    if geolocation.attributes:
        geolocation.add_reference(input_attribute.uuid, "locates")
        misp_event.add_object(geolocation)

    number = _value(data, "asn.asn")
    if number is not None:
        asn = MISPObject("asn")
        asn.add_attribute("asn", f"AS{number}")
        _add(asn, data, _ASN_MAPPING)
        asn.add_reference(input_attribute.uuid, "includes")
        misp_event.add_object(asn)

    # Flags are tested for truthiness: is_crawler is false or the name of the crawler, and is_vpn can hold a truthy
    # value other than true.
    details = [(flag.replace("_", "-"), 1, "boolean") for flag in _FLAGS if data.get(flag)]
    details += [
        (relation, value, attribute_type)
        for path, relation, attribute_type in _IPAPI_IS_MAPPING
        if (value := _value(data, path)) is not None
    ]
    if details:
        intelligence = MISPObject("ipapi-is-ip")
        if getattr(intelligence, "template_uuid", None) is None:
            intelligence.template_uuid = IPAPI_IS_TEMPLATE["uuid"]
            intelligence.template_version = IPAPI_IS_TEMPLATE["version"]
            intelligence.description = IPAPI_IS_TEMPLATE["description"]
            setattr(intelligence, "meta-category", IPAPI_IS_TEMPLATE["meta-category"])
        if keyless:
            intelligence.comment = KEYLESS_COMMENT
        intelligence.add_attribute("ip", str(ip), type="ip-src")
        for relation, value, attribute_type in details:
            intelligence.add_attribute(relation, value, type=attribute_type, disable_correlation=True)
        intelligence.add_reference(input_attribute.uuid, "describes")
        misp_event.add_object(intelligence)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if event.get(key)}}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    attribute = request.get("attribute")
    if not attribute or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    try:
        ip = ipaddress.ip_address(attribute["value"].strip())
    except ValueError:
        return {"error": f"{attribute['value']} is not a valid IP address."}
    if not ip.is_global:
        return {"error": f"{ip} is a private or reserved address and cannot be looked up."}

    api_key = ((request.get("config") or {}).get("api_key") or "").strip()
    try:
        data = lookup(str(ip), api_key)
    except IpapiIsError as e:
        return {"error": str(e)}
    if data.get("is_bogon"):
        return {"error": f"ipapi.is reports {ip} as a bogon: a private or reserved address."}
    return build_results(attribute, ip, data)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
