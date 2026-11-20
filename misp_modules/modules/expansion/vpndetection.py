import ipaddress
import json

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "version": 1,
    "author": "VPNDetection",
    "description": (
        "An expansion and hover module to check an IP address for VPN, privacy relay, Tor, hosting, CDN and proxy"
        " use with VPNDetection, with its country and ASN. No API key is needed."
    ),
    "module-type": ["expansion", "hover"],
    "name": "VPNDetection Lookup",
    "logo": "vpndetection.png",
    "requirements": [
        "A VPNDetection API key (optional: without one the API answers the VPN, relay and Tor flags, the country and"
        " the ASN)"
    ],
    "features": (
        "The module takes an IP address attribute as input and looks it up with the [VPNDetection"
        " API](https://vpndetection.io/api). It returns a geolocation object, an asn object, and a vpndetection-ip"
        " object with the detection flags that are set, each with its provider where one is known, its confidence and"
        " the date the address was last seen as such.\n\nThe `api_key` is optional. Without one the API answers whether"
        " the address is a VPN, a privacy relay or a Tor exit, the relay's provider, the country and the ASN. With a"
        " key it also answers the hosting, CDN and residential, datacenter, mobile and public proxy flags, the VPN and"
        " hosting providers, the anycast, mobile carrier and satellite flags, whether the address runs an SSH, SMTP or"
        " web server, an open DNS resolver or BitTorrent, its region, city, postal code and coordinates, its reverse"
        " DNS hostname, the organization it is registered to and its abuse contact. The key is sent in the"
        " Authorization header. Private and reserved addresses are not looked up. Terms: https://vpndetection.io/terms,"
        " privacy: https://vpndetection.io/privacy."
    ),
    "references": ["https://vpndetection.io/api", "https://docs.vpndetection.io"],
    "input": "An IP address attribute (ip-src or ip-dst).",
    "output": (
        "A geolocation object with the country (with a key, down to the city), an asn object, and a vpndetection-ip"
        " object with the flags that are set and the provider, confidence and last-seen date behind each detection,"
        " and with a key the hostname, organization and abuse contact."
    ),
}
moduleconfig = ["api_key"]

API_URL = "https://api.vpndetection.io/"
TIMEOUT = 10
USER_AGENT = "misp-modules-vpndetection/1"

# The vpndetection-ip template (MISP/misp-objects), described here for PyMISP releases that do not ship it yet:
# MISP refuses to create an object without its meta-category and template UUID.
VPNDETECTION_TEMPLATE = {
    "uuid": "823b8e68-8b81-489e-a7d7-1f008ebf745f",
    "version": 1,
    "meta-category": "network",
    "description": (
        "IP address intelligence from VPNDetection: VPN, privacy relay, Tor, hosting, CDN and residential,"
        " datacenter, mobile and public proxy detection, each with the provider where one is known, a confidence"
        " and the date the address was last seen as such; anycast, mobile carrier, satellite and the services it"
        " runs; its reverse DNS hostname, the organization it is registered to and its abuse contact."
    ),
}
KEYED_DETECTIONS = ("hosting", "cdn", "resproxy", "dcproxy", "mobproxy", "pubproxy")
DETECTIONS = ("vpn", "relay", "tor") + KEYED_DETECTIONS
SERVICES = ("anycast", "carrier", "satellite", "ssh", "smtp", "web", "dns_resolver", "bittorrent")
# Without a key, once a free key's daily trial is spent, or past the organization's overage cap, these flags are
# left out or null: that must not read as a clean address.
KEYED_FLAGS = KEYED_DETECTIONS + SERVICES
PARTIAL_COMMENT = (
    "Partial VPNDetection answer (no API key, a free key's daily trial is spent, or the organization's overage cap"
    " is reached): the hosting, CDN, proxy and service flags, the city, the hostname, the organization and the"
    " abuse contact are not included"
)


class VPNDetectionError(Exception):
    """A lookup failed with a message that can be shown to the MISP user."""


def lookup(ip, api_key):
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"  # never in the URL, where it would end up in logs
    try:
        response = requests.get(API_URL + ip, headers=headers, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise VPNDetectionError(f"Could not reach the VPNDetection API: {e}")
    try:
        data = response.json()
    except ValueError:
        data = None
    if response.status_code != 200:
        message = data.get("error") if isinstance(data, dict) else None
        raise VPNDetectionError(f"VPNDetection API error {response.status_code}: {message or response.reason}")
    if not isinstance(data, dict):
        raise VPNDetectionError("The VPNDetection API returned a response that is not a JSON object.")
    return data


def _text(value):
    return value if isinstance(value, (str, int, float)) and not isinstance(value, bool) and value != "" else None


def _dict(data, key):
    return data.get(key) if isinstance(data.get(key), dict) else {}


def _details(data):
    """The vpndetection-ip attributes the answer holds: who the address belongs to, then each flag that is set."""
    details = []
    company, abuse = _dict(data, "company"), _dict(data, "abuse")
    for value, relation, attribute_type in (
        (data.get("hostname"), "hostname", "hostname"),
        (company.get("name"), "company-name", "text"),
        (company.get("domain"), "company-domain", "domain"),
        (company.get("type"), "company-type", "text"),
        (abuse.get("email"), "abuse-email", "email"),
        (abuse.get("name"), "abuse-name", "text"),
    ):
        if (value := _text(value)) is not None:
            details.append((relation, value, attribute_type))
    for flag in DETECTIONS:
        if data.get(f"is_{flag}") is not True:
            continue
        details.append((f"is-{flag}", 1, "boolean"))
        detail = _dict(data, flag)
        provider = _text(detail.get("provider_name")) or _text(detail.get("provider"))
        if provider is not None and flag != "tor":
            details.append((f"{flag}-provider", provider, "text"))
        if (confidence := _text(detail.get("confidence"))) is not None:
            details.append((f"{flag}-confidence", confidence, "text"))
        if (last_seen := _text(detail.get("last_seen"))) is not None:
            details.append((f"{flag}-last-seen", last_seen, "datetime"))
    for flag in SERVICES:
        if data.get(f"is_{flag}") is True:
            details.append((f"is-{flag.replace('_', '-')}", 1, "boolean"))
    if data.get("is_carrier") is True and (name := _text(_dict(data, "carrier").get("name"))) is not None:
        details.append(("carrier-name", name, "text"))
    satellite = _dict(data, "satellite")
    if data.get("is_satellite") is True:
        if (provider := _text(satellite.get("provider_name")) or _text(satellite.get("provider"))) is not None:
            details.append(("satellite-provider", provider, "text"))
    return details


def build_results(attribute, ip, data):
    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    location = _dict(data, "location")
    geolocation = MISPObject("geolocation")
    for key, relation in (
        ("country", "countrycode"),
        ("country_name", "country"),
        ("region", "region"),
        ("city", "city"),
        ("postal_code", "zipcode"),
        ("latitude", "latitude"),
        ("longitude", "longitude"),
        ("accuracy_radius", "accuracy-radius"),
    ):
        if (value := _text(location.get(key))) is not None:
            geolocation.add_attribute(relation, value)
    if geolocation.attributes:
        geolocation.add_reference(input_attribute.uuid, "locates")
        misp_event.add_object(geolocation)

    network = _dict(data, "asn")
    if (number := _text(network.get("asn"))) is not None:
        asn = MISPObject("asn")
        asn.add_attribute("asn", f"AS{number}")
        for key, relation in (("name", "organization"), ("prefix", "subnet-announced"), ("country", "country")):
            if (value := _text(network.get(key))) is not None:
                asn.add_attribute(relation, value)
        asn.add_reference(input_attribute.uuid, "includes")
        misp_event.add_object(asn)

    details = _details(data)
    if details:
        intelligence = MISPObject("vpndetection-ip")
        if getattr(intelligence, "template_uuid", None) is None:
            intelligence.template_uuid = VPNDETECTION_TEMPLATE["uuid"]
            intelligence.template_version = VPNDETECTION_TEMPLATE["version"]
            intelligence.description = VPNDETECTION_TEMPLATE["description"]
            setattr(intelligence, "meta-category", VPNDETECTION_TEMPLATE["meta-category"])
        if any(data.get(f"is_{flag}") is None for flag in KEYED_FLAGS):
            intelligence.comment = PARTIAL_COMMENT
        intelligence.add_attribute("ip", str(ip), type="ip-src")
        # Hostnames, organizations, contacts, flags and providers are shared by many unrelated addresses: only the
        # IP correlates.
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
    except VPNDetectionError as e:
        return {"error": str(e)}
    if data.get("is_bogon"):
        return {"error": f"VPNDetection reports {ip} as a bogon: a private or reserved address."}
    return build_results(attribute, ip, data)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
