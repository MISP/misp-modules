import ipaddress
import json

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "version": 2,
    "author": "Christian Studer",
    "description": "An expansion module to query IPinfo for geolocation, ASN and contextual IP intelligence.",
    "module-type": ["expansion", "hover"],
    "name": "IPInfo.io Lookup",
    "logo": "ipinfo.png",
    "requirements": ["An IPinfo token for the selected API"],
    "features": (
        "IP address data powered by [IPinfo](https://ipinfo.io). The module accepts an IP address attribute and"
        " returns geolocation, ASN and related domain information when available.\n\n"
        "Set `api` to `lite` for the unlimited free country/continent and basic ASN API, or `lookup` for the paid"
        " Core/Plus API with city-level geolocation and network intelligence. `legacy` (the default when unset)"
        " preserves existing configurations using ipinfo.io. Tokens must match the selected API subscription."
        " Lite does not include city, coordinates, postal code, hostname or timezone.\n\n"
        "Privacy/anonymous flags, abuse contacts, company, carrier and other contextual fields returned by the"
        " selected plan are preserved in a JSON annotation referencing the input attribute. Explicit false flags"
        " are retained; absent fields do not imply a clean address. Hosted domains included in the response are"
        " added to the domain-ip object. No additional API endpoints are queried."
    ),
    "references": [
        "https://ipinfo.io/developers",
        "https://ipinfo.io/developers/lite-api",
        "https://ipinfo.io/developers/core-api",
        "https://ipinfo.io/developers/plus-api",
    ],
    "input": "IP address attribute (ip-src or ip-dst).",
    "output": "geolocation, asn and domain-ip objects, plus a referenced annotation for contextual IPinfo data.",
}
moduleconfig = ["token", "api"]

_API_URLS = {
    "legacy": "https://ipinfo.io/{ip}/json",
    "lite": "https://api.ipinfo.io/lite/{ip}",
    "lookup": "https://api.ipinfo.io/lookup/{ip}",
}
_GEOLOCATION_OBJECT_MAPPING = {
    "city": "city",
    "postal": "zipcode",
    "region": "region",
    "country": "countrycode",
}
_CONTEXT_FIELDS = (
    "privacy",
    "anonymous",
    "abuse",
    "company",
    "carrier",
    "mobile",
    "place",
    "is_anonymous",
    "is_anycast",
    "is_hosting",
    "is_mobile",
    "is_satellite",
    "is_place",
    "timezone",
    "continent",
    "continent_code",
    "as_domain",
)


def _add_attributes(misp_object, data, mapping):
    for field, relation in mapping.items():
        value = data.get(field)
        if value is not None and value != "":
            misp_object.add_attribute(relation, value, to_ids=False)


def _build_results(attribute, ip, data, api):
    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    geolocation = MISPObject("geolocation")
    geo = data.get("geo") or {}
    if api == "lookup":
        _add_attributes(
            geolocation,
            geo,
            {
                "city": "city",
                "postal_code": "zipcode",
                "region": "region",
                "country_code": "countrycode",
                "country": "country",
                "latitude": "latitude",
                "longitude": "longitude",
                "radius": "accuracy-radius",
            },
        )
    elif api == "lite":
        _add_attributes(geolocation, data, {"country_code": "countrycode", "country": "country"})
    else:
        _add_attributes(geolocation, data, _GEOLOCATION_OBJECT_MAPPING)
        loc = data.get("loc")
        if isinstance(loc, str) and len(coordinates := loc.split(",")) == 2:
            _add_attributes(
                geolocation,
                dict(zip(("latitude", "longitude"), coordinates)),
                {
                    "latitude": "latitude",
                    "longitude": "longitude",
                },
            )
    if geolocation.attributes:
        geolocation.add_reference(input_attribute.uuid, "locates")
        misp_event.add_object(geolocation)

    domain_ip = MISPObject("domain-ip")
    _add_attributes(domain_ip, data, {"hostname": "hostname"})
    domains = data.get("domains") or {}
    if isinstance(domains, dict):
        for domain in dict.fromkeys(domains.get("domains") or []):
            if domain:
                domain_ip.add_attribute("domain", domain, to_ids=False)
    if domain_ip.attributes:
        domain_ip.add_attribute("ip", ip, to_ids=False)
        domain_ip.add_reference(input_attribute.uuid, "resolves")
        misp_event.add_object(domain_ip)

    as_info = data.get("as") if api == "lookup" else data.get("asn")
    if isinstance(as_info, str):  # Lite uses a flat ASN string.
        as_info = {"asn": as_info, "name": data.get("as_name")}
    if not as_info and data.get("org"):
        number, _, description = data["org"].partition(" ")
        as_info = {"asn": number, "name": description}
    if isinstance(as_info, dict) and as_info.get("asn"):
        asn = MISPObject("asn")
        _add_attributes(asn, as_info, {"asn": "asn", "name": "description", "route": "subnet-announced"})
        asn.add_reference(input_attribute.uuid, "includes")
        misp_event.add_object(asn)

    # Retain provider context without inventing relations absent from the installed object templates.
    context = {key: data[key] for key in _CONTEXT_FIELDS if data.get(key) is not None}
    if isinstance(as_info, dict):
        extra_as = {key: as_info[key] for key in ("domain", "type", "last_changed") if key in as_info}
        if extra_as:
            context["as"] = extra_as
    extra_geo = {
        key: geo[key]
        for key in ("timezone", "continent", "continent_code", "region_code", "dma_code", "geoname_id", "last_changed")
        if key in geo
    }
    if extra_geo:
        context["geo"] = extra_geo
    if isinstance(domains, dict) and domains.get("total") is not None:
        context["hosted_domains_total"] = domains["total"]
    if context:
        annotation = MISPObject("annotation")
        annotation.add_attribute("type", "IPinfo context", to_ids=False, disable_correlation=True)
        annotation.add_attribute("format", "json", to_ids=False, disable_correlation=True)
        annotation.add_attribute(
            "text", json.dumps(context, indent=2, sort_keys=True), to_ids=False, disable_correlation=True
        )
        annotation.add_attribute("ref", "https://ipinfo.io", to_ids=False, disable_correlation=True)
        annotation.add_reference(input_attribute.uuid, "annotates")
        misp_event.add_object(annotation)

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
    if not request.get("config"):
        return {"error": "Missing ipinfo config."}
    token = (request["config"].get("token") or "").strip()
    if not token:
        return {"error": "Missing ipinfo token."}
    api = (request["config"].get("api") or "legacy").strip().lower()
    if api not in _API_URLS:
        return {"error": "Invalid ipinfo api: choose legacy, lite or lookup."}
    try:
        ip = str(ipaddress.ip_address(attribute["value"].strip()))
    except ValueError:
        return {"error": "The attribute value must be a valid IPv4 or IPv6 address."}

    try:
        response = requests.get(
            _API_URLS[api].format(ip=ip),
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=10,
        )
    except requests.RequestException:
        # Exception messages may contain request credentials; return a bounded message instead.
        return {"error": "Could not reach the IPinfo API."}
    if response.status_code != 200:
        return {"error": f"Error while querying ipinfo.io - HTTP {response.status_code}."}
    try:
        data = response.json()
    except ValueError:
        return {"error": "The IPinfo API returned invalid JSON."}
    if not isinstance(data, dict):
        return {"error": "The IPinfo API returned an unexpected response."}
    if data.get("error"):
        return {"error": "The IPinfo API returned an error; check your token and selected API."}
    if data.get("bogon"):
        return {"error": "The IP address is reserved for special use"}
    return _build_results(attribute, ip, data, api)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
