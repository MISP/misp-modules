import ipaddress
import json

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject
from requests.exceptions import RequestException, Timeout

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.1",
    "author": "Vito Grecciani",
    "description": "Lamis Network IP Intelligence and Risk Scoring expansion module.",
    "module-type": ["expansion", "hover"],
    "name": "Lamis Network Lookup",
    "logo": "",
    "requirements": ["A Lamis Network API Key"],
    "features": (
        "Takes an IP address (ip-src, ip-dst) and queries the Lamis Network API to enrich it with "
        "ASN details, infrastructure type (datacenter/hosting), proxy indicators (VPN, Tor, Proxy), "
        "and a contextual risk score (0-100)."
    ),
    "references": [
        "https://lamisnetwork.com/community.html",
        "https://docs.lamisnetwork.com",
    ],
    "input": "IP address attribute (ip-src, ip-dst).",
    "output": "Enriched ASN, geolocation, proxy indicators, and risk score.",
}
moduleconfig = ["api_key", "risk_threshold", "timeout"]


def _parse_int(val, default, min_val=None, max_val=None):
    """Safely parse integer with fallback default, bool guarding, and boundary checks."""
    if isinstance(val, bool):
        return default
    try:
        if val is None or val == "":
            return default
        res = int(val)
        if min_val is not None and res < min_val:
            return default
        if max_val is not None and res > max_val:
            return default
        return res
    except (ValueError, TypeError, OverflowError):
        return default


def _parse_bool(val):
    """Safely parse boolean from various string or numeric representations."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes", "t")
    if isinstance(val, (int, float)):
        return bool(val)
    return False


def handler(q=False):
    """Handle the MISP query for an IP attribute."""
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (json.JSONDecodeError, TypeError) as e:
        return {"error": f"Malformed input query JSON: {e}"}

    if not isinstance(request, dict):
        return {"error": "Invalid request: expected a JSON object."}

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {
            "error": (
                f"{standard_error_message}, which should contain at least a type, "
                "a value and an uuid."
            )
        }
    attribute = request["attribute"]
    if attribute.get("type") not in mispattributes["input"]:
        return {"error": "Unsupported input attribute type."}

    ip_value = str(attribute.get("value", "")).strip()
    try:
        ipaddress.ip_address(ip_value)
    except ValueError:
        return {"error": f"Invalid IP address format: {ip_value}"}

    config = request.get("config")
    if not isinstance(config, dict) or not config.get("api_key"):
        return {"error": "Missing Lamis Network API key in configuration."}

    api_key = str(config["api_key"]).strip()
    if not api_key:
        return {"error": "Missing Lamis Network API key in configuration."}

    timeout = _parse_int(config.get("timeout"), default=10, min_val=1, max_val=60)
    risk_threshold = _parse_int(
        config.get("risk_threshold"), default=75, min_val=0, max_val=100
    )

    api_url = f"https://api.lamisnetwork.com/v1/ip/{ip_value}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "User-Agent": "MISP-Module-LamisNetwork/0.1",
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=timeout)
        if response.status_code == 401:
            return {"error": "Authentication failed: invalid Lamis Network API key."}
        if response.status_code == 429:
            return {
                "error": "Rate limit or monthly quota exceeded for Lamis Network API key."
            }
        response.raise_for_status()
        data = response.json()
    except Timeout:
        return {
            "error": f"Connection timed out while querying Lamis Network for {ip_value}."
        }
    except (json.JSONDecodeError, ValueError) as e:
        return {"error": f"Invalid JSON response from Lamis Network API: {e}"}
    except RequestException as e:
        return {"error": f"Error querying Lamis Network API: {e}"}

    if not isinstance(data, dict):
        return {"error": "Invalid API response structure: expected a JSON object."}

    # Initialize MISP data structures
    misp_event = MISPEvent()
    input_attr = MISPAttribute()
    input_attr.from_dict(**attribute)
    target_attr = misp_event.add_attribute(**input_attr)

    # 1. ASN Object
    asn_data = data.get("asn")
    if isinstance(asn_data, dict):
        has_asn = False
        asn_obj = MISPObject("asn")
        asn_obj.add_reference(input_attr.uuid, "includes")
        if asn_data.get("asn"):
            asn_obj.add_attribute("asn", str(asn_data["asn"]))
            has_asn = True
        if asn_data.get("name"):
            asn_obj.add_attribute("description", str(asn_data["name"]))
            has_asn = True
        if has_asn:
            misp_event.add_object(asn_obj)
    elif isinstance(asn_data, str) and asn_data.strip():
        asn_obj = MISPObject("asn")
        asn_obj.add_reference(input_attr.uuid, "includes")
        asn_obj.add_attribute("asn", asn_data.strip())
        misp_event.add_object(asn_obj)

    # 2. Geolocation Object
    geo_data = data.get("geo") or data.get("location")
    if isinstance(geo_data, dict):
        has_geo = False
        geo_obj = MISPObject("geolocation")
        geo_obj.add_reference(input_attr.uuid, "locates")
        if geo_data.get("country_code"):
            geo_obj.add_attribute("countrycode", str(geo_data["country_code"]))
            has_geo = True
        if geo_data.get("country"):
            geo_obj.add_attribute("country", str(geo_data["country"]))
            has_geo = True
        if geo_data.get("city"):
            geo_obj.add_attribute("city", str(geo_data["city"]))
            has_geo = True
        if has_geo:
            misp_event.add_object(geo_obj)

    # 3. Risk & Proxy Indicators
    raw_score = data.get("fraud_score")
    fraud_score = None
    if raw_score is not None and not isinstance(raw_score, bool):
        try:
            parsed_score = int(raw_score)
            if 0 <= parsed_score <= 100:
                fraud_score = parsed_score
        except (ValueError, TypeError, OverflowError):
            fraud_score = None

    is_vpn = _parse_bool(data.get("is_vpn"))
    is_tor = _parse_bool(data.get("is_tor"))
    is_proxy = _parse_bool(data.get("is_proxy"))
    is_datacenter = _parse_bool(data.get("is_datacenter"))

    summary_parts = []
    if is_tor:
        summary_parts.append("Tor Exit Node")
        target_attr.add_tag('network:tor="exit-node"')
    if is_vpn:
        summary_parts.append("VPN")
        target_attr.add_tag('network:vpn="active"')
    if is_proxy:
        summary_parts.append("Public Proxy")
    if is_datacenter:
        summary_parts.append("Datacenter/Hosting")

    if fraud_score is not None:
        score_comment = f"Lamis Risk Score: {fraud_score}/100"
        if fraud_score >= risk_threshold:
            target_attr.add_tag('ioc:artifact-state="suspicious"')
    else:
        score_comment = "Lamis Risk Score: N/A"

    if summary_parts:
        score_comment += f" ({', '.join(summary_parts)})"

    misp_event.add_attribute("comment", score_comment)

    event_dict = json.loads(misp_event.to_json())
    return {
        "results": {
            "Attribute": event_dict.get("Attribute", []),
            "Object": event_dict.get("Object", []),
        }
    }


def introspection():
    """Return MISP input specification."""
    return mispattributes


def version():
    """Return module info and configuration parameters."""
    moduleinfo["config"] = moduleconfig
    return moduleinfo
