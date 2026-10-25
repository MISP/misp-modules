import json
from ipaddress import ip_address

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleconfig = ["apikey"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "ShadowTrackr",
    "description": "Enrich IP addresses with ShadowTrackr false-positive and infrastructure context.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Posts JSON to /api/v3/ip_info for IPv4 or IPv6; the API key stays out of the URL. Existing attribute tags are"
        " sent as labels. Returns the false_positive_estimate, provider details and VPN/CDN/cloud/bogon/Tor/public-DNS"
        " flags in a referenced annotation. Scores are reported without changing MISP decay scores or IDS flags."
    ),
    "references": ["https://shadowtrackr.com/docs_v3/5-API"],
    "input": "ip-src, ip-dst MISP attribute.",
    "output": "A referenced annotation containing IP intelligence.",
}
TIMEOUT = 30


class ModuleError(ValueError):
    """An actionable module error safe to return to the caller."""


def _post(url, **kwargs):
    try:
        response = requests.post(url, timeout=TIMEOUT, allow_redirects=False, **kwargs)
    except requests.RequestException:
        raise ModuleError("The service request failed or timed out.") from None
    if response.status_code == 404:
        return None
    if response.status_code == 204:
        return None
    if response.status_code != 200:
        raise ModuleError(f"The service returned HTTP {response.status_code}.")
    try:
        return response.json()
    except ValueError:
        raise ModuleError("The service returned invalid JSON.") from None


def _ip(value):
    return str(ip_address(value))


def _annotation(event, attribute, title, data):
    obj = MISPObject("annotation")
    obj.comment = title
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True, indent=2), to_ids=False, disable_correlation=True)
    obj.add_reference(attribute["uuid"], "describes")
    event.add_object(obj)


def _results(event):
    data = json.loads(event.to_json())
    return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all((attribute.get(k) for k in ("type", "value", "uuid"))):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Unsupported attribute type.")
        if not isinstance(attribute["value"], str) or not attribute["value"].strip():
            raise ModuleError("The attribute value must be a nonempty string.")
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        for key in ["apikey"]:
            if not isinstance(config.get(key), str) or not config[key].strip():
                raise ModuleError(f"Missing {key} configuration.")
        event = MISPEvent()
        event.add_attribute(**attribute)
        return _expand(event, attribute, config)
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, OverflowError, OSError):
        return {"error": "Invalid request or service response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)


def _expand(event, attribute, config):
    address = _ip(attribute["value"].strip())
    labels = [tag["name"] for tag in attribute.get("Tag", []) if isinstance(tag, dict) and tag.get("name")]
    data = _post(
        "https://shadowtrackr.com/api/v3/ip_info",
        json={"api_key": config["apikey"], "ip": address, "labels": labels or ""},
    )
    if data is None or data == {}:
        return _results(event)
    if not isinstance(data, dict):
        raise ModuleError("ShadowTrackr returned an unexpected response.")
    if data.get("error"):
        raise ModuleError("ShadowTrackr rejected the lookup.")
    fields = (
        "false_positive_estimate",
        "vpn",
        "cdn",
        "cloud",
        "bogon",
        "tor",
        "public_dns",
        "cdn_provider",
        "cloud_provider",
    )
    context = {key: data[key] for key in fields if key in data}
    if context:
        _annotation(event, attribute, "ShadowTrackr IP context", context)
    return _results(event)
