import json
from ipaddress import ip_address

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleconfig = ["user_id", "api_key", "vpn_lookup"]
moduleinfo = {
    "version": "1",
    "author": "Alexandre Dulaunoy",
    "name": "NeutrinoAPI IP Blocklist",
    "description": (
        "Enrich public IP addresses with NeutrinoAPI blocklist categories, detection flags, timestamps and sensor"
        " context."
    ),
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests", "NeutrinoAPI user ID and API key"],
    "features": (
        "Requires `user_id` and `api_key`, sent in HTTP headers to the IP Blocklist API. Set `vpn_lookup` to true to"
        " include public VPN providers (default false). Returns a referenced annotation with the listing status,"
        " categories, flags, first/last seen times, counts and sensor details. Missing flags remain unknown; is-vpn is"
        " only included when VPN lookup was requested. An unlisted address is not declared benign. All enrichment has"
        " to_ids disabled. Supports public IPv4 and IPv6 addresses."
    ),
    "references": ["https://www.neutrinoapi.com/api/ip-blocklist/"],
    "input": "ip-src, ip-dst MISP attribute.",
    "output": "A referenced annotation containing IP blocklist intelligence.",
}
TIMEOUT = 30


class ModuleError(ValueError):
    """An error safe to display without request URLs, credentials or remote error bodies."""


def _request(q):
    request = json.loads(q)
    if not isinstance(request, dict):
        raise ModuleError("The request must be a JSON object.")
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not all(attribute.get(k) for k in ("type", "value", "uuid")):
        raise ModuleError("An attribute containing type, value and uuid is required.")
    if attribute["type"] not in mispattributes["input"]:
        raise ModuleError("Unsupported attribute type.")
    if not isinstance(attribute["value"], str) or not attribute["value"].strip():
        raise ModuleError("The attribute value must be a nonempty string.")
    config = request.get("config", {})
    if not isinstance(config, dict):
        raise ModuleError("The config must be a JSON object.")
    event = MISPEvent()
    event.add_attribute(**attribute)
    return event, attribute, config


def _annotation(event, attribute, title, data):
    obj = MISPObject("annotation")
    obj.comment = title
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True, indent=2), to_ids=False, disable_correlation=True)
    obj.add_reference(attribute["uuid"], "describes")
    event.add_object(obj)


def _results(event):
    data = json.loads(event.to_json())
    return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}


def _json(response, service, missing=False):
    if missing and response.status_code in (204, 404):
        return None
    if response.status_code != 200:
        suffix = " Retry later and respect the service's Retry-After header." if response.status_code == 429 else ""
        raise ModuleError(f"{service} returned HTTP {response.status_code}.{suffix}")
    try:
        data = response.json()
    except ValueError:
        raise ModuleError(f"{service} returned invalid JSON.") from None
    if not isinstance(data, dict):
        raise ModuleError(f"{service} returned an unexpected response.")
    if data.get("error") or data.get("errors"):
        raise ModuleError(f"{service} reported an API error.")
    return data


def handler(q=False):
    if q is False:
        return False
    try:
        event, attribute, config = _request(q)
        return _expand(event, attribute, config)
    except ModuleError as exc:
        return {"error": str(exc)}
    except requests.RequestException:
        return {"error": "The service request failed or timed out."}
    except (ValueError, TypeError, KeyError, OverflowError):
        return {"error": "Invalid request or service response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)


def _ip(value):
    if not isinstance(value, str) or "%" in value:
        raise ModuleError("A public IPv4 or IPv6 address is required.")
    address = ip_address(value.strip())
    if (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or getattr(address, "ipv4_mapped", None) is not None
    ):
        raise ModuleError("Only public unicast IP addresses without IPv4 mapping can be looked up.")
    return str(address)


def _expand(event, attribute, config):
    address = _ip(attribute["value"])
    for key in ("user_id", "api_key"):
        if not isinstance(config.get(key), str) or not config[key].strip():
            raise ModuleError(f"NeutrinoAPI {key} is required.")
    vpn = config.get("vpn_lookup", False)
    if isinstance(vpn, str) and vpn.lower() in ("true", "false", "1", "0", ""):
        vpn = vpn.lower() in ("true", "1")
    if not isinstance(vpn, bool):
        raise ModuleError("vpn_lookup must be true or false.")
    response = requests.post(
        "https://neutrinoapi.net/ip-blocklist",
        headers={"User-ID": config["user_id"].strip(), "API-Key": config["api_key"].strip()},
        data={"ip": address, "vpn-lookup": str(vpn).lower()},
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    data = _json(response, "NeutrinoAPI")
    if "api-error" in data:
        raise ModuleError("NeutrinoAPI reported an API error; check credentials, quota and input.")
    if _ip(data.get("ip")) != address or not isinstance(data.get("is-listed"), bool):
        raise ModuleError("NeutrinoAPI returned an unexpected IP address or listing status.")
    summary = {"ip": address, "vpn-lookup": vpn, "is-listed": data["is-listed"]}
    for key in (
        "is-proxy",
        "is-tor",
        "is-malware",
        "is-spyware",
        "is-dshield",
        "is-hijacked",
        "is-spider",
        "is-bot",
        "is-spam-bot",
        "is-exploit-bot",
    ) + (("is-vpn",) if vpn else ()):
        if key in data:
            if not isinstance(data[key], bool):
                raise ModuleError("NeutrinoAPI returned an invalid detection flag.")
            summary[key] = data[key]
    for key in ("first-seen", "last-seen", "total-hits", "list-count"):
        if key in data:
            if isinstance(data[key], bool) or not isinstance(data[key], int) or data[key] < 0:
                raise ModuleError("NeutrinoAPI returned an invalid count or timestamp.")
            summary[key] = data[key]
    for key in ("first-seen-date", "last-seen-date", "cidr"):
        if data.get(key):
            if not isinstance(data[key], str):
                raise ModuleError("NeutrinoAPI returned an invalid response field.")
            summary[key] = data[key]
    for key, member in (("blocklists", str), ("sensors", dict)):
        if key in data:
            if not isinstance(data[key], list) or not all(isinstance(item, member) for item in data[key]):
                raise ModuleError("NeutrinoAPI returned invalid blocklist or sensor data.")
            summary[key] = data[key]
    _annotation(event, attribute, "NeutrinoAPI IP Blocklist observations", summary)
    return _results(event)
