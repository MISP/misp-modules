import json
from ipaddress import ip_address, ip_network
from urllib.parse import quote

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleconfig = ["user_agent"]
moduleinfo = {
    "version": "1",
    "author": "Alexandre Dulaunoy",
    "name": "DShield SANS ISC",
    "description": (
        "Look up IP reports, target counts, network ownership and threat-feed observations in DShield / SANS ISC."
    ),
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Queries the public ISC IP API without an API key. Set `user_agent` to identify your deployment and include a"
        " contact address, as requested by ISC. IPv4 and IPv6 are accepted; private and reserved addresses are"
        " rejected. Returns reported packet and unique target counts, first/last seen dates and per-feed observations"
        " as a referenced annotation, plus an ASN object and an abuse-contact email when available. Zero reports do not"
        " establish that an address is benign. HTTP 429 is returned as an error without automatic retries; wait at"
        " least five minutes and respect Retry-After before another lookup. All enrichment has to_ids disabled."
    ),
    "references": ["https://www.dshield.org/api/#ip"],
    "input": "ip-src, ip-dst MISP attribute.",
    "output": "A referenced annotation and ASN object, and an abuse-contact email attribute.",
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
    agent = config.get("user_agent") or "misp-modules-dshield/1 (https://www.misp-project.org/)"
    if not isinstance(agent, str) or not agent.strip():
        raise ModuleError("user_agent must be a nonempty string.")
    response = requests.get(
        "https://isc.sans.edu/api/ip/" + quote(address, safe="") + "?json",
        headers={"User-Agent": agent},
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    if response.status_code == 429:
        raise ModuleError("DShield returned HTTP 429. Wait at least five minutes and respect Retry-After.")
    data = _json(response, "DShield", missing=True)
    if data is None:
        _annotation(event, attribute, "DShield lookup", {"ip": address, "status": "No information available"})
        return _results(event)
    data = data.get("ip", data)
    if not isinstance(data, dict) or _ip(data.get("number")) != address:
        raise ModuleError("DShield returned an unexpected IP address or response.")
    summary = {"ip": address, "reference": "https://isc.sans.edu/ipinfo.html?ip=" + quote(address, safe="")}
    for field, label in (("count", "reported-packets"), ("attacks", "unique-targets")):
        value = data.get(field)
        if value not in (None, ""):
            if isinstance(value, bool) or not str(value).isdigit():
                raise ModuleError("DShield returned an invalid report count.")
            summary[label] = int(value)
    for field in ("mindate", "maxdate", "updated", "comment", "maxrisk"):
        if data.get(field) not in (None, ""):
            summary[field] = data[field]
    feeds = data.get("threatfeeds")
    if feeds not in (None, "", []):
        if not isinstance(feeds, dict):
            raise ModuleError("DShield returned invalid threat-feed observations.")
        summary["threatfeeds"] = feeds
    _annotation(event, attribute, "DShield / SANS ISC IP observations", summary)
    number = data.get("as")
    if number not in (None, "", 0, "0"):
        if isinstance(number, bool) or not str(number).isdigit():
            raise ModuleError("DShield returned an invalid ASN.")
        obj = MISPObject("asn")
        obj.add_attribute("asn", value=f"AS{number}", to_ids=False)
        for key, relation in (("asname", "name"), ("ascountry", "country")):
            if isinstance(data.get(key), str) and data[key]:
                obj.add_attribute(relation, value=data[key], to_ids=False)
        if data.get("network"):
            network = ip_network(data["network"], strict=False)
            if ip_address(address) not in network:
                raise ModuleError("DShield returned a network that does not contain the queried IP.")
            obj.add_attribute("subnet-announced", value=str(network), to_ids=False)
        obj.add_reference(attribute["uuid"], "includes")
        event.add_object(obj)
    contact = data.get("asabusecontact")
    if isinstance(contact, str) and "@" in contact:
        event.add_attribute("email", contact, to_ids=False, comment="DShield ASN abuse contact for " + address)
    return _results(event)
