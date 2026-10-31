import json
import re
from ipaddress import ip_address, ip_network

import requests
from pymisp import MISPEvent, MISPObject

mispattributes = {"input": ["ip-src", "ip-dst", "AS"], "format": "misp_standard"}
moduleconfig = ["sourceapp"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "RIPEstat",
    "description": "Query RIPEstat for the announcing ASNs, prefixes and ASN holders of IP, prefix and AS attributes.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Uses the public network-info, prefix-overview and as-overview endpoints without an API key. Supports IPv4,"
        " IPv6 and multiple origin ASNs. Returns linked asn objects with contextual attributes (to_ids=false)."
        " The optional sourceapp identifies regular API usage; defaults to misp-modules."
        " See the usage guide in documentation/expansion/ripestat.md."
    ),
    "references": ["https://stat.ripe.net/docs/data-api/ripestat-data-api"],
    "input": "An ip-src or ip-dst address/CIDR prefix, or an AS attribute (AS3333 or 3333).",
    "output": (
        "ASN objects with holder descriptions and the observed announcing prefix, linked to the source attribute."
    ),
}

API_URL = "https://stat.ripe.net/data"
TIMEOUT = 30


class ModuleError(ValueError):
    """A request or API error that can be returned to the caller."""


def _asn(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ModuleError("Invalid AS number.")
    number = str(value).strip().upper()
    if number.startswith("AS"):
        number = number[2:]
    if not re.fullmatch(r"[0-9]+", number) or not 0 <= int(number) <= 4294967295:
        raise ModuleError("Invalid AS number.")
    return f"AS{int(number)}"


def _get(endpoint, resource, sourceapp):
    try:
        response = requests.get(
            f"{API_URL}/{endpoint}/data.json",
            params={"resource": resource, "sourceapp": sourceapp},
            headers={"Accept": "application/json"},
            timeout=TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException:
        raise ModuleError(f"RIPEstat {endpoint} request failed or timed out.") from None
    if response.status_code != 200:
        raise ModuleError(f"RIPEstat {endpoint} returned HTTP {response.status_code}.")
    try:
        payload = response.json()
    except ValueError:
        raise ModuleError(f"RIPEstat {endpoint} returned invalid JSON.") from None
    if not isinstance(payload, dict):
        raise ModuleError(f"RIPEstat {endpoint} returned an invalid response.")
    if payload.get("status") != "ok":
        raise ModuleError(f"RIPEstat {endpoint} reported an error or is under maintenance.")
    if not isinstance(payload.get("data"), dict):
        raise ModuleError(f"RIPEstat {endpoint} returned invalid data.")
    return payload["data"]


def _overview(number, sourceapp):
    data = _get("as-overview", number, sourceapp)
    if _asn(data.get("resource")) != number:
        raise ModuleError("RIPEstat returned an unexpected AS number.")
    return data


def _add_asn(event, attribute, number, data, prefix=None):
    holder = data.get("holder")
    if holder is not None and not isinstance(holder, str):
        raise ModuleError("RIPEstat returned an invalid ASN holder.")
    obj = MISPObject("asn")
    obj.comment = "RIPEstat"
    if "announced" in data:
        if not isinstance(data["announced"], bool):
            raise ModuleError("RIPEstat returned an invalid announcement status.")
        obj.comment += f"; announced: {str(data['announced']).lower()}"
    obj.add_attribute("asn", value=number, to_ids=False)
    if holder:
        obj.add_attribute("description", value=holder, to_ids=False)
    if prefix:
        obj.add_attribute("subnet-announced", value=prefix, to_ids=False)
    obj.add_reference(attribute["uuid"], "related-to")
    event.add_object(obj)


def _expand(event, attribute, sourceapp):
    value = attribute["value"].strip()
    if attribute["type"] == "AS":
        number = _asn(value)
        _add_asn(event, attribute, number, _overview(number, sourceapp))
        return

    if "/" in value:
        network = ip_network(value, strict=False)
        data = _get("prefix-overview", str(network), sourceapp)
        prefix = ip_network(data["resource"], strict=False)
        # prefix-overview may describe a less specific containing prefix.
        if network.version != prefix.version or not network.subnet_of(prefix):
            raise ModuleError("RIPEstat returned an unexpected prefix.")
        origins = data.get("asns")
        if not isinstance(origins, list) or any(not isinstance(origin, dict) for origin in origins):
            raise ModuleError("RIPEstat returned invalid origin ASNs.")
        seen = set()
        for origin in origins:
            number = _asn(origin.get("asn"))
            if number not in seen:
                _add_asn(event, attribute, number, origin, str(prefix))
                seen.add(number)
    else:
        address = ip_address(value)
        data = _get("network-info", str(address), sourceapp)
        origins = data.get("asns")
        if not isinstance(origins, list):
            raise ModuleError("RIPEstat returned invalid origin ASNs.")
        prefix = data.get("prefix")
        if not prefix and not origins:
            return  # Unrouted addresses have no prefix or announcing ASNs.
        prefix = ip_network(prefix, strict=False)
        if address.version != prefix.version or address not in prefix:
            raise ModuleError("RIPEstat returned an unexpected prefix.")
        numbers = dict.fromkeys(_asn(origin) for origin in origins)
        for number in numbers:
            _add_asn(event, attribute, number, _overview(number, sourceapp), str(prefix))


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all(attribute.get(key) for key in ("type", "value", "uuid")):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Unsupported attribute type.")
        if not isinstance(attribute["value"], str) or not attribute["value"].strip():
            raise ModuleError("The attribute value must be a nonempty string.")
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        sourceapp = config.get("sourceapp") or "misp-modules"
        if not isinstance(sourceapp, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", sourceapp):
            raise ModuleError("sourceapp must contain only ASCII letters, digits, hyphens and underscores.")
        event = MISPEvent()
        event.add_attribute(**attribute)
        _expand(event, attribute, sourceapp)
        result = json.loads(event.to_json())
        return {"results": {key: result.get(key, []) for key in ("Attribute", "Object")}}
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError):
        return {"error": "Invalid request or RIPEstat response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
