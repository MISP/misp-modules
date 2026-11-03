import json
import re
from ipaddress import ip_address
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst", "domain", "hostname", "url"], "format": "misp_standard"}
moduleconfig = ["api_key"]
moduleinfo = {
    "version": "1",
    "author": "Alexandre Dulaunoy",
    "name": "Pulsedive",
    "description": "Look up IP, domain and URL risk, linked threats, feeds and DNS observations in Pulsedive.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests", "Optional Pulsedive API key"],
    "features": (
        "Uses the existing indicator lookup API only; never submits an indicator or starts an active scan. `api_key` is"
        " optional, with stricter service limits for unauthenticated requests. The API requires the key as a query"
        " parameter, so avoid logging request URLs. Returns a referenced annotation containing risk, retirement state,"
        " risk factors, timestamps, threats and feed provenance. DNS addresses become domain-ip objects. Other DNS"
        " names, IP reverse-DNS PTR names and observed redirects are pivotable attributes. A 404 returns a"
        " no-information annotation and does not"
        " imply that the indicator is benign. All enrichment has to_ids disabled."
    ),
    "references": [
        "https://docs.pulsedive.com/api/indicator/get-by-value",
        "https://docs.pulsedive.com/api/authentication",
    ],
    "input": "ip-src, ip-dst, domain, hostname, url MISP attribute.",
    "output": "A referenced annotation, domain-ip objects and related hostname/URL attributes.",
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


def _domain(value, require_dot=True):
    if not isinstance(value, str):
        raise ModuleError("A valid domain or hostname is required.")
    host = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if (
        len(host) > 253
        or (require_dot and "." not in host)
        or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split("."))
    ):
        raise ModuleError("A valid domain or hostname is required.")
    try:
        ip_address(host)
    except ValueError:
        return host
    raise ModuleError("A domain or hostname is required, not an IP address.")


def _indicator(kind, value):
    if not isinstance(value, str) or not value.strip():
        raise ModuleError("A nonempty indicator string is required.")
    if kind in ("ip-src", "ip-dst"):
        return _ip(value)
    if kind in ("domain", "hostname"):
        return _domain(value)
    parts = urlsplit(value.strip())
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ModuleError("A valid HTTP(S) URL without embedded credentials is required.")
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise ModuleError("The URL port is invalid.")
    try:
        ip_address(parts.hostname)
    except ValueError:
        _domain(parts.hostname)
    else:
        _ip(parts.hostname)
    return value.strip()


def _strings(value):
    # Pulsedive can return a scalar, a list or nested lists for historical properties.
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return list(dict.fromkeys(item for child in value for item in _strings(child)))
    raise ModuleError("Pulsedive returned an invalid property value.")


def _expand(event, attribute, config):
    value = _indicator(attribute["type"], attribute["value"])
    params = {"indicator": value}
    key = config.get("api_key")
    if key is not None:
        if not isinstance(key, str):
            raise ModuleError("api_key must be a string.")
        if key.strip():
            params["key"] = key.strip()
    response = requests.get(
        "https://pulsedive.com/api/indicator.php", params=params, timeout=TIMEOUT, allow_redirects=False
    )
    data = _json(response, "Pulsedive", missing=True)
    if data is None:
        _annotation(event, attribute, "Pulsedive lookup", {"indicator": value, "status": "No information available"})
        return _results(event)
    if _indicator(attribute["type"], data.get("indicator", "")) != value:
        raise ModuleError("Pulsedive returned an unexpected indicator.")
    expected = "ip" if attribute["type"] in ("ip-src", "ip-dst") else "url" if attribute["type"] == "url" else "domain"
    if data.get("type") != expected:
        raise ModuleError("Pulsedive returned an unexpected indicator type.")
    summary = {"indicator": value, "type": data["type"]}
    for field in (
        "iid",
        "risk",
        "risk_recommended",
        "manualrisk",
        "retired",
        "stamp_added",
        "stamp_updated",
        "stamp_seen",
        "stamp_probed",
        "stamp_retired",
    ):
        if data.get(field) is not None:
            summary[field] = data[field]
    for field in ("riskfactors", "threats", "feeds"):
        if field in data:
            if not isinstance(data[field], list) or not all(isinstance(item, dict) for item in data[field]):
                raise ModuleError("Pulsedive returned invalid threat or feed data.")
            summary[field] = data[field]
    _annotation(event, attribute, "Pulsedive indicator intelligence", summary)
    properties = data.get("properties") or {}
    if not isinstance(properties, dict):
        raise ModuleError("Pulsedive returned invalid properties.")
    dns = properties.get("dns") or {}
    if not isinstance(dns, dict):
        raise ModuleError("Pulsedive returned invalid DNS properties.")
    # DNS A/AAAA records belong to the queried domain, not to an IP or an arbitrary URL.
    if expected == "domain":
        addresses = list(dict.fromkeys(_strings(dns.get("a")) + _strings(dns.get("aaaa"))))
        if addresses:
            obj = MISPObject("domain-ip")
            obj.add_attribute("domain", value=value, to_ids=False)
            for address in addresses:
                obj.add_attribute("ip", value=str(ip_address(address)), to_ids=False)
            obj.add_reference(attribute["uuid"], "describes")
            event.add_object(obj)
    for field in (("mx", "ns", "ptr") if expected == "ip" else ("mx", "ns")):
        for name in _strings(dns.get(field)):
            event.add_attribute("hostname", _domain(name), to_ids=False, comment=f"Pulsedive DNS {field} for {value}")
    redirects = data.get("redirects") or {}
    if not isinstance(redirects, dict):
        raise ModuleError("Pulsedive returned invalid redirects.")
    seen = set()
    for direction in ("from", "to"):
        entries = redirects.get(direction) or []
        if not isinstance(entries, list):
            raise ModuleError("Pulsedive returned invalid redirects.")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ModuleError("Pulsedive returned an invalid redirect.")
            target = entry.get("indicator", "")
            if not isinstance(target, str) or not target:
                raise ModuleError("Pulsedive returned an invalid redirect indicator.")
            if "://" in target:
                kind = "url"
            else:
                try:
                    ip_address(target)
                    kind = "ip-dst"
                except ValueError:
                    kind = "domain"
            target = _indicator(kind, target)
            if (kind, target) not in seen:
                event.add_attribute(kind, target, to_ids=False, comment=f"Pulsedive redirect {direction} {value}")
                seen.add((kind, target))
    return _results(event)
