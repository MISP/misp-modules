import base64
import json
import re
from ipaddress import ip_address

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["ip-src", "ip-dst", "domain", "hostname", "x509-fingerprint-sha1"],
    "format": "misp_standard",
}
moduleconfig = ["api_key", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "Alexandre Dulaunoy",
    "name": "ZoomEye",
    "description": "Search ZoomEye API v2 for IP addresses, domains, hostnames and SHA-1 certificate fingerprints.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests", "ZoomEye API key"],
    "features": (
        "Requires `api_key`. Builds an escaped, Base64-encoded search query for API v2 and requests one page of up to"
        " `max_results` assets (default 20, maximum 100). Uses the v4/v6 dataset for IPs, web for domains, and all"
        " datasets for hostnames and certificate fingerprints. Leading/trailing API key whitespace is removed."
        " A result-limit notice is included when total exceeds the returned"
        " records; additional pages are not fetched automatically. Returns referenced ip-port objects with"
        " service/banner context, and an annotation retaining result counts and observed metadata. Certificate searches"
        " identify assets using an observed certificate, not a malicious verdict. All enrichment has to_ids disabled."
    ),
    "references": ["https://github.com/zoomeye-ai/ZoomEye-python/blob/master/api.md"],
    "input": "ip-src, ip-dst, domain, hostname, x509-fingerprint-sha1 MISP attribute.",
    "output": "Referenced ip-port objects and an annotation with result count and search coverage.",
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


FIELDS = "ip,port,domain,hostname,service,protocol,banner,product,version,os,update_time,asn,organization.name,ssl"


def _search(attribute):
    kind, value = attribute["type"], attribute["value"].strip()
    if kind in ("ip-src", "ip-dst"):
        address = _ip(value)
        return f'ip="{address}"', "v6" if ip_address(address).version == 6 else "v4"
    if kind in ("domain", "hostname"):
        # Validate before interpolation so quotes/operators cannot broaden the search.
        host = _domain(value, require_dot=kind == "domain")
        return f'{"domain" if kind == "domain" else "hostname"}="{host}"', "web" if kind == "domain" else "all"
    size = 40
    fingerprint = value.replace(":", "").lower()
    if not re.fullmatch(r"[a-f0-9]{" + str(size) + r"}", fingerprint):
        raise ModuleError("Invalid certificate fingerprint.")
    return f'ssl.cert.fingerprint="{fingerprint}"', "all"


def _expand(event, attribute, config):
    query, dataset = _search(attribute)
    if not isinstance(config.get("api_key"), str) or not config["api_key"].strip():
        raise ModuleError("ZoomEye api_key is required.")
    limit = config.get("max_results", 20)
    if limit == "":
        limit = 20
    if isinstance(limit, bool) or not str(limit).isdigit() or not 1 <= int(limit) <= 100:
        raise ModuleError("max_results must be an integer between 1 and 100.")
    limit = int(limit)
    response = requests.post(
        "https://api.zoomeye.ai/v2/search",
        headers={"API-KEY": config["api_key"].strip()},
        json={
            "qbase64": base64.b64encode(query.encode()).decode(),
            "page": 1,
            "pagesize": limit,
            "sub_type": dataset,
            "fields": FIELDS,
        },
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    data = _json(response, "ZoomEye")
    if data.get("code") != 60000:
        raise ModuleError("ZoomEye reported an API error; check credentials, quota and search permissions.")
    records, total = data.get("data"), data.get("total")
    if not isinstance(records, list) or isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise ModuleError("ZoomEye returned invalid search results.")
    if not all(isinstance(record, dict) for record in records):
        raise ModuleError("ZoomEye returned an invalid asset.")
    selected = records[:limit]
    summary = {
        "query": query,
        "dataset": dataset,
        "total": total,
        "returned": len(selected),
        "truncated": total > len(selected) or len(records) > limit,
    }
    if summary["truncated"]:
        summary["notice"] = "Results are limited to the first page; this is not a complete asset inventory."
    if not selected:
        summary["status"] = "No assets returned"
    for record in selected:
        obj = MISPObject("ip-port")
        obj.comment = "ZoomEye observed service"
        address = record.get("ip")
        if address:
            obj.add_attribute("ip", value=str(ip_address(address)), to_ids=False)
        for field, relation in (("domain", "domain"), ("hostname", "hostname")):
            name = record.get(field)
            if name:
                obj.add_attribute(relation, value=_domain(name, require_dot=field == "domain"), to_ids=False)
        if not obj.attributes:
            raise ModuleError("ZoomEye returned an asset without an IP address or hostname.")
        port = record.get("port")
        if port is not None:
            if isinstance(port, bool) or not isinstance(port, int) or not 0 < port <= 65535:
                raise ModuleError("ZoomEye returned an invalid port.")
            obj.add_attribute("dst-port", value=port, to_ids=False)
        protocol = record.get("protocol")
        if protocol is not None and protocol != "":
            if not isinstance(protocol, str):
                raise ModuleError("ZoomEye returned an invalid protocol.")
            obj.add_attribute("protocol", value=protocol.lower(), to_ids=False)
        context = {
            field: record[field]
            for field in FIELDS.split(",")
            if field not in ("ip", "port", "domain", "hostname", "protocol") and field in record
        }
        if context:
            obj.add_attribute("text", value=json.dumps(context, sort_keys=True), to_ids=False, disable_correlation=True)
        obj.add_reference(attribute["uuid"], "describes")
        event.add_object(obj)
    _annotation(event, attribute, "ZoomEye search coverage", summary)
    return _results(event)
