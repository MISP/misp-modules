import json
import re
from ipaddress import ip_address
from urllib.parse import quote, urlsplit

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "hostname", "ip-src", "ip-dst", "url"], "format": "misp_standard"}
moduleconfig = ["apikey"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Silent Push Enrichment",
    "description": "Retrieve domain and IP risk and infrastructure context from Silent Push.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Uses the documented enrich endpoint with x-api-key authentication. URL inputs query only the hostname. IPv4"
        " and IPv6 use their respective endpoints. Risk scores and flags remain in a referenced annotation; AS numbers,"
        " reverse DNS and nameservers become pivotable attributes. Does not submit or scan URLs."
    ),
    "references": ["https://help.silentpush.com/docs/get-enrichment-data"],
    "input": "domain, hostname, ip-src, ip-dst, url MISP attribute.",
    "output": "A context annotation and related ASN and hostname attributes.",
}
TIMEOUT = 30


class ModuleError(ValueError):
    """An actionable module error safe to return to the caller."""


def _get(url, **kwargs):
    try:
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=False, **kwargs)
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


def _domain(value):
    if not isinstance(value, str):
        raise ModuleError("Invalid domain or hostname.")
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all((re.fullmatch("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in value.split("."))):
        raise ModuleError("Invalid domain or hostname.")
    return value


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
    value = attribute["value"].strip()
    kind = attribute["type"]
    if kind == "url":
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ModuleError("A URL must contain an HTTP(S) hostname.")
        value = parsed.hostname
    if kind in ("ip-src", "ip-dst"):
        address = ip_address(value)
        api_type, value = (f"ipv{address.version}", str(address))
    else:
        try:
            address = ip_address(value)
            api_type, value = (f"ipv{address.version}", str(address))
        except ValueError:
            api_type, value = ("domain", _domain(value))
    data = _get(
        f"https://api.silentpush.com/api/v1/merge-api/explore/enrich/{api_type}/{quote(value, safe='')}",
        headers={"x-api-key": config["apikey"]},
    )
    if data is None or data == {}:
        return _results(event)
    if not isinstance(data, dict) or data.get("error") or data.get("errors") or data.get("status") == "error":
        raise ModuleError("Silent Push returned an unexpected response or rejected the lookup.")
    data = data.get("response", data)
    if not isinstance(data, dict):
        raise ModuleError("Silent Push returned an invalid response envelope.")
    if api_type != "domain":
        rows = data.get("ip2asn")
        if not isinstance(rows, list):
            raise ModuleError("Silent Push returned an unexpected IP response.")
        if not rows:
            return _results(event)
        context = rows[0]
    else:
        context = data
    if not isinstance(context, dict):
        raise ModuleError("Silent Push returned an unexpected enrichment record.")
    _annotation(event, attribute, "Silent Push intelligence", context)
    records = context.get("ip2asn", []) if api_type == "domain" else rows
    if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
        raise ModuleError("Silent Push returned invalid resolved-address records.")
    seen = set()
    for record in [context, *records]:
        if record.get("asn") is not None:
            number = str(record["asn"]).removeprefix("AS")
            if number.isdigit() and ("AS", number) not in seen:
                seen.add(("AS", number))
                event.add_attribute("AS", "AS" + number, to_ids=False, comment="Silent Push")
        ptr = record.get("ip_ptr")
        if isinstance(ptr, str) and ptr and ("hostname", ptr) not in seen:
            seen.add(("hostname", ptr))
            event.add_attribute("hostname", ptr, to_ids=False, comment="Silent Push PTR")
    reputation = context.get("ns_reputation") or {}
    if not isinstance(reputation, dict):
        raise ModuleError("Silent Push returned invalid nameserver context.")
    for row in reputation.get("ns_srv_reputation", []) or []:
        if isinstance(row, dict) and isinstance(row.get("ns_server"), str) and row["ns_server"]:
            event.add_attribute("hostname", row["ns_server"], to_ids=False, comment="Silent Push nameserver")
    return _results(event)
