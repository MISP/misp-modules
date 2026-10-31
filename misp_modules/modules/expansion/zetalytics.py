import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "hostname", "ip-src", "ip-dst"], "format": "misp_standard"}
moduleconfig = ["apikey", "max_results"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Zetalytics Passive DNS",
    "description": "Look up passive DNS records in Zetalytics.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests"],
    "features": (
        "Uses the Zonecruncher v2 domain2rrtypes or ip endpoint with token authentication. max_results defaults to 25"
        " (1-100). Returns DNS record objects for A, AAAA, CNAME, MX, NS, PTR and TXT, with first/last observation"
        " times when available. Duplicate records are suppressed and unsupported record types remain in annotations. No"
        " additional SDK is required."
    ),
    "references": ["https://zonecruncher.com/", "https://github.com/ZETAlytics/community/tree/master/zetalytics-api"],
    "input": "domain, hostname, ip-src, ip-dst MISP attribute.",
    "output": "Referenced DNS record objects with observation times.",
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


def _ip(value):
    return str(ip_address(value))


def _domain(value):
    if not isinstance(value, str):
        raise ModuleError("Invalid domain or hostname.")
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all((re.fullmatch("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in value.split("."))):
        raise ModuleError("Invalid domain or hostname.")
    return value


def _limit(config, key="max_results", default=25, maximum=100):
    raw = config.get(key)
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool) or not str(raw).isdigit() or (not 1 <= int(raw) <= maximum):
        raise ModuleError(f"{key} must be an integer between 1 and {maximum}.")
    return int(raw)


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


def _observation_time(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ModuleError("Zetalytics returned an invalid observation timestamp.")
    if (
        isinstance(value, (int, float))
        or isinstance(value, str)
        and re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", value.strip())
    ):
        return datetime.fromtimestamp(float(value), timezone.utc)
    if not isinstance(value, str):
        raise ModuleError("Zetalytics returned an invalid observation timestamp.")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _observation_times(row):
    result = []
    for keys in (("first_seen", "first_ts", "date"), ("last_seen", "last_ts")):
        value = next((row[key] for key in keys if row.get(key) is not None and row[key] != ""), None)
        result.append(_observation_time(value))
    return tuple(result)


def _expand(event, attribute, config):
    limit = _limit(config)
    params = {"token": config["apikey"], "size": limit, "tsfield": "all"}
    if attribute["type"] in ("ip-src", "ip-dst"):
        endpoint, params["q"] = ("ip", _ip(attribute["value"].strip()))
    else:
        endpoint, params["q"] = ("domain2rrtypes", _domain(attribute["value"].strip()))
        params.update(rrtypes="a,aaaa,cname,mx,ns,ptr,txt", toBaseDomain="false", noSubdomains="true")
    data = _get("https://zonecruncher.com/api/v2/" + endpoint, params=params)
    if data is None:
        return _results(event)
    if not isinstance(data, dict) or data.get("error") or (not isinstance(data.get("results"), list)):
        raise ModuleError("Zetalytics returned an unexpected response.")
    relations = {
        "a": "a-record",
        "aaaa": "aaaa-record",
        "cname": "cname-record",
        "mx": "mx-record",
        "ns": "ns-record",
        "ptr": "ptr-record",
        "txt": "txt-record",
    }
    seen = set()
    for row in data["results"][:limit]:
        if not isinstance(row, dict) or not isinstance(row.get("value"), str):
            raise ModuleError("Zetalytics returned an invalid DNS record.")
        domain = _domain(row.get("qname", ""))
        kind, value = (str(row.get("rrtype", "")).lower(), row["value"])
        if kind in ("a", "aaaa"):
            address = ip_address(value)
            if address.version != (4 if kind == "a" else 6):
                raise ModuleError("Zetalytics returned an invalid DNS address family.")
            value = str(address)
        elif kind == "mx":
            parts = value.split()
            if not parts:
                raise ModuleError("Zetalytics returned an empty MX record.")
            value = _domain(parts[-1])
        elif kind in ("cname", "ns", "ptr"):
            value = _domain(value)
        first_seen, last_seen = _observation_times(row)
        key = (domain, kind, value, first_seen, last_seen)
        if key in seen:
            continue
        seen.add(key)
        if kind not in relations:
            _annotation(event, attribute, "Zetalytics DNS record", row)
            continue
        obj = MISPObject("dns-record")
        obj.comment = "Zetalytics passive DNS"
        obj.add_attribute("queried-domain", value=domain, to_ids=False)
        obj.add_attribute(relations[kind], value=value, to_ids=False)
        for target, timestamp in (("first_seen", first_seen), ("last_seen", last_seen)):
            if timestamp is not None:
                setattr(obj, target, timestamp)
        obj.add_reference(attribute["uuid"], "related-to")
        event.add_object(obj)
    total = data.get("total", data.get("count", 0))
    if len(data["results"]) >= limit or (isinstance(total, int) and total > limit):
        _annotation(
            event, attribute, "Zetalytics result limit", {"limit": limit, "more_records_may_be_available": True}
        )
    return _results(event)
