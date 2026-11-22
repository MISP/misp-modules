"""Gather Offensive Agency statistics or observations for a supplied asset inventory."""

import base64
import datetime as dt
import ipaddress
import json
from importlib import resources

import requests
from pymisp import MISPObject

from misp_modules.lib.gathering import CONTRACT_VERSION, NAMESPACE, canonical_json, get_jobs, origin_tags, stable_uuid

MODULE = "offensive_agency"
SOURCE = "https://offensive.agency/"
SOURCE_NAMESPACE = stable_uuid(NAMESPACE, "offensive.agency")
OBSERVATION_NAME = "offensive-agency-observation"
OBSERVATION_TEMPLATE = json.loads(
    resources.files("misp_modules")
    .joinpath("data", "offensive-agency", OBSERVATION_NAME, "definition.json")
    .read_text(encoding="utf-8")
)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
moduleinfo = {
    "name": "Offensive Agency",
    "version": "1.0",
    "author": "MISP Project",
    "module-type": ["gathering"],
    "description": "Gather Offensive Agency exposure statistics and observations for monitored IP addresses.",
    "requirements": ["requests"],
    "references": [SOURCE, SOURCE + "about"],
}
moduleconfig = []
PARAMETERS = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "asset_ips": {
            "type": "array",
            "items": {"type": "string"},
            "default": [],
            "description": (
                "IP addresses in your inventory to look up with Offensive Agency. Empty collects statistics."
            ),
        }
    },
}


def asset_ips(params):
    if not isinstance(params, dict) or set(params) - {"asset_ips"}:
        raise ValueError("Unknown Offensive Agency parameters")
    values = params.get("asset_ips", [])
    if not isinstance(values, list) or any(not isinstance(ip, str) or "%" in ip for ip in values):
        raise ValueError("asset_ips must be a list of IPv4 or IPv6 addresses")
    return sorted({str(ipaddress.ip_address(ip)) for ip in values})


def day(value):
    return dt.datetime.combine(dt.date.fromisoformat(value), dt.time.min, tzinfo=dt.timezone.utc)


def event_for(kind, key, info, observed):
    uuid = stable_uuid(SOURCE_NAMESPACE, kind, key)
    return {
        "uuid": uuid,
        "info": info,
        "date": observed.date().isoformat(),
        "distribution": "0",
        "analysis": "2",
        "threat_level_id": "4",
        "published": True,
        "Orgc": {"name": "Offensive Agency", "uuid": stable_uuid(SOURCE_NAMESPACE, "organisation")},
        "Tag": origin_tags(MODULE, "offensive.agency"),
        "Attribute": [],
    }


def add_attribute(event, key, attribute_type, value, **fields):
    event["Attribute"].append(
        {
            "uuid": stable_uuid(event["uuid"], key),
            "type": attribute_type,
            "value": value,
            "to_ids": False,
            "disable_correlation": True,
            **fields,
        }
    )


def canonical_statistics(record):
    # Ranked breakdowns can change tie order. The dates and corresponding time series are positional.
    def sort_breakdowns(row, fields):
        result = row.copy()
        for field in fields:
            if field in row:
                result[field] = sorted(row[field], key=lambda pair: (-pair[1], canonical_json(pair[0])))
        return result

    result = sort_breakdowns(record, ("c2", "countries", "orgs", "pairs"))
    if "tools" in record:
        result["tools"] = {
            name: sort_breakdowns(metrics, ("countries", "orgs", "ports")) for name, metrics in record["tools"].items()
        }
    return canonical_json(result)


def statistics(record):
    observed = day(record["ref_day"])
    date = observed.date().isoformat()
    event = event_for("statistics", date, f"Offensive Agency exposure statistics for {date}", observed)
    add_attribute(event, "source", "link", SOURCE + "stats")
    for key, label in (
        ("total", "IPs in tracker history"),
        ("active", "Active IPs"),
        ("new", "New IPs in the active window"),
        ("multi", "Active IPs with multiple agents"),
        ("with_c2", "Active IPs with a co-hosted C2"),
    ):
        count = record[key]
        if type(count) is not int or count < 0:
            raise ValueError(f"Invalid Offensive Agency count for {key}")
        add_attribute(event, key, "text", f"{label}: {count}")
    add_attribute(
        event,
        "statistics-json",
        "attachment",
        f"offensive-agency-stats-{date}.json",
        data=base64.b64encode(canonical_statistics(record).encode()).decode(),
        comment="Published aggregate statistics and daily time series, based on ONYPHE observations.",
    )
    return event, int(observed.timestamp())


def host_observation(ip, record):
    if str(ipaddress.ip_address(record["ip"])) != ip:
        raise ValueError("Offensive Agency returned a different asset IP")
    first, last = day(record["first_seen"]), day(record["last_seen"])
    if first > last:
        raise ValueError("Invalid Offensive Agency observation dates")
    event = event_for("asset", ip, f"Offensive Agency observation for {ip}", last)
    observation = MISPObject(
        OBSERVATION_NAME, strict=True, standalone=False, misp_objects_template_custom=OBSERVATION_TEMPLATE
    )
    observation.uuid = stable_uuid(event["uuid"], "observation")
    observation.first_seen = first
    observation.last_seen = last

    def add(relation, value, *, key=None, **fields):
        observation.add_attribute(
            relation, value=value, uuid=stable_uuid(observation.uuid, relation, key), to_ids=False, **fields
        )

    add("source-url", SOURCE + "host/" + ip)
    add(
        "ip",
        ip,
        disable_correlation=record.get("kind") not in ("hosting", "cloud"),
        first_seen=first,
        last_seen=last,
        comment="ONYPHE observation, day precision. Shared CDN addresses can serve unrelated domains.",
    )
    for field, relation in (("kind", "network-type"), ("country", "country"), ("org", "network-operator"), ("asn", "asn")):
        if record.get(field):
            add(relation, record[field])
    tools = record["tools"]
    if not isinstance(tools, dict):
        raise ValueError("Invalid Offensive Agency agent observations")
    for name, level in sorted(tools.items()):
        if not isinstance(name, str) or level not in ("confirmed", "probable"):
            raise ValueError("Invalid Offensive Agency agent observation")
        add(
            "framework",
            f"{name}: {level}",
            key=name,
            comment="Provider confidence in the software observation. Operator intent is unknown.",
        )
    add(
        "source-record",
        f"offensive-agency-host-{ip.replace(':', '_')}.json",
        data=base64.b64encode(canonical_json(record).encode()).decode(),
        comment="Complete per-host observation reported by Offensive Agency.",
    )
    event["Object"] = [json.loads(observation.to_json(strict=True))]
    return event, int(last.timestamp())


def fetch(session, path, builder, allow_missing=False):
    builder.check_cancel()
    with session.get(SOURCE + "api/" + path, stream=True, timeout=(5, 30), allow_redirects=False) as response:
        if allow_missing and response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ValueError(f"Offensive Agency returned HTTP {response.status_code}")
        body = bytearray()
        for chunk in response.iter_content(65536):
            builder.check_cancel()
            if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                raise ValueError("Offensive Agency response exceeds the size budget")
            body.extend(chunk)
    record = json.loads(body)
    if not isinstance(record, dict):
        raise ValueError("Expected an Offensive Agency JSON object")
    return record


def gather(params, builder, config=None):
    ips = asset_ips(params)
    with requests.Session() as session:
        session.headers["User-Agent"] = "MISP-modules/offensive-agency-gathering"
        if not ips:
            builder.add(*statistics(fetch(session, "stats.json", builder)))
            return
        for ip in ips:
            record = fetch(session, "host/" + ip, builder, allow_missing=True)
            if record is not None:
                builder.add(*host_observation(ip, record))


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or request.get("operation", "prepare") != "prepare":
            raise ValueError("Expected gathering operation prepare")
        params = request.get("parameters", {})
        asset_ips(params)
        config = request.get("config", {})
        if not isinstance(config, dict):
            raise ValueError("Config must be an object")
        return get_jobs().submit(MODULE, params, config, gather)
    except (ValueError, TypeError, OSError) as exc:
        return {"error": str(exc)}


def introspection():
    return {"input": [], "output": ["MISP feed"], "gathering_version": CONTRACT_VERSION, "parameters": PARAMETERS}


def version():
    return {**moduleinfo, "config": moduleconfig}
