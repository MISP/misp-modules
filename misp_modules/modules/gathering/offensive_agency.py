"""Gather Offensive Agency statistics or observations from its host export or an asset inventory."""

import base64
import json
from importlib import resources

import requests
from pymisp import MISPObject

from misp_modules.lib.gathering import CONTRACT_VERSION, NAMESPACE, canonical_json, get_jobs, origin_tags, stable_uuid
from misp_modules.lib.offensive_agency import SOURCE, add, day, fetch, host_ip, host_objects

MODULE = "offensive_agency"
SOURCE_NAMESPACE = stable_uuid(NAMESPACE, "offensive.agency")
STATISTICS_NAME = "offensive-agency-statistics"
STATISTICS_TEMPLATE = json.loads(
    resources.files("misp_modules")
    .joinpath("data", "offensive-agency", STATISTICS_NAME, "definition.json")
    .read_text(encoding="utf-8")
)
moduleinfo = {
    "name": "Offensive Agency",
    "version": "1.2",
    "author": "MISP Project",
    "module-type": ["gathering"],
    "description": "Gather Offensive Agency exposure statistics, inventory matches or the full historical host export.",
    "requirements": ["requests", "PyMISP"],
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
                "IP addresses in your inventory to look up with Offensive Agency. Empty collects statistics unless"
                " all_hosts is enabled."
            ),
        },
        "all_hosts": {
            "type": "boolean",
            "default": False,
            "description": "Collect the complete historical hosts export. Use with an empty asset_ips list.",
        },
    },
}


def parameters(params):
    if not isinstance(params, dict) or set(params) - PARAMETERS["properties"].keys():
        raise ValueError("Unknown Offensive Agency parameters")
    values = params.get("asset_ips", [])
    if not isinstance(values, list):
        raise ValueError("asset_ips must be a list of IPv4 or IPv6 addresses")
    all_hosts = params.get("all_hosts", False)
    if not isinstance(all_hosts, bool):
        raise ValueError("all_hosts must be a boolean")
    if all_hosts and values:
        raise ValueError("all_hosts requires an empty asset_ips list")
    return all_hosts, sorted({host_ip(ip) for ip in values})


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
    obj = MISPObject(STATISTICS_NAME, strict=True, misp_objects_template_custom=STATISTICS_TEMPLATE)
    obj.uuid = stable_uuid(event["uuid"], "statistics")
    add(obj, "report-date", observed.isoformat())
    add(obj, "source-url", SOURCE + "stats")
    for key, relation in (
        ("total", "tracked-ips"),
        ("active", "active-ips"),
        ("new", "new-ips"),
        ("multi", "multi-agent-ips"),
        ("with_c2", "cohosted-c2-ips"),
    ):
        count = record[key]
        if type(count) is not int or count < 0:
            raise ValueError(f"Invalid Offensive Agency count for {key}")
        add(obj, relation, count)
    add(
        obj,
        "source-record",
        f"offensive-agency-stats-{date}.json",
        data=base64.b64encode(canonical_statistics(record).encode()).decode(),
    )
    event["Object"] = [json.loads(obj.to_json())]
    return event, int(observed.timestamp())


def host_observation(ip, record, kind="asset"):
    last = day(record["last_seen"])
    event = event_for(kind, ip, f"Offensive Agency observation for {ip}", last)
    objects = host_objects(ip, record, event["uuid"])
    event["Object"] = [json.loads(obj.to_json(strict=True)) for obj in objects]
    return event, int(last.timestamp())


def gather(params, builder, config=None):
    all_hosts, ips = parameters(params)
    with requests.Session() as session:
        session.headers["User-Agent"] = "MISP-modules/offensive-agency-gathering"
        if all_hosts:
            rows = fetch(session, "hosts.json?scope=all", builder.check_cancel, export=True)
            for row in rows:
                builder.check_cancel()
                if not isinstance(row, dict) or "ip" not in row:
                    raise ValueError("Invalid Offensive Agency host export row")
                builder.add(*host_observation(host_ip(row["ip"]), row, kind="host-export"))
            return
        if not ips:
            builder.add(*statistics(fetch(session, "stats.json", builder.check_cancel)))
            return
        for ip in ips:
            record = fetch(session, "host/" + ip, builder.check_cancel, allow_missing=True)
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
        parameters(params)
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
