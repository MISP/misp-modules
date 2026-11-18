"""Gather BeaconBeagle records through the background MISP feed contract."""

import datetime as dt
import json

from misp_modules.lib.beaconbeagle import Client, convert, integer, path_key
from misp_modules.lib.gathering import get_jobs

moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "BeaconBeagle Gathering",
    "description": "Gather Cobalt Strike configurations, beacon hosts and C2 infrastructure into a MISP feed ZIP.",
    "module-type": ["gathering"],
    "timeout": 10,
    "requirements": ["requests", "PyMISP"],
    "features": (
        "Paginated collection with stable identities, complete source JSON and observation timestamps. See "
        "https://github.com/MISP/misp-modules/blob/main/documentation/gathering/beaconbeagle.md."
    ),
    "references": ["https://beaconbeagle.com/", "https://beaconbeagle.com/api/"],
}
moduleconfig = []
PARAMETERS = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "dataset": {"type": "string", "enum": ["all", "configs", "beacons", "c2"], "default": "all"},
        "date_from": {"type": "string", "format": "date", "description": "Inclusive last-observed UTC date."},
        "date_to": {"type": "string", "format": "date", "description": "Exclusive last-observed UTC date."},
        "page_size": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
        "max_events": {
            "type": "integer",
            "minimum": 0,
            "default": 0,
            "description": "Optional event budget; exceeding it fails the job. Zero means unlimited.",
        },
    },
}


def parameters(value):
    if not isinstance(value, dict) or set(value) - set(PARAMETERS["properties"]):
        raise ValueError("Unknown gathering parameters")
    dataset = value.get("dataset", "all")
    if dataset not in ("all", "configs", "beacons", "c2"):
        raise ValueError("Invalid dataset")
    start = dt.date.fromisoformat(value["date_from"]) if "date_from" in value else dt.date.min
    end = dt.date.fromisoformat(value["date_to"]) if "date_to" in value else dt.date.max
    if start >= end:
        raise ValueError("date_from must precede date_to")
    size = integer(value.get("page_size"), 100, 500)
    limit = value.get("max_events", 0)
    if type(limit) is not int or limit < 0:
        raise ValueError("max_events must be a non-negative integer")
    return dataset, start, end, size, limit


def gather(params, builder, config=None):
    dataset, start, end, size, limit = parameters(params)
    count, seen = 0, set()
    with Client(builder.check_cancel) as client:
        for kind in (("configs", "beacons", "c2") if dataset == "all" else (dataset,)):
            listing = "configs/latest" if kind == "configs" else kind
            for summary in client.pages(listing, page_size=size):
                builder.check_cancel()
                if not isinstance(summary, dict):
                    raise ValueError("Invalid BeaconBeagle listing record")
                key = summary.get({"configs": "hash", "beacons": "ip", "c2": "key"}[kind])
                if not isinstance(key, str) or not key:
                    raise ValueError("BeaconBeagle listing record has no identity")
                if (kind, key) in seen:
                    continue
                seen.add((kind, key))
                data = client.get(kind + "/" + path_key(key))
                event, observed = convert(kind, key, data)
                if not start <= dt.date.fromisoformat(event["date"]) < end:
                    continue
                count += 1
                if limit and count > limit:
                    raise ValueError("BeaconBeagle max_events exceeded; narrow the dataset or date range")
                builder.add(event, observed)


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
        return get_jobs().submit("beaconbeagle_gathering", params, config, gather)
    except (ValueError, TypeError, OSError) as exc:
        return {"error": str(exc)}


def introspection():
    return {"input": [], "output": ["MISP feed"], "gathering_version": 2, "parameters": PARAMETERS}


def version():
    return {**moduleinfo, "config": moduleconfig}
