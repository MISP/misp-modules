"""Gather witha.name DDoSia configuration snapshots without contacting targets."""

import base64
import copy
import datetime as dt
import ipaddress
import json
import re
from collections import Counter
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import requests
from pymisp import MISPObject

from misp_modules.lib.gathering import NAMESPACE, canonical_json, get_jobs, stable_uuid

SOURCE = "https://witha.name/data/"
SOURCE_NAMESPACE = stable_uuid(NAMESPACE, "witha.name/data")
FILENAME = re.compile(r"^(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})_DDoSia-target-list-full\.json$")
MAX_SOURCE_BYTES = 8 * 1024 * 1024

moduleinfo = {
    "version": "0.2",
    "author": "MISP Project",
    "description": "Gather witha.name DDoSia configurations as a deterministic MISP feed.",
    "module-type": ["gathering"],
    "name": "WithAName",
    "timeout": 10,
    "references": ["https://witha.name/"],
}
moduleconfig = []
PARAMETERS = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "date_from": {"type": "string", "format": "date", "description": "Inclusive UTC date; defaults to yesterday."},
        "date_to": {"type": "string", "format": "date", "description": "Exclusive UTC date; defaults to tomorrow."},
        "max_events": {
            "type": "integer",
            "minimum": 0,
            "default": 0,
            "description": "Optional event count budget; 0 means all matching snapshots.",
        },
        "deduplicate_entries": {"type": "boolean", "default": True},
    },
}


class Listing(HTMLParser):
    def __init__(self):
        super().__init__()
        self.filenames = set()

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        href = dict(attrs).get("href", "")
        url = urlsplit(urljoin(SOURCE, href))
        filename = url.path.removeprefix("/data/")
        if url.scheme == "https" and url.netloc == "witha.name" and not url.query and not url.fragment:
            if FILENAME.fullmatch(filename):
                self.filenames.add(filename)


def parameters(value):
    if not isinstance(value, dict) or set(value) - set(PARAMETERS["properties"]):
        raise ValueError("Unknown gathering parameters")
    today = dt.datetime.now(dt.timezone.utc).date()
    start = dt.date.fromisoformat(value.get("date_from", str(today - dt.timedelta(days=1))))
    end = dt.date.fromisoformat(value.get("date_to", str(today + dt.timedelta(days=1))))
    limit = value.get("max_events", 0)
    deduplicate = value.get("deduplicate_entries", True)
    if start >= end:
        raise ValueError("date_from must precede the exclusive date_to")
    if type(limit) is not int or limit < 0:
        raise ValueError("max_events must be a non-negative integer")
    if type(deduplicate) is not bool:
        raise ValueError("deduplicate_entries must be a boolean")
    return start, end, limit, deduplicate


def normalized_config(config):
    if not isinstance(config, dict) or not isinstance(config.get("targets"), list):
        raise ValueError("Configuration must contain a targets array")
    if not isinstance(config.get("randoms", []), list):
        raise ValueError("Configuration randoms must be an array")
    result = copy.deepcopy(config)
    for key in ("targets", "randoms"):
        if key in result:
            if not all(isinstance(entry, dict) for entry in result[key]):
                raise ValueError(f"Configuration {key} entries must be objects")
            result[key] = sorted(result[key], key=canonical_json)
    return result


def convert(config, filename, deduplicate=True):
    match = FILENAME.fullmatch(filename)
    if not match:
        raise ValueError("Invalid configuration filename")
    observed = dt.datetime.strptime(match[1], "%Y-%m-%d_%H-%M-%S").replace(tzinfo=dt.timezone.utc)
    config = normalized_config(config)
    event_uuid = stable_uuid(SOURCE_NAMESPACE, filename, {"deduplicate_entries": deduplicate})
    source_url = SOURCE + filename
    event = {
        "uuid": event_uuid,
        "info": f"WithAName DDoSia configuration {observed.isoformat()}",
        "date": observed.date().isoformat(),
        "analysis": "2",
        "threat_level_id": "4",
        "distribution": "0",
        "published": True,
        "Orgc": {"name": "WithAName", "uuid": stable_uuid(SOURCE_NAMESPACE, "organisation")},
        "Attribute": [],
        "Object": [],
    }
    for relation, value in (("link", source_url), ("attachment", filename)):
        attribute = {
            "uuid": stable_uuid(event_uuid, relation, value),
            "type": relation,
            "category": "External analysis" if relation == "link" else "Artifacts dropped",
            "value": value,
            "to_ids": False,
            "disable_correlation": True,
            "distribution": "5",
            "comment": "Source configuration; listed systems are DDoS targets, not attacker infrastructure.",
        }
        if relation == "attachment":
            attribute["data"] = base64.b64encode(canonical_json(config).encode()).decode()
            attribute["comment"] = (
                "Canonical source JSON, including random substitution definitions and unmapped fields."
            )
        event["Attribute"].append(attribute)
    occurrences = Counter()
    for target in config["targets"]:
        identity = canonical_json(target)
        occurrences[identity] += 1
        if deduplicate and occurrences[identity] > 1:
            continue
        obj = MISPObject("ddos-config", strict=True)
        obj.uuid = stable_uuid(event_uuid, "target", identity, occurrences[identity])
        obj.comment = f"Observed in {source_url}"
        values = {"ddos-tool": "DDoSia-go"}
        for source, value in target.items():
            relation = source.replace("_", "-")
            if relation not in obj._definition["attributes"] or value is None:
                continue
            if relation == "ip":
                value = str(ipaddress.ip_address(value))
            elif relation == "port":
                if type(value) is not int or not 1 <= value <= 65535:
                    raise ValueError("Target port must be an integer between 1 and 65535")
            elif relation == "use-ssl":
                if type(value) is not bool:
                    raise ValueError("Target use_ssl must be a boolean")
                value = "true" if value else "false"
            elif relation in ("body", "headers"):
                value = canonical_json(value)
            elif not isinstance(value, str):
                raise ValueError(f"Target {source} must be a string")
            values[relation] = value
        for relation, value in sorted(values.items()):
            obj.add_attribute(
                relation,
                value=value,
                uuid=stable_uuid(obj.uuid, relation, str(value)),
                to_ids=False,
                disable_correlation=True,
                first_seen=observed,
                last_seen=observed,
            )
        event["Object"].append(json.loads(obj.to_json()))
    return event, int(observed.timestamp())


def gather(params, builder, config=None):
    start, end, limit, deduplicate = parameters(params)

    def fetch(session, url):
        builder.check_cancel()
        with session.get(url, timeout=(5, 15), stream=True, allow_redirects=False) as response:
            if response.status_code != 200:
                raise ValueError(f"Source returned HTTP {response.status_code}")
            chunks, size = [], 0
            for chunk in response.iter_content(65536):
                builder.check_cancel()
                size += len(chunk)
                if size > MAX_SOURCE_BYTES:
                    raise ValueError("Source file size budget exceeded")
                chunks.append(chunk)
            return b"".join(chunks)

    with requests.Session() as session:
        session.headers["User-Agent"] = "MISP-modules/withaname-gathering"
        listing = Listing()
        listing.feed(fetch(session, SOURCE).decode("utf-8"))
        if not listing.filenames:
            raise ValueError("Source listing contains no recognized configuration files")
        filenames = sorted(name for name in listing.filenames if str(start) <= name[:10] < str(end))
        if limit and len(filenames) > limit:
            raise ValueError(
                f"Date range contains {len(filenames)} configurations, exceeding max_events; narrow the range"
            )
        for filename in filenames:
            config = json.loads(fetch(session, SOURCE + filename))
            event, timestamp = convert(config, filename, deduplicate)
            builder.add(event, timestamp)
            del config, event


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or request.get("operation", "prepare") != "prepare":
            raise ValueError("Expected gathering operation prepare")
        params = request.get("parameters", {})
        parameters(params)
        return get_jobs().submit("withaname", params, request.get("config", {}), gather)
    except (ValueError, TypeError, OSError):
        return {"error": "Invalid gathering parameters or job queue unavailable"}


def introspection():
    return {"input": [], "output": ["MISP feed"], "gathering_version": 2, "parameters": PARAMETERS}


def version():
    return {**moduleinfo, "config": moduleconfig}
