"""Gather the SinkDB sinkhole export into a single fixed MISP event."""

import datetime as dt
import ipaddress
import json
import time
from importlib import resources
from urllib.parse import urlencode

import certifi
import urllib3
from pymisp import MISPObject

from misp_modules.lib.gathering import CONTRACT_VERSION, NAMESPACE, get_jobs, origin_tags, stable_uuid

MODULE = "sinkdb"
SOURCE = "https://sinkdb.abuse.ch/"
EXPORT_URL = "https://sinkdb-api.abuse.ch/api/v1/"
MAX_EXPORT_BYTES = 16 * 1024 * 1024
SOURCE_NAMESPACE = stable_uuid(NAMESPACE, "sinkdb.abuse.ch")
EVENT_UUID = stable_uuid(SOURCE_NAMESPACE, "sinkholes")
OBJECT_NAME = "sinkhole-server"
OBJECT_TEMPLATE = json.loads(
    resources.files("misp_modules").joinpath("data", OBJECT_NAME, "definition.json").read_text(encoding="utf-8")
)

moduleinfo = {
    "name": "SinkDB",
    "version": "1",
    "author": "MISP Project",
    "module-type": ["gathering"],
    "description": "Gather the complete abuse.ch SinkDB sinkhole export into one fixed MISP event.",
    "requirements": ["SinkDB HTTPS API key"],
    "references": [SOURCE, SOURCE + "about/"],
}
moduleconfig = {"api_key": {"description": "SinkDB HTTPS API key", "redacted": True}}
PARAMETERS = {"type": "object", "additionalProperties": False, "properties": {}}
IP_TYPES = {
    "ipv4": ipaddress.IPv4Address,
    "ipv6": ipaddress.IPv6Address,
    "ipv4_range": ipaddress.IPv4Network,
    "ipv6_range": ipaddress.IPv6Network,
}


def api_key(config):
    key = config.get("api_key") if isinstance(config, dict) else None
    if not isinstance(key, str) or not key.strip():
        raise ValueError("Configure the SinkDB HTTPS API key")
    return key.strip()


def fetch(key, check_cancel):
    check_cancel()
    body = urlencode({"api_key": key, "export": "sinkholes"}).encode("ascii")
    payload = bytearray()
    # The general requests debug tracer logs request and response bodies. Both are private here.
    try:
        with (
            urllib3.PoolManager(ca_certs=certifi.where()) as client,
            client.request(
                "POST",
                EXPORT_URL,
                body=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "MISP-modules/sinkdb",
                },
                timeout=urllib3.Timeout(connect=5, read=30),
                redirect=False,
                retries=False,
                preload_content=False,
            ) as response,
        ):
            if response.status != 200:
                raise ValueError(f"SinkDB export returned HTTP {response.status}")
            for chunk in response.stream(64 * 1024, decode_content=True):
                check_cancel()
                if len(payload) + len(chunk) > MAX_EXPORT_BYTES:
                    raise ValueError("SinkDB export size budget exceeded")
                payload.extend(chunk)
    except urllib3.exceptions.HTTPError:
        raise ValueError("SinkDB export request failed") from None

    try:
        export = json.loads(payload)
    except (ValueError, RecursionError):
        raise ValueError("SinkDB export did not return valid JSON") from None
    if not isinstance(export, dict) or export.get("query_status") != "ok":
        raise ValueError("SinkDB rejected the export request; check the HTTPS API key and export access")
    if not isinstance(export.get("results"), list):
        raise ValueError("SinkDB export is missing its results array")
    return export["results"]


def text_field(record, key):
    value = record.get(key)
    return value.strip() if isinstance(value, str) else ""


def indicator_attribute(kind, indicator):
    if kind in IP_TYPES:
        try:
            parse = IP_TYPES[kind]
            address = parse(indicator, strict=False) if kind.endswith("_range") else parse(indicator)
            return "ip", str(address)
        except ValueError:
            return "indicator", indicator
    if kind == "domain_soa":
        return ("soa-email", indicator) if "@" in indicator else ("soa-domain", indicator.lower())
    if kind == "nameserver":
        return "nameserver", indicator.lower()
    if kind == "whois_email":
        return "whois-email", indicator
    return "indicator", indicator


def sinkhole_object(record):
    if not isinstance(record, dict):
        raise ValueError("SinkDB export contains a non-object record")
    kind = text_field(record, "type").lower()
    indicator = text_field(record, "indicator")
    if not kind or not indicator:
        raise ValueError("SinkDB record is missing its indicator or type")

    relation, value = indicator_attribute(kind, indicator)
    source = text_field(record, "source")
    added = text_field(record, "date_added")
    if added:
        try:
            added = dt.datetime.fromisoformat(added.removesuffix(" UTC").removesuffix("Z"))
            added = added.replace(tzinfo=added.tzinfo or dt.timezone.utc).astimezone(dt.timezone.utc).isoformat()
        except (ValueError, OverflowError):
            raise ValueError("SinkDB record contains an invalid date_added") from None

    obj = MISPObject(OBJECT_NAME, strict=True, misp_objects_template_custom=OBJECT_TEMPLATE)
    obj.uuid = stable_uuid(EVENT_UUID, source, kind, value, added)
    obj.distribution = 5
    values = {
        relation: value,
        "indicator-type": kind,
        "source": source,
        "classification": text_field(record, "classification"),
        "date-added": added,
    }
    if record.get("expose_org") in (1, "1"):
        values["operator"] = text_field(record, "operator")
    for relation, value in values.items():
        if value:
            obj.add_attribute(
                relation,
                value,
                uuid=stable_uuid(obj.uuid, relation),
                distribution=5,
                to_ids=False,
                disable_correlation=True,
            )
    return json.loads(obj.to_json()), added[:10]


def gather(parameters, builder, config=None):
    records = fetch(api_key(config), builder.check_cancel)
    objects = []
    latest_date = "1970-01-01"
    for record in records:
        builder.check_cancel()
        obj, added = sinkhole_object(record)
        objects.append(obj)
        latest_date = max(latest_date, added)
    event = {
        "uuid": EVENT_UUID,
        "info": "abuse.ch SinkDB sinkholes",
        "date": latest_date,
        "distribution": "0",
        "analysis": "2",
        "threat_level_id": "4",
        "published": False,
        "Orgc": {"name": "abuse.ch", "uuid": stable_uuid(SOURCE_NAMESPACE, "organisation")},
        "Tag": [*origin_tags(MODULE, "sinkdb.abuse.ch"), {"name": "tlp:amber"}],
        "Attribute": [],
        "Object": objects,
    }
    # The export provides no snapshot timestamp. The revision store preserves
    # this timestamp on identical content and advances it when the export changes.
    builder.add(event, int(time.time()))


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or request.get("operation", "prepare") != "prepare":
            raise ValueError("Expected gathering operation prepare")
        parameters = request.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise ValueError("SinkDB gathering takes no parameters")
        config = {"api_key": api_key(request.get("config"))}
        return get_jobs().submit(MODULE, parameters, config, gather, keep_revisions=True)
    except (ValueError, TypeError, OSError) as exc:
        return {"error": str(exc)}


def introspection():
    return {"input": [], "output": ["MISP feed"], "gathering_version": CONTRACT_VERSION, "parameters": PARAMETERS}


def version():
    return {**moduleinfo, "config": moduleconfig}
