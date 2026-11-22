"""Offensive Agency API transport and MISP host observation mapping."""

import base64
import datetime as dt
import ipaddress
import json
from collections import defaultdict
from importlib import resources

from pymisp import MISPObject

from misp_modules.lib.gathering import canonical_json, stable_uuid

SOURCE = "https://offensive.agency/"
OBSERVATION_NAME = "offensive-agency-observation"
OBSERVATION_TEMPLATE = json.loads(
    resources.files("misp_modules")
    .joinpath("data", "offensive-agency", OBSERVATION_NAME, "definition.json")
    .read_text(encoding="utf-8")
)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_EXPORT_BYTES = 64 * 1024 * 1024


def host_ip(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Expected an IPv4 or IPv6 address")
    return str(ipaddress.ip_address(value))


def day(value):
    return dt.datetime.combine(dt.date.fromisoformat(value), dt.time.min, tzinfo=dt.timezone.utc)


def fetch(session, path, check_cancel=lambda: None, *, allow_missing=False, export=False):
    limit = MAX_EXPORT_BYTES if export else MAX_RESPONSE_BYTES
    check_cancel()
    with session.get(SOURCE + "api/" + path, stream=True, timeout=(5, 30), allow_redirects=False) as response:
        if allow_missing and response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ValueError(f"Offensive Agency returned HTTP {response.status_code}")
        body = bytearray()
        for chunk in response.iter_content(65536):
            check_cancel()
            if len(body) + len(chunk) > limit:
                raise ValueError("Offensive Agency response exceeds the size budget")
            body.extend(chunk)
    data = json.loads(body)
    if not isinstance(data, list if export else dict):
        raise ValueError("Unexpected Offensive Agency JSON response")
    return data


def add(obj, relation, value, *, key=None, **fields):
    obj.add_attribute(relation, value=value, uuid=stable_uuid(obj.uuid, relation, key), to_ids=False, **fields)


def reference(obj, target, relationship):
    obj.add_reference(target, relationship, uuid=stable_uuid(obj.uuid, relationship, target))


def framework_levels(tools):
    if not isinstance(tools, dict) or any(level not in ("confirmed", "probable") for level in tools.values()):
        raise ValueError("Invalid Offensive Agency agent observations")
    return sorted(tools.items())


def strings(values):
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ValueError("Invalid Offensive Agency label list")
    return sorted(set(values))


def network_objects(record, observation, ip, disable_correlation):
    def related(template, *key):
        obj = MISPObject(template, strict=True, standalone=False)
        obj.uuid = stable_uuid(observation.uuid, template, *key)
        add(obj, "ip", ip, disable_correlation=disable_correlation)
        reference(obj, observation.uuid, "related-to")
        return obj

    domains = record.get("domains", [])
    if not isinstance(domains, list):
        raise ValueError("Invalid Offensive Agency domain list")
    for domain in domains:
        if not isinstance(domain, dict) or not isinstance(domain.get("name"), str) or not domain["name"].strip():
            raise ValueError("Invalid Offensive Agency domain observation")
        name = domain["name"]
        levels = [f"{tool}: {level}" for tool, level in framework_levels(domain.get("tools", {}))]
        obj = related("domain-ip", "domain", name)
        add(obj, "domain", name, comment=", ".join(levels))
        yield obj
    for name in strings(record.get("rdns", [])):
        obj = related("domain-ip", "hostname", name)
        add(obj, "hostname", name, comment="Reverse DNS reported by ONYPHE.")
        yield obj

    tools_by_port = defaultdict(set)
    for tool, ports in record.get("ports", {}).items():
        if not isinstance(ports, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
            raise ValueError("Invalid Offensive Agency port list")
        for port in ports:
            tools_by_port[port].add(tool)
    for port, tools in sorted(tools_by_port.items()):
        obj = related("ip-port", port)
        add(obj, "dst-port", port, comment="Observed frameworks: " + ", ".join(sorted(tools)))
        yield obj


def host_objects(ip, record, parent_uuid):
    if host_ip(record["ip"]) != ip:
        raise ValueError("Offensive Agency returned a different asset IP")
    first, last = day(record["first_seen"]), day(record["last_seen"])
    if first > last:
        raise ValueError("Invalid Offensive Agency observation dates")
    observation = MISPObject(
        OBSERVATION_NAME, strict=True, standalone=False, misp_objects_template_custom=OBSERVATION_TEMPLATE
    )
    observation.uuid = stable_uuid(parent_uuid, "observation")
    observation.first_seen = first
    observation.last_seen = last
    disable_correlation = record.get("kind") not in ("hosting", "cloud")
    add(observation, "source-url", SOURCE + "host/" + ip)
    add(
        observation,
        "ip",
        ip,
        disable_correlation=disable_correlation,
        first_seen=first,
        last_seen=last,
        comment="ONYPHE observation, day precision. Shared CDN addresses can serve unrelated domains.",
    )
    for field, relation in (
        ("kind", "network-type"),
        ("country", "country"),
        ("org", "network-operator"),
        ("asn", "asn"),
    ):
        if record.get(field):
            add(observation, relation, record[field])

    for name, level in framework_levels(record["tools"]):
        comment = "Provider confidence in the software observation. Operator intent is unknown."
        families = strings(record.get("families", {}).get(name, []))
        if families:
            comment += " Fingerprint families: " + ", ".join(families)
        add(observation, "framework", f"{name}: {level}", key=name, comment=comment)

    context = []
    for field, label in (
        ("classes", "Device classes"),
        ("clusters", "Cluster labels"),
        ("c2", "Co-hosted C2 labels"),
        ("sources", "Collection sources"),
        ("titles", "Page titles"),
    ):
        values = strings(record.get(field, []))
        if values:
            context.append(f"{label}: " + ", ".join(values))
    if context:
        observation.comment = "\n".join(context)
    add(
        observation,
        "source-record",
        f"offensive-agency-host-{ip.replace(':', '_')}.json",
        data=base64.b64encode(canonical_json(record).encode()).decode(),
        comment="Complete per-host observation reported by Offensive Agency.",
    )
    return [observation, *network_objects(record, observation, ip, disable_correlation)]
