"""Export IDS-marked network attributes as nftables block or logging rules."""

import base64
import ipaddress
import json
import re
import socket
from collections import Counter

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Netfilter nftables Export",
    "description": "Export IDS-marked event and object network attributes as nftables block or logging rules.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Exports validated IPv4/IPv6 addresses and networks, IP/port pairs, domain/IP pairs, ports and source MAC"
        " addresses as deduplicated nftables chain-body rules. Defaults to dropping matches; mode=log logs without"
        " changing the firewall verdict. Only to_ids attributes are included, and deleted data is excluded. DNS-only"
        " attributes require opt-in resolve_dns and are resolved to address snapshots at export time. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/netfilter_export.md)."
    ),
    "references": [
        "https://netfilter.org/projects/nftables/",
        "https://www.netfilter.org/projects/nftables/manpage.html",
    ],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded nftables chain-body fragment; skipped counts and warnings in the API response.",
}
moduleconfig = ["mode", "resolve_dns"]
RULE_ACTIONS = {"block": "counter drop", "log": 'counter log prefix "MISP: " level info'}
DNS_TYPES = {"domain", "hostname", "hostname|port"}
SUPPORTED_TYPES = DNS_TYPES | {
    "ip-src",
    "ip-dst",
    "ip-src|port",
    "ip-dst|port",
    "domain|ip",
    "port",
    "mac-address",
}


def _boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError(f"{name} must be true, false, 1 or 0.")


def _settings(config):
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    mode = config.get("mode")
    if mode is None or mode == "":
        mode = "block"
    if not isinstance(mode, str) or mode not in RULE_ACTIONS:
        raise ValueError("mode must be block or log.")
    return mode, _boolean(config.get("resolve_dns"), "resolve_dns")


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _attributes(data):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("data must be an event object or a list of events.")
    for envelope in data:
        if not isinstance(envelope, dict):
            raise ValueError("Each event must be an object.")
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if _boolean(event.get("deleted"), "deleted"):
            continue
        collections = dict(event, **envelope)
        yield from _records(collections, "Attribute")
        for obj in _records(collections, "Object"):
            if not _boolean(obj.get("deleted"), "deleted"):
                yield from _records(obj, "Attribute")


def _address(value):
    if "%" in value:
        raise ValueError("Scoped IPv6 is unsupported.")
    address = ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
    return str(address), "ip" if address.version == 4 else "ip6"


def _hostname(value):
    name = value.removesuffix(".").encode("idna").decode("ascii").lower()
    labels = name.split(".")
    if (
        len(name) > 253
        or len(labels) < 2
        or not re.search(r"[a-z]", labels[-1])
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
    ):
        raise ValueError("Invalid qualified DNS name.")
    return name


def _port(value):
    if not re.fullmatch(r"[0-9]{1,5}", value) or int(value) > 65535:
        raise ValueError("Port must be an integer from 0 to 65535.")
    return str(int(value))


def _resolve(name, cache):
    if name not in cache:
        addresses = set()
        try:
            # A trailing dot prevents expansion through the resolver's DNS search path.
            answers = socket.getaddrinfo(name + ".", None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, _, _, _, endpoint in answers:
                if family in (socket.AF_INET, socket.AF_INET6):
                    try:
                        addresses.add(_address(endpoint[0]))
                    except ValueError:
                        continue
        except OSError:
            pass
        cache[name] = sorted(addresses)
    if not cache[name]:
        raise OSError("No usable A or AAAA records.")
    return cache[name]


def _match(host=None, family=None, source=False, port=None):
    parts = []
    if host is not None:
        parts.append(f"{family} {'saddr' if source else 'daddr'} {host}")
    if port is not None:
        parts.append("meta l4proto { tcp, udp }")
        parts.append(f"th {'sport' if source else 'dport'} {port}")
    return " ".join(parts)


def _matches(kind, value, dns_cache):
    if not isinstance(value, str) or not value or any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError("Indicator must be a non-empty string without whitespace or control characters.")
    if kind == "port":
        return [_match(port=_port(value))]
    if kind == "mac-address":
        mac = value.replace("-", ":").lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            raise ValueError("Invalid 48-bit MAC address.")
        return [f"ether saddr {mac}"]
    if kind == "domain|ip":
        name, separator, address = value.partition("|")
        if not separator:
            raise ValueError("Missing domain/IP separator.")
        _hostname(name)
        host, family = _address(address)
        return [_match(host, family), _match(host, family, source=True)]
    port = None
    if "|port" in kind:
        value, separator, raw_port = value.partition("|")
        if not separator:
            raise ValueError("Missing host/port separator.")
        port = _port(raw_port)
    if kind in DNS_TYPES:
        addresses = _resolve(_hostname(value), dns_cache)
        directions = (False,) if kind == "hostname|port" else (False, True)
        return [_match(host, family, source, port) for host, family in addresses for source in directions]
    host, family = _address(value)
    return [_match(host, family, source=kind.startswith("ip-src"), port=port)]


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        mode, resolve_dns = _settings(request.get("config"))
        rules, skipped, dns_cache = set(), Counter(), {}
        port_only = mac_addresses = False
        for attribute in _attributes(request.get("data")):
            if _boolean(attribute.get("deleted"), "deleted"):
                skipped["deleted"] += 1
                continue
            if not _boolean(attribute.get("to_ids"), "to_ids"):
                skipped["non-IDS"] += 1
                continue
            kind = attribute.get("type")
            if not isinstance(kind, str) or kind not in SUPPORTED_TYPES:
                skipped["unsupported"] += 1
                continue
            if kind in DNS_TYPES and not resolve_dns:
                skipped["DNS resolution disabled"] += 1
                continue
            try:
                matches = _matches(kind, attribute.get("value"), dns_cache)
            except (ValueError, UnicodeError):
                skipped["malformed"] += 1
                continue
            except OSError:
                skipped["unresolved DNS"] += 1
                continue
            rules.update(f"{match} {RULE_ACTIONS[mode]}" for match in matches)
            port_only |= kind == "port"
            mac_addresses |= kind == "mac-address"
        lines = ["# MISP netfilter nftables export: include inside an inet-family chain", *sorted(rules)]
        output = ("\n".join(lines) + "\n").encode("ascii")
    except (ValueError, TypeError) as exc:
        return {"error": f"Netfilter nftables export: {exc}"}
    result = {
        "response": [],
        "data": base64.b64encode(output).decode("ascii"),
        "summary": {"count": len(rules), "skipped": dict(skipped)},
    }
    warnings = [f"Skipped {count} {reason} attribute(s)." for reason, count in sorted(skipped.items())]
    if dns_cache:
        warnings.append("DNS rules use export-time address snapshots; re-export to follow DNS changes.")
    if port_only:
        warnings.append("Standalone port attributes match that destination port for TCP and UDP on all addresses.")
    if mac_addresses:
        warnings.append(
            "MAC attributes match Ethernet source addresses only on links where those headers are available."
        )
    if warnings:
        result["warnings"] = warnings
    return result


def introspection():
    return {
        "input": sorted(SUPPORTED_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "nft",
        "responseType": "text/plain",
        "userConfig": {
            "mode": {"type": "String", "message": "Rule mode: block (default) or log"},
            "resolve_dns": {
                "type": "Boolean",
                "message": "Resolve DNS-only indicators at export time (default: false)",
            },
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
