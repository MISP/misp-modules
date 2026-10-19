"""Export IDS-marked network attributes as Cisco IOS/IOS-XE ACL fragments."""

import base64
import ipaddress
import json
import re
import socket
from collections import Counter

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Cisco IOS ACL Export",
    "description": "Export IDS-marked network attributes as Cisco IOS/IOS-XE IPv4 and IPv6 ACL fragments.",
    "module-type": ["export"],
    "logo": "cisco.png",
    "requirements": [],
    "features": (
        "Exports validated event and object network attributes as named IPv4 extended and IPv6 ACL fragments."
        " Defaults to deny entries; mode=log emits permit entries with log. Cisco ACL logging is first-match and"
        " permits matching traffic, so it cannot preserve later deny decisions. Only to_ids attributes are included;"
        " deleted data is excluded. DNS-only attributes require opt-in resolve_dns. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/cisco_acl_export.md)."
    ),
    "references": [
        "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-create-ip-apply-0.html",
        "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_ip6-acls-xe.html",
    ],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded IOS/IOS-XE ACL configuration fragments; skipped counts and integration warnings.",
}
moduleconfig = ["mode", "acl_name", "resolve_dns"]
DNS_TYPES = {"domain", "hostname", "hostname|port"}
SUPPORTED_TYPES = DNS_TYPES | {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip", "port"}
POLICY_WARNING = "ACL fragments have an implicit deny; merge entries into existing policy and retain its final rules."
LOG_WARNING = "Logging mode uses permit ... log: matching traffic is allowed and later ACL entries are not evaluated."


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
    if not isinstance(mode, str) or mode not in ("block", "log"):
        raise ValueError("mode must be block or log.")
    name = config.get("acl_name")
    if name is None or name == "":
        name = "MISP-IOC"
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,26}", name):
        raise ValueError(
            "acl_name must start with a letter and contain 1-27 ASCII letters, digits, underscores or hyphens."
        )
    return mode, name, _boolean(config.get("resolve_dns"), "resolve_dns")


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
    network = ipaddress.ip_network(value, strict=False)
    if network.prefixlen == 0:
        address = "any"
    elif network.prefixlen == network.max_prefixlen:
        address = f"host {network.network_address}"
    elif network.version == 4:
        address = f"{network.network_address} {network.hostmask}"
    else:
        address = str(network)
    return network.version, address


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


def _entries(family, address="any", source=False, port=None):
    endpoint = address + (f" eq {port}" if port is not None else "")
    endpoints = f"{endpoint} any" if source else f"any {endpoint}"
    protocols = ("tcp", "udp") if port is not None else ("ip" if family == 4 else "ipv6",)
    return [(family, f"{protocol} {endpoints}") for protocol in protocols]


def _indicators(kind, value, dns_cache):
    if not isinstance(value, str) or not value or any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError("Indicator must be a non-empty string without whitespace or control characters.")
    if kind == "port":
        port = _port(value)
        return [entry for family in (4, 6) for entry in _entries(family, port=port)]
    if kind == "domain|ip":
        name, separator, address = value.partition("|")
        if not separator:
            raise ValueError("Missing domain/IP separator.")
        _hostname(name)
        family, address = _address(address)
        return _entries(family, address) + _entries(family, address, source=True)
    port = None
    if "|port" in kind:
        value, separator, raw_port = value.partition("|")
        if not separator:
            raise ValueError("Missing host/port separator.")
        port = _port(raw_port)
    if kind in DNS_TYPES:
        addresses = _resolve(_hostname(value), dns_cache)
        directions = (False,) if kind == "hostname|port" else (False, True)
        return [
            entry
            for family, address in addresses
            for source in directions
            for entry in _entries(family, address, source, port)
        ]
    family, address = _address(value)
    return _entries(family, address, source=kind.startswith("ip-src"), port=port)


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        mode, name, resolve_dns = _settings(request.get("config"))
        rules, skipped, dns_cache = {4: set(), 6: set()}, Counter(), {}
        port_only = False
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
                indicators = _indicators(kind, attribute.get("value"), dns_cache)
            except (ValueError, UnicodeError):
                skipped["malformed"] += 1
                continue
            except OSError:
                skipped["unresolved DNS"] += 1
                continue
            for family, entry in indicators:
                rules[family].add(f"deny {entry}" if mode == "block" else f"permit {entry} log")
            port_only |= kind == "port"
        count = sum(len(entries) for entries in rules.values())
        lines = ["! MISP Cisco IOS/IOS-XE ACL export: IDS-marked network attributes"]
        if count:
            lines.append("! " + POLICY_WARNING)
            if mode == "log":
                lines.append("! " + LOG_WARNING)
        for family, header in ((4, "ip access-list extended"), (6, "ipv6 access-list")):
            if rules[family]:
                lines.append(f"{header} {name}-V{family}")
                lines.extend(f" {entry}" for entry in sorted(rules[family]))
                lines.append("exit")
        output = ("\n".join(lines) + "\n").encode("ascii")
    except (ValueError, TypeError) as exc:
        return {"error": f"Cisco IOS ACL export: {exc}"}
    result = {
        "response": [],
        "data": base64.b64encode(output).decode("ascii"),
        "summary": {"count": count, "skipped": dict(skipped)},
    }
    warnings = [f"Skipped {number} {reason} attribute(s)." for reason, number in sorted(skipped.items())]
    if count:
        warnings.append(POLICY_WARNING)
        if mode == "log":
            warnings.append(LOG_WARNING)
    if dns_cache:
        warnings.append("DNS rules use export-time address snapshots; re-export to follow DNS changes.")
    if port_only:
        warnings.append("Standalone ports match that TCP/UDP destination port on all IPv4 and IPv6 addresses.")
    if warnings:
        result["warnings"] = warnings
    return result


def introspection():
    return {
        "input": sorted(SUPPORTED_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "cfg",
        "responseType": "text/plain",
        "userConfig": {
            "mode": {"type": "String", "message": "Rule mode: block (default) or log (permits matching traffic)"},
            "acl_name": {
                "type": "String",
                "message": "ACL name prefix, max 27 characters (default: MISP-IOC; adds -V4 and -V6)",
            },
            "resolve_dns": {
                "type": "Boolean",
                "message": "Resolve DNS-only indicators at export time (default: false)",
            },
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
