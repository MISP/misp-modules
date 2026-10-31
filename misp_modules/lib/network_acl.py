"""Validated, vendor-neutral matches and the common MISP ACL export contract."""

import base64
import hashlib
import ipaddress
import json
import re
import socket
from collections import Counter
from typing import NamedTuple

DNS_TYPES = {"domain", "hostname", "hostname|port"}
SUPPORTED_TYPES = DNS_TYPES | {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip", "port"}
COMMON_CONFIG = {
    "mode": {"type": "String", "message": "Rule mode: block (default) or log; see vendor logging semantics"},
    "name_prefix": {"type": "String", "message": "Managed name prefix, 1-27 ASCII characters (default: MISP-IOC)"},
    "resolve_dns": {"type": "Boolean", "message": "Resolve DNS-only indicators at export time (default: false)"},
}
PLACEMENT_WARNING = (
    "Configuration fragment: place generated entries before existing terminal decisions, preserve the site's final"
    " policy and remove stale managed entries when refreshing indicators."
)
PERMIT_LOG_WARNING = "Logging mode permits matching traffic and stops policy evaluation; later denies can be bypassed."


class Rule(NamedTuple):
    family: int
    direction: str
    address: str
    protocol: str = ""
    port: str = ""

    @property
    def key(self):
        return hashlib.sha256("|".join(map(str, self)).encode("ascii")).hexdigest()[:16]

    @property
    def source(self):
        return self.address if self.direction == "src" else self.any_network

    @property
    def destination(self):
        return self.address if self.direction == "dst" else self.any_network

    @property
    def any_network(self):
        return "0.0.0.0/0" if self.family == 4 else "::/0"


def boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError(f"{name} must be true, false, 1 or 0.")


def token(config, key, default, limit=27):
    value = config.get(key)
    if value is None or value == "":
        value = default
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0," + str(limit - 1) + "}", value):
        raise ValueError(f"{key} must start with a letter and contain 1-{limit} ASCII letters, digits, _ or -.")
    return value


def settings(config):
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    mode = config.get("mode")
    if mode is None or mode == "":
        mode = "block"
    if not isinstance(mode, str) or mode not in ("block", "log"):
        raise ValueError("mode must be block or log.")
    return dict(
        config,
        mode=mode,
        name_prefix=token(config, "name_prefix", "MISP-IOC"),
        resolve_dns=boolean(config.get("resolve_dns"), "resolve_dns"),
    )


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def attributes(data):
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
        if boolean(event.get("deleted"), "deleted"):
            continue
        collections = dict(event, **envelope)
        yield from _records(collections, "Attribute")
        for obj in _records(collections, "Object"):
            if not boolean(obj.get("deleted"), "deleted"):
                yield from _records(obj, "Attribute")


def _network(value):
    if "%" in value:
        raise ValueError("Scoped IPv6 is unsupported.")
    network = ipaddress.ip_network(value, strict=False)
    return network.version, str(network)


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
            for family, _, _, _, endpoint in socket.getaddrinfo(name + ".", None, socket.AF_UNSPEC, socket.SOCK_STREAM):
                if family in (socket.AF_INET, socket.AF_INET6):
                    try:
                        addresses.add(_network(endpoint[0]))
                    except ValueError:
                        continue
        except OSError:
            pass
        cache[name] = sorted(addresses)
    if not cache[name]:
        raise OSError("No usable A or AAAA records.")
    return cache[name]


def _matches(family, address, direction, port=""):
    return [Rule(family, direction, address, protocol, port) for protocol in (("tcp", "udp") if port else ("",))]


def indicators(kind, value, cache):
    if (
        not isinstance(value, str)
        or not value
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("Indicator must be a non-empty string without whitespace or control characters.")
    if kind == "port":
        port = _port(value)
        return _matches(4, "0.0.0.0/0", "dst", port) + _matches(6, "::/0", "dst", port)
    if kind == "domain|ip":
        name, separator, value = value.partition("|")
        if not separator:
            raise ValueError("Missing domain/IP separator.")
        _hostname(name)
        family, address = _network(value)
        return _matches(family, address, "src") + _matches(family, address, "dst")
    port = ""
    if "|port" in kind:
        value, separator, raw_port = value.partition("|")
        if not separator:
            raise ValueError("Missing host/port separator.")
        port = _port(raw_port)
    if kind in DNS_TYPES:
        addresses = _resolve(_hostname(value), cache)
        directions = ("dst",) if kind == "hostname|port" else ("src", "dst")
        return [
            rule
            for family, address in addresses
            for direction in directions
            for rule in _matches(family, address, direction, port)
        ]
    family, address = _network(value)
    return _matches(family, address, "src" if kind.startswith("ip-src") else "dst", port)


def handle(q, title, configure, render, policy_warnings, comment="#", supports_zero=True):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        config = configure(settings(request.get("config")))
        rules, skipped, cache = set(), Counter(), {}
        port_only = False
        for attribute in attributes(request.get("data")):
            if boolean(attribute.get("deleted"), "deleted"):
                skipped["deleted"] += 1
                continue
            if not boolean(attribute.get("to_ids"), "to_ids"):
                skipped["non-IDS"] += 1
                continue
            kind = attribute.get("type")
            if not isinstance(kind, str) or kind not in SUPPORTED_TYPES:
                skipped["unsupported"] += 1
                continue
            if kind in DNS_TYPES and not config["resolve_dns"]:
                skipped["DNS resolution disabled"] += 1
                continue
            try:
                matches = indicators(kind, attribute.get("value"), cache)
            except (ValueError, UnicodeError):
                skipped["malformed"] += 1
                continue
            except OSError:
                skipped["unresolved DNS"] += 1
                continue
            if not supports_zero and any(match.port == "0" for match in matches):
                skipped["unsupported port zero"] += 1
                continue
            rules.update(matches)
            port_only |= kind == "port"
        warnings = [f"Skipped {number} {reason} attribute(s)." for reason, number in sorted(skipped.items())]
        if rules:
            warnings.extend([PLACEMENT_WARNING, *policy_warnings(config)])
        if cache:
            warnings.append("DNS rules use export-time address snapshots; re-export to follow DNS changes.")
        if port_only:
            warnings.append("Standalone ports match that TCP/UDP destination port on all IPv4 and IPv6 addresses.")
        lines = [f"{comment} MISP {title}: IDS-marked network attributes"]
        lines.extend(f"{comment} {warning}" for warning in warnings)
        lines.extend(render(sorted(rules), config))
        output = ("\n".join(lines) + "\n").encode("ascii")
    except (ValueError, TypeError) as exc:
        return {"error": f"{title}: {exc}"}
    result = {
        "response": [],
        "data": base64.b64encode(output).decode("ascii"),
        "summary": {"count": len(rules), "skipped": dict(skipped)},
    }
    if warnings:
        result["warnings"] = warnings
    return result


def introspection(extra=None):
    return {
        "input": sorted(SUPPORTED_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "cfg",
        "responseType": "text/plain",
        "userConfig": {**COMMON_CONFIG, **(extra or {})},
    }


def module_info(name, slug, description, references):
    return {
        "version": "1.0",
        "author": "MISP Project",
        "name": name,
        "description": description,
        "module-type": ["export"],
        "logo": "",
        "requirements": [],
        "features": (
            "Exports validated IDS-marked event and object network attributes as deduplicated IPv4/IPv6 configuration"
            " fragments. Preserves source/destination address and port constraints. Deleted data is excluded. DNS-only"
            " attributes require opt-in resolve_dns. No device connection or additional dependency is required. See"
            f" the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/{slug}.md) for"
            " configuration, logging semantics and policy integration."
        ),
        "references": references,
        "input": "MISP events and object attributes in standard, bare or legacy export format.",
        "output": "Base64-encoded configuration fragment; rule counts, skipped counts and integration warnings.",
    }
