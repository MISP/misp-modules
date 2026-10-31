"""Export IDS-marked network indicators as a libpcap capture filter."""

import base64
import ipaddress
import json
import re
from collections import Counter

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "BPF Export",
    "description": "Export IDS-marked event and object network attributes as a tcpdump/libpcap capture filter.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Produces a sorted, deduplicated BPF capture expression for IPv4/IPv6 hosts and networks, IP/port pairs,"
        " domains, hostname/port pairs, domain/IP pairs, ports and MAC addresses. Only to_ids attributes are"
        " included; deleted data is excluded. Names are resolved by libpcap at filter compilation time. Empty"
        " matches return an error rather than an unfiltered capture. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/bpf_export.md)."
    ),
    "references": ["https://www.tcpdump.org/manpages/pcap-filter.7.html"],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded libpcap capture filter for tcpdump -F; skipped counts and warnings in the API response.",
}
moduleconfig = []
SUPPORTED_TYPES = {
    "ip-src",
    "ip-dst",
    "ip-src|port",
    "ip-dst|port",
    "domain",
    "hostname",
    "domain|ip",
    "hostname|port",
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
        # Standard exports nest collections under Event; legacy exports put them beside it.
        collections = dict(event, **envelope)
        yield from _records(collections, "Attribute")
        for obj in _records(collections, "Object"):
            if not _boolean(obj.get("deleted"), "deleted"):
                yield from _records(obj, "Attribute")


def _hostname(value):
    name = value.removesuffix(".").encode("idna").decode("ascii").lower()
    # Require a qualified DNS name to avoid PF keywords, interface names and numeric aliases.
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


def _address(value):
    if "%" in value:
        raise ValueError("Scoped IPv6 is unsupported.")
    address = ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
    return str(address), "ip" if address.version == 4 else "ip6", "net" if "/" in value else "host"


def _match(host=None, family=None, qualifier="host", direction="", port=None):
    parts = []
    if host is not None:
        parts.append(" ".join(part for part in (family, direction, qualifier, host) if part))
    if port is not None:
        parts.append("(tcp or udp)")
        parts.append(" ".join(part for part in (direction, "port", port) if part))
    return "(" + " and ".join(parts) + ")"


def _rule(kind, value):
    if not isinstance(value, str) or not value or any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError("Indicator must be a non-empty string without whitespace or control characters.")
    if kind == "port":
        return _match(port=_port(value), direction="dst")
    if kind == "mac-address":
        mac = value.replace("-", ":").lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            raise ValueError("Invalid 48-bit MAC address.")
        return f"(ether host {mac})"
    if kind == "domain|ip":
        name, separator, address = value.partition("|")
        if not separator:
            raise ValueError("Missing domain/IP separator.")
        _hostname(name)
        host, family, qualifier = _address(address)
        return _match(host, family, qualifier)
    port = None
    if "|port" in kind:
        value, separator, raw_port = value.partition("|")
        if not separator:
            raise ValueError("Missing host/port separator.")
        port = _port(raw_port)
    direction = "src" if kind.startswith("ip-src") else "dst"
    if kind in ("domain", "hostname", "hostname|port"):
        host, family, qualifier = _hostname(value), None, "host"
        if kind != "hostname|port":
            direction = ""
    else:
        host, family, qualifier = _address(value)
    return _match(host, family, qualifier, direction, port)


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        rules, skipped = set(), Counter()
        dns_names = port_only = mac_addresses = False
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
            try:
                rule = _rule(kind, attribute.get("value"))
            except (ValueError, UnicodeError):
                skipped["malformed"] += 1
                continue
            rules.add(rule)
            dns_names |= kind in ("domain", "hostname", "hostname|port")
            port_only |= kind == "port"
            mac_addresses |= kind == "mac-address"
        if not rules:
            return {
                "error": "BPF export: No usable IDS-marked network attributes; no capture filter generated.",
                "summary": {"count": 0, "skipped": dict(skipped)},
            }
        output = (" or\n".join(sorted(rules)) + "\n").encode("ascii")
    except (ValueError, TypeError) as exc:
        return {"error": f"BPF export: {exc}"}
    result = {
        "response": [],
        "data": base64.b64encode(output).decode("ascii"),
        "summary": {"count": len(rules), "skipped": dict(skipped)},
    }
    warnings = [f"Skipped {count} {reason} attribute(s)." for reason, count in sorted(skipped.items())]
    if dns_names:
        warnings.append(
            "libpcap resolves DNS names at filter compilation time; unresolved names can prevent compilation."
            " These expressions do not match DNS queries, TLS SNI, HTTP Host headers or subdomains."
        )
    if port_only:
        warnings.append("Standalone port attributes match that destination port for TCP and UDP on all addresses.")
    if mac_addresses:
        warnings.append("MAC address filters require a link-layer type supported by libpcap for ether host.")
    if warnings:
        result["warnings"] = warnings
    return result


def introspection():
    return {
        "input": sorted(SUPPORTED_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "bpf",
        "responseType": "text/plain",
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
