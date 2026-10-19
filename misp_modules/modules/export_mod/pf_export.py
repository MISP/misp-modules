"""Export IDS-marked network indicators as OpenBSD PF block or logging rules."""

import base64
import ipaddress
import json
import re
from collections import Counter

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "OpenBSD PF Export",
    "description": "Export IDS-marked event and object network attributes as OpenBSD PF block or logging rules.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Exports validated IPv4/IPv6 addresses and networks, IP/port pairs, domains, hostnames, domain/IP pairs,"
        " hostname/port pairs and ports as deduplicated block drop quick rules by default, or match log (all) rules"
        " with mode=log. Logging preserves the existing pass/block policy. Only to_ids attributes are included;"
        " deleted data is excluded. DNS names are resolved by PF at ruleset load time. No network access or additional"
        " Python dependency is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/pf_export.md)."
    ),
    "references": ["https://man.openbsd.org/pf.conf", "https://man.openbsd.org/pfctl"],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded PF ruleset fragment; skipped counts and warnings in the API response.",
}
moduleconfig = ["mode"]
RULE_ACTIONS = {"block": "block drop quick", "log": "match log (all)"}
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
}


def _boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError(f"{name} must be true, false, 1 or 0.")


def _mode(config):
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    mode = config.get("mode")
    if mode is None or mode == "":
        return "block"
    if not isinstance(mode, str) or mode not in RULE_ACTIONS:
        raise ValueError("mode must be block or log.")
    return mode


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


def _address(value):
    # Scoped IPv6 and PF interface/keyword syntax must never enter a rule.
    if "%" in value:
        raise ValueError("Scoped IPv6 is unsupported.")
    address = ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
    return str(address), "inet" if address.version == 4 else "inet6"


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


def _rule(mode, host="any", family="", source=False, port=None):
    prefix = RULE_ACTIONS[mode]
    if family:
        prefix += f" {family}"
    if port is not None:
        prefix += " proto { tcp, udp }"
    endpoint = host + (f" port = {port}" if port is not None else "")
    return f"{prefix} from {endpoint} to any" if source else f"{prefix} from any to {endpoint}"


def _rules(kind, value, mode):
    if not isinstance(value, str) or not value or any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError("Indicator must be a non-empty string without whitespace or control characters.")
    if kind == "port":
        return [_rule(mode, port=_port(value))]
    if kind in ("domain", "hostname"):
        host = _hostname(value)
        return [_rule(mode, host), _rule(mode, host, source=True)]
    if kind == "domain|ip":
        domain, separator, address = value.partition("|")
        if not separator:
            raise ValueError("Missing domain/IP separator.")
        _hostname(domain)
        host, family = _address(address)
        return [_rule(mode, host, family), _rule(mode, host, family, source=True)]
    port = None
    if "|port" in kind:
        value, separator, raw_port = value.partition("|")
        if not separator:
            raise ValueError("Missing host/port separator.")
        port = _port(raw_port)
    if kind == "hostname|port":
        host, family = _hostname(value), ""
    else:
        host, family = _address(value)
    return [_rule(mode, host, family, source=kind.startswith("ip-src"), port=port)]


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        mode = _mode(request.get("config"))
        rules, skipped = set(), Counter()
        dns_names = port_only = False
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
                generated = _rules(kind, attribute.get("value"), mode)
            except (ValueError, UnicodeError):
                skipped["malformed"] += 1
                continue
            rules.update(generated)
            dns_names |= kind in ("domain", "hostname", "hostname|port")
            port_only |= kind == "port"
        lines = ["# MISP OpenBSD PF export: IDS-marked network attributes", *sorted(rules)]
        output = ("\n".join(lines) + "\n").encode("ascii")
    except (ValueError, TypeError) as exc:
        return {"error": f"OpenBSD PF export: {exc}"}
    result = {
        "response": [],
        "data": base64.b64encode(output).decode("ascii"),
        "summary": {"count": len(rules), "skipped": dict(skipped)},
    }
    warnings = [f"Skipped {count} {reason} attribute(s)." for reason, count in sorted(skipped.items())]
    if dns_names:
        warnings.append(
            "PF resolves DNS names at ruleset load time; these rules do not match DNS queries or subdomains."
        )
    if port_only:
        warnings.append("Standalone port attributes match that destination port for TCP and UDP on all addresses.")
    if warnings:
        result["warnings"] = warnings
    return result


def introspection():
    return {
        "input": sorted(SUPPORTED_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "conf",
        "responseType": "text/plain",
        "userConfig": {"mode": {"type": "String", "message": "Rule mode: block (default) or log"}},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
