"""Export IDS-marked proxy indicators as Squid ACLs and deny rules."""

import base64
import ipaddress
import json
import re
from collections import Counter
from urllib.parse import urlsplit, urlunsplit

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Squid Proxy Export",
    "description": "Export IDS-marked event and object attributes as Squid proxy ACLs and deny rules.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Exports validated addresses/networks, domains, hostnames, HTTP(S) URLs and destination ports as"
        " deduplicated Squid ACLs with http_access deny rules. Composite attributes retain their constraints."
        " Only to_ids attributes are included; deleted data is excluded. No network access or additional dependency"
        " is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/squid_export.md)."
    ),
    "references": [
        "https://www.squid-cache.org/Doc/config/acl/",
        "https://www.squid-cache.org/Doc/config/http_access/",
    ],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded Squid .conf fragment; skipped counts and integration warnings in the API response.",
}
moduleconfig = []
SUPPORTED_TYPES = {
    "ip-src",
    "ip-dst",
    "ip-dst|port",
    "domain",
    "hostname",
    "domain|ip",
    "hostname|port",
    "url",
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
    return str(address)


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
    if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 65535:
        raise ValueError("Port must be an integer from 1 to 65535.")
    return str(int(value))


def _url(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None:
        raise ValueError("URL must be absolute HTTP(S) without credentials.")
    host = parsed.hostname
    if "%" in host or parsed.netloc.endswith(":"):
        raise ValueError("Scoped addresses and empty ports are unsupported.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        host = _hostname(host)
    else:
        host = f"[{address}]" if address.version == 6 else str(address)
    port = parsed.port
    if port is not None:
        _port(str(port))
        if port != (80 if parsed.scheme == "http" else 443):
            host += f":{port}"
    # Fragments are never sent to the proxy. Squid canonicalizes host case,
    # default ports and empty paths; preserve the case of paths and queries.
    url = urlunsplit((parsed.scheme, host, parsed.path or "/", parsed.query, ""))
    # Only RFC 3986 ASCII URI characters, excluding fragment delimiters, quotes
    # and backslashes, may enter Squid's configuration tokenizer.
    if not re.fullmatch(r"[A-Za-z0-9._~:/?\[\]@!$&()*+,;=%-]+", url) or re.search(r"%(?![0-9a-fA-F]{2})", url):
        raise ValueError("URL must use valid ASCII URI characters and percent escapes.")
    # Escape POSIX ERE metacharacters explicitly (rather than accepting an IOC
    # as a regex). Anchors prevent broader host or path substring matches.
    return "^" + re.sub(r"([.\[\]()*+?{}^$|\\])", r"\\\1", url) + "$"


def _matches(kind, value):
    if (
        not isinstance(value, str)
        or not value
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("Indicator must be a non-empty string without whitespace or control characters.")
    if kind == "url":
        return (f"url_regex {_url(value)}",)
    if kind == "port":
        return (f"port {_port(value)}",)
    if kind in ("domain", "hostname"):
        host = _hostname(value)
        return (f"dstdomain -n {'.' if kind == 'domain' else ''}{host}",)
    if kind == "domain|ip":
        domain, separator, address = value.partition("|")
        if not separator:
            raise ValueError("Missing domain/IP separator.")
        return (f"dstdomain -n .{_hostname(domain)}", f"dst {_address(address)}")
    if kind in ("hostname|port", "ip-dst|port"):
        host, separator, port = value.partition("|")
        if not separator:
            raise ValueError("Missing host/port separator.")
        destination = f"dstdomain -n {_hostname(host)}" if kind == "hostname|port" else f"dst {_address(host)}"
        return (destination, f"port {_port(port)}")
    return (f"{'src' if kind == 'ip-src' else 'dst'} {_address(value)}",)


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        matches, skipped = set(), Counter()
        has_urls = port_only = False
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
                match = _matches(kind, attribute.get("value"))
            except (ValueError, UnicodeError):
                skipped["malformed"] += 1
                continue
            matches.add(match)
            has_urls |= kind == "url"
            port_only |= kind == "port"
        lines = [
            "# MISP Squid export: IDS-marked proxy attributes",
            "# Include before http_access allow rules; reserve the misp_squid_ ACL prefix.",
        ]
        for index, match in enumerate(sorted(matches), 1):
            names = [f"misp_squid_{index}_{part}" for part in range(1, len(match) + 1)]
            lines.extend(f"acl {name} {condition}" for name, condition in zip(names, match))
            lines.append(f"http_access deny {' '.join(names)}")
        output = ("\n".join(lines) + "\n").encode("ascii")
    except (ValueError, TypeError) as exc:
        return {"error": f"Squid export: {exc}"}
    warnings = [f"Skipped {count} {reason} attribute(s)." for reason, count in sorted(skipped.items())]
    warnings.append(
        "Include before existing http_access allow rules and keep an explicit final deny all in your policy."
    )
    if has_urls:
        warnings.append(
            "URL ACLs match exact visible HTTP(S) URLs. HTTPS CONNECT tunnels hide paths and queries without TLS"
            " inspection; URL indicators are not expanded into host-wide blocks."
        )
    if port_only:
        warnings.append("Standalone port attributes match that destination port on all hosts.")
    return {
        "response": [],
        "data": base64.b64encode(output).decode("ascii"),
        "summary": {"count": len(matches), "skipped": dict(skipped)},
        "warnings": warnings,
    }


def introspection():
    return {
        "input": sorted(SUPPORTED_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "conf",
        "responseType": "text/plain",
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
