"""Export IDS-marked HTTP indicators as custom ModSecurity rules for OWASP CRS."""

import base64
import ipaddress
import json
import re
from collections import Counter
from urllib.parse import urlsplit

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "OWASP CRS Export",
    "description": "Export IDS-marked proxy and HTTP indicators as custom ModSecurity rules alongside OWASP CRS.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Exports validated source addresses/networks, source address/port pairs, domains, hostnames, hostname/port"
        " pairs, HTTP(S) URLs, request URIs and user agents. Only to_ids attributes are included; deleted data is"
        " excluded. Produces deterministic, deduplicated phase 1 deny rules with configurable local rule IDs."
        " No network access or additional dependency is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/owasp_crs_export.md)."
    ),
    "references": [
        "https://coreruleset.org/",
        "https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)",
    ],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded ModSecurity .conf fragment; skipped counts and integration warnings in the response.",
}
moduleconfig = ["rule_id_start"]
SUPPORTED_TYPES = {"ip-src", "ip-src|port", "domain", "hostname", "hostname|port", "url", "uri", "user-agent"}


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


def _rule_id_start(config):
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    value = config.get("rule_id_start", 10000)
    if value is None or value == "":
        value = 10000
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError("rule_id_start must be an integer from 10000 to 99999.")
    number = int(value)
    if not 10000 <= number <= 99999:
        raise ValueError("rule_id_start must be an integer from 10000 to 99999.")
    return number


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


def _literal(value):
    # PCRE hex escapes protect both the configuration tokenizer and regex parser.
    # In particular, no quotes, action delimiters or %{...} macros reach SecRule.
    return "".join(
        char if char.isascii() and (char.isalnum() or char in "_/-:") else f"\\x{ord(char):02x}" for char in value
    )


def _host_pattern(host, subdomains=False, port=None, optional_port=False):
    prefix = r"(?:[a-z0-9-]+\.)*" if subdomains else ""
    if port is None:
        suffix = r"(?::[0-9]{1,5})?"
    else:
        suffix = rf"(?::{port})?" if optional_port else f":{port}"
    return rf"(?i:{prefix}{_literal(host)}\.?{suffix})"


def _rx(target, pattern):
    return target, rf"@rx \A{pattern}\z"


def _uri(value):
    if not re.fullmatch(r"/[A-Za-z0-9._~:/?\[\]@!$&'()*+,;=%-]*", value) or re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("URI must be an ASCII origin-form request target with valid percent escapes and no fragment.")
    return value


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
        if parsed.netloc.startswith("["):
            raise ValueError("Only IPv6 addresses may use bracketed URL hosts.")
        host = _hostname(host)
    else:
        host = f"[{address}]" if address.version == 6 else str(address)
    port = _port(str(parsed.port)) if parsed.port is not None else ("80" if parsed.scheme == "http" else "443")
    authority = _host_pattern(host, port=port, optional_port=port == ("80" if parsed.scheme == "http" else "443"))
    path = _uri((parsed.path or "/") + ("?" + parsed.query if parsed.query or "?" in value.split("#", 1)[0] else ""))
    # Raw origin-form and absolute-form targets retain path/query case and encoding.
    target = rf"(?:(?i:{parsed.scheme})://{authority})?{_literal(path)}"
    return (_rx("REQUEST_HEADERS:Host", authority), _rx("REQUEST_URI_RAW", target))


def _matches(kind, value):
    if not isinstance(value, str) or not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Indicator must be a non-empty string without control characters.")
    if kind == "user-agent":
        if not value.isascii():
            raise ValueError("User agent must be ASCII.")
        return (_rx("REQUEST_HEADERS:User-Agent", _literal(value)),)
    if any(char.isspace() for char in value):
        raise ValueError("Indicator must not contain whitespace.")
    if kind == "url":
        return _url(value)
    if kind == "uri":
        return (_rx("REQUEST_URI_RAW", _literal(_uri(value))),)
    port = None
    if kind.endswith("|port"):
        value, separator, port = value.partition("|")
        if not separator:
            raise ValueError("Missing host/port separator.")
        port = _port(port)
    if kind in ("domain", "hostname", "hostname|port"):
        return (_rx("REQUEST_HEADERS:Host", _host_pattern(_hostname(value), kind == "domain", port)),)
    if "%" in value:
        raise ValueError("Scoped IPv6 is unsupported.")
    address = ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
    match = (("REMOTE_ADDR", f"@ipMatch {address}"),)
    return match + (("REMOTE_PORT", f"@eq {port}"),) if port else match


def _render(matches, start):
    lines = [
        "# MISP OWASP CRS export: IDS-marked HTTP indicators",
        "# Custom ModSecurity rules; reserve the generated IDs and replace this fragment on each export.",
        "# Requires SecRuleEngine On to block; DetectionOnly logs without blocking.",
    ]
    if start + len(matches) - 1 > 99999:
        raise ValueError("Export exceeds the available local rule ID range (10000-99999).")
    for rule_id, conditions in enumerate(sorted(matches), start):
        actions = (
            f"id:{rule_id},phase:1,deny,status:403,log,t:none,msg:'MISP IDS"
            " indicator',tag:'misp-ioc',severity:'CRITICAL'"
        )
        for index, (target, operator) in enumerate(conditions):
            action = actions if index == 0 else "t:none"
            if index < len(conditions) - 1:
                action += ",chain"
            lines.append(f'SecRule {target} "{operator}" "{action}"')
    return ("\n".join(lines) + "\n").encode("ascii")


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        start = _rule_id_start(request.get("config"))
        matches, skipped = set(), Counter()
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
                matches.add(_matches(kind, attribute.get("value")))
            except (ValueError, UnicodeError):
                skipped["malformed"] += 1
        output = _render(matches, start)
    except (ValueError, TypeError) as exc:
        return {"error": f"OWASP CRS export: {exc}"}
    return {
        "response": [],
        "data": base64.b64encode(output).decode("ascii"),
        "summary": {"count": len(matches), "skipped": dict(skipped)},
        "warnings": [
            *(f"Skipped {count} {reason} attribute(s)." for reason, count in sorted(skipped.items())),
            (
                "Reserve generated rule IDs across all loaded files. Rules directly deny independently of CRS anomaly"
                " scores."
            ),
            "REMOTE_ADDR/REMOTE_PORT describe the client visible to ModSecurity; forwarded headers are not trusted.",
            "Host matches inspect the requested authority, not an upstream DNS lookup or resolved destination IP.",
            (
                "URL rules require visible HTTP headers and request targets; HTTPS CONNECT tunnels hide paths without"
                " TLS inspection. Origin-form URL matches cannot distinguish HTTP from HTTPS; explicit hostname ports"
                " must appear in Host."
            ),
        ],
    }


def introspection():
    return {
        "input": sorted(SUPPORTED_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "conf",
        "responseType": "text/plain",
        "userConfig": {
            "rule_id_start": {
                "type": "String",
                "message": "First local ModSecurity rule ID (10000-99999; default 10000)",
            }
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
