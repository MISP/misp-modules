"""Export MISP indicators as a Zeek Intel Framework ASCII input file."""

import base64
import ipaddress
import json
import re
import uuid
from collections import Counter
from urllib.parse import urlsplit

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Zeek Intel Export",
    "description": "Export validated MISP event and object indicators as a Zeek Intel Framework feed.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Produces a tab-separated Intel input file with native indicator types, escaped fields, stable source labels"
        " and MISP provenance. Supports addresses/subnets, domains, HTTP(S) URLs, emails, file names/hashes,"
        " certificate SHA-1 hashes and SSH MD5 fingerprints. Defaults to IDS-marked attributes and excludes deleted"
        " data. No Zeek connection or additional dependency is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/zeek_intel_export.md)."
    ),
    "references": [
        "https://docs.zeek.org/en/current/frameworks/intel.html",
        "https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html",
    ],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded ASCII Zeek Intel TSV, with skipped counts and provenance in the API response.",
}
moduleconfig = ["source", "misp_url", "include_non_ids"]
FIELDS = ("indicator", "indicator_type", "meta.source", "meta.desc", "meta.url")
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
EMAIL_TYPES = {"email", "email-src", "email-dst", "target-email"}
FILENAME_TYPES = {"filename", "email-attachment", "attachment"}
SUPPORTED_TYPES = (
    {
        "ip-src",
        "ip-dst",
        "domain",
        "hostname",
        "domain|ip",
        "url",
        "x509-fingerprint-sha1",
        "ssh-fingerprint",
        "malware-sample",
    }
    | EMAIL_TYPES
    | FILENAME_TYPES
    | HASH_LENGTHS.keys()
    | {f"filename|{kind}" for kind in HASH_LENGTHS}
)


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


def _settings(config):
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object.")
    source = config.get("source")
    if source is None or source == "":
        source = "misp-modules"
    if not isinstance(source, str) or not source.strip() or len(source) > 128:
        raise ValueError("source must be a non-empty string of at most 128 characters.")
    source.encode("utf-8")
    base = config.get("misp_url")
    if base is None or base == "":
        base = None
    else:
        if not isinstance(base, str):
            raise ValueError("misp_url must be an HTTPS base URL.")
        parsed = urlsplit(base)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(ord(char) <= 32 or ord(char) == 127 for char in base)
        ):
            raise ValueError("misp_url must be HTTPS without credentials, a query or a fragment.")
        parsed.port
        base = base.rstrip("/")
    return source, base, _boolean(config.get("include_non_ids"), "include_non_ids")


def _domain(value):
    domain = value.removesuffix(".").encode("idna").decode("ascii").lower()
    if len(domain) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")
    ):
        raise ValueError("Invalid DNS name.")
    return domain


def _fingerprint(value, length):
    if re.fullmatch(r"[0-9a-fA-F]{" + str(length) + r"}", value):
        return value.lower()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){" + str(length // 2 - 1) + r"}[0-9a-fA-F]{2}", value):
        return value.replace(":", "").lower()
    raise ValueError("Invalid fingerprint.")


def _unescape_uri(value):
    """Mirror Zeek HTTP's byte-oriented, single-pass unescape_URI routine."""
    raw, decoded, index = value.encode("utf-8"), bytearray(), 0
    while index < len(raw):
        remaining = raw[index : index + 6]
        if remaining.startswith(b"%%") and len(remaining) >= 3:
            index += 1  # Zeek ignores the first '%' in a doubled escape.
            continue
        if re.match(rb"%[0-9a-fA-F]{2}", remaining):
            decoded.append(int(remaining[1:3], 16))
            index += 3
        elif re.match(rb"%u[0-9a-fA-F]{4}", remaining):
            high, low = int(remaining[2:4], 16), int(remaining[4:6], 16)
            if high:
                decoded.append(high)
            decoded.append(low)
            index += 6
        else:
            decoded.append(raw[index])
            index += 1
    return bytes(decoded)


def _urls(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("URL must be absolute HTTP(S), without credentials or whitespace.")
    port = parsed.port
    host = parsed.netloc.rsplit(":", 1)[0] if port is not None else parsed.netloc
    responder_port = port if port is not None else (80 if parsed.scheme == "http" else 443)
    target = parsed.path or "/"
    if "?" in value.split("#", 1)[0]:
        target += "?" + parsed.query
    target = _unescape_uri(target)
    # HTTP::build_url returns request targets containing '://' without a Host prefix.
    if b"://" in target:
        return [("Intel::URL", target)]
    authorities = {host.encode("utf-8")}
    if port is not None or responder_port != 80:
        authorities.add(f"{host}:{responder_port}".encode("utf-8"))
    if port is not None:
        authorities.add(parsed.netloc.encode("utf-8"))
    # The observer appends the responder port even when Host already includes it.
    suffix = f":{responder_port}".encode("ascii") if responder_port != 80 else b""
    return [("Intel::URL", authority + suffix + target) for authority in sorted(authorities)]


def _atomic(kind, value):
    value.encode("utf-8")
    if kind in FILENAME_TYPES:
        return "Intel::FILE_NAME", value
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Control characters are unsupported for this indicator type.")
    if kind in HASH_LENGTHS:
        if not re.fullmatch(rf"[0-9a-fA-F]{{{HASH_LENGTHS[kind]}}}", value):
            raise ValueError("Invalid file hash.")
        return "Intel::FILE_HASH", value.lower()
    if kind in ("ip-src", "ip-dst"):
        if "%" in value:
            raise ValueError("Scoped IPv6 is unsupported.")
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version == 6 and network.network_address.ipv4_mapped is not None:
                network = ipaddress.IPv4Network((network.network_address.ipv4_mapped, network.prefixlen - 96))
            return "Intel::SUBNET", str(network)
        address = ipaddress.ip_address(value)
        if address.version == 6 and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return "Intel::ADDR", str(address)
    if kind in ("domain", "hostname"):
        return "Intel::DOMAIN", _domain(value)
    if kind in EMAIL_TYPES:
        local, separator, domain = value.rpartition("@")
        if not separator or not re.fullmatch(r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
            raise ValueError("Unsupported email address.")
        return "Intel::EMAIL", local + "@" + _domain(domain)
    if kind == "x509-fingerprint-sha1":
        return "Intel::CERT_HASH", _fingerprint(value, 40)
    if kind == "ssh-fingerprint":
        digest = _fingerprint(re.sub(r"^MD5:", "", value, flags=re.IGNORECASE), 32)
        return "Intel::PUBKEY_HASH", ":".join(digest[index : index + 2] for index in range(0, 32, 2))
    raise ValueError("Unsupported atomic indicator.")


def _indicators(kind, value):
    if kind == "url":
        return _urls(value)
    if "|" not in kind and kind != "malware-sample":
        return [_atomic(kind, value)]
    first, separator, second = value.rpartition("|")
    if not separator or not first.strip() or not second.strip():
        raise ValueError("Invalid composite.")
    if kind == "domain|ip":
        return [_atomic("domain", first), _atomic("ip-dst", second)]
    return [_atomic("md5" if kind == "malware-sample" else kind.split("|")[1], second)]


def _collect(data, include_non_ids):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(envelope, dict) for envelope in data):
        raise ValueError("data must contain an event or list of events.")
    indicators, skipped = {}, Counter()
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if _boolean(event.get("deleted"), "deleted"):
            continue
        collections = dict(event, **envelope)
        attributes = [(attribute, {}) for attribute in _records(collections, "Attribute")]
        for obj in _records(collections, "Object"):
            if not _boolean(obj.get("deleted"), "deleted"):
                attributes.extend((attribute, obj) for attribute in _records(obj, "Attribute"))
        for attribute, obj in attributes:
            if _boolean(attribute.get("deleted"), "deleted") or (
                not _boolean(attribute.get("to_ids"), "to_ids") and not include_non_ids
            ):
                skipped["deleted or non-IDS"] += 1
                continue
            kind, value = attribute.get("type"), attribute.get("value")
            if not isinstance(kind, str) or kind not in SUPPORTED_TYPES:
                skipped["unsupported"] += 1
                continue
            try:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("Empty value.")
                atoms = _indicators(kind, value)
            except ValueError:
                skipped["malformed"] += 1
                continue
            ref = {
                "event": str(event.get("uuid") or event.get("id") or "unknown"),
                "attribute": str(attribute.get("uuid") or attribute.get("id") or "unknown"),
                "misp_type": kind,
                "original_value": value,
            }
            if obj:
                ref["object"] = str(obj.get("uuid") or obj.get("id") or obj.get("name") or "unknown")
                ref["object_relation"] = str(attribute.get("object_relation") or "")
            # Zeek's Intel string store is case-insensitive. Merge those keys so
            # identical source labels cannot overwrite another attribute's provenance.
            for atom_type, indicator in atoms:
                atom = atom_type, (
                    indicator.lower() if isinstance(indicator, bytes) else indicator.translate(ASCII_LOWER)
                )
                refs = indicators.setdefault(atom, [])
                if ref not in refs:
                    refs.append(ref)
    return indicators, dict(skipped)


def _escape(value):
    if value is None:
        return "-"
    encoded = value if isinstance(value, bytes) else value.encode("utf-8")
    escaped = "".join(chr(byte) if 32 <= byte <= 126 and byte not in (35, 92) else f"\\x{byte:02x}" for byte in encoded)
    if escaped in ("-", "(empty)"):
        escaped = f"\\x{encoded[0]:02x}" + escaped[1:]
    return escaped


def _event_url(base, refs):
    if base is None or len(events := {ref["event"] for ref in refs}) != 1:
        return None
    identifier = next(iter(events))
    if re.fullmatch(r"[1-9][0-9]*", identifier):
        return f"{base}/events/view/{identifier}"
    try:
        identifier = str(uuid.UUID(identifier))
    except ValueError:
        return None
    return f"{base}/events/view/{identifier}"


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        source, base, include_non_ids = _settings(request.get("config"))
        indicators, skipped = _collect(request.get("data"), include_non_ids)
        lines, provenance = ["#fields\t" + "\t".join(FIELDS)], []
        for (kind, indicator), refs in sorted(indicators.items()):
            refs = sorted(refs, key=lambda ref: json.dumps(ref, sort_keys=True))
            description = json.dumps(refs, sort_keys=True, ensure_ascii=False)
            row = (indicator, kind, source, description, _event_url(base, refs))
            lines.append("\t".join(_escape(field) for field in row))
            displayed = (
                indicator.decode("utf-8", errors="backslashreplace") if isinstance(indicator, bytes) else indicator
            )
            provenance.append({"indicator": displayed, "indicator_type": kind, "sources": refs})
        output = ("\n".join(lines) + "\n").encode("ascii")
    except (ValueError, TypeError) as exc:
        return {"error": f"Zeek intel export: {exc}"}
    result = {
        "response": [],
        "data": base64.b64encode(output).decode("ascii"),
        "summary": {"count": len(indicators), "skipped": skipped},
        "sources": provenance,
    }
    if skipped:
        result["warnings"] = [f"Skipped {count} {reason} attribute(s)." for reason, count in sorted(skipped.items())]
    return result


def introspection():
    return {
        "input": sorted(SUPPORTED_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "intel",
        "responseType": "text/plain",
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
