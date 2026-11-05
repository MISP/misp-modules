"""Export stored Sigma rules and opt-in Windows indicator detections."""

import base64
import hashlib
import io
import ipaddress
import json
import re
import zipfile
from collections import Counter
from uuid import UUID, uuid5

import yaml

from misp_modules.lib.indicator_list import boolean

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Sigma Rule Export",
    "description": "Export stored Sigma rules and optionally generate Windows IOC detections.",
    "module-type": ["export"],
    "logo": "sigma.png",
    "requirements": ["PyYAML"],
    "features": (
        "Produces a ZIP of Sigma YAML files and a provenance manifest. The default rules mode preserves stored Sigma"
        " attributes, including those in objects. Select indicators or both to generate experimental Windows"
        " process_creation, dns_query and network_connection rules from supported IDS-marked indicators. Deleted"
        " data is excluded; duplicate rules are combined with all source references. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/sigma_export.md)."
    ),
    "references": ["https://sigmahq.io/", "https://github.com/SigmaHQ/sigma-specification"],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded ZIP containing rules/*.yml and manifest.json.",
}
moduleconfig = ["mode", "include_non_ids"]
HASHES = {"md5": 32, "sha1": 40, "sha256": 64, "imphash": 32}
INDICATOR_TYPES = {
    "domain",
    "hostname",
    "ip-src",
    "ip-dst",
    "ip-src|port",
    "ip-dst|port",
    "filename",
    "malware-sample",
    *HASHES,
    *(f"filename|{kind}" for kind in HASHES),
}
MAX_RULES = 1000
MAX_RULE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
RULE_NAMESPACE = UUID("a4973a04-1cd1-4cc2-b981-25418801ac95")


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _attributes(data):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ValueError("data must contain an event or a list of events.")
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if boolean(event.get("deleted"), "deleted") or boolean(envelope.get("deleted"), "deleted"):
            continue
        collections = dict(event, **envelope)
        for attribute in _records(collections, "Attribute"):
            yield event, {}, attribute
        for obj in _records(collections, "Object"):
            if not boolean(obj.get("deleted"), "deleted"):
                for attribute in _records(obj, "Attribute"):
                    yield event, obj, attribute


def _literal(value):
    # Sigma has its own wildcard escaping, independently of YAML quoting.
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _hash(kind, value):
    if not re.fullmatch(rf"[a-fA-F0-9]{{{HASHES[kind]}}}", value):
        raise ValueError("Invalid hash.")
    return f"{kind.upper()}={value.lower()}"


def _filename(value):
    if value.startswith("/") or any(char in value for char in '<>"|'):
        raise ValueError("Not a Windows filename.")
    value = value.replace("/", "\\")
    if re.match(r"^[A-Za-z]:\\", value) or value.startswith("\\\\"):
        return "Image", _literal(value)
    if ":" in value:
        raise ValueError("Unsupported relative Windows filename.")
    return "Image|endswith", _literal("\\" + value.lstrip("\\"))


def _selection(kind, value):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Empty value or control characters.")
    if kind in HASHES:
        return "process_creation", {"Hashes|contains": _hash(kind, value)}
    if kind == "filename":
        field, match = _filename(value)
        return "process_creation", {field: match}
    if kind.startswith("filename|") or kind == "malware-sample":
        filename, separator, digest = value.rpartition("|")
        if not separator or not filename:
            raise ValueError("Invalid filename/hash composite.")
        field, match = _filename(filename)
        hash_kind = "md5" if kind == "malware-sample" else kind.split("|", 1)[1]
        return "process_creation", {field: match, "Hashes|contains": _hash(hash_kind, digest)}
    if kind in ("domain", "hostname"):
        name = value.removesuffix(".").encode("idna").decode("ascii").lower()
        if len(name) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in name.split(".")
        ):
            raise ValueError("Invalid DNS name.")
        names = [name, name + "."]
        if kind == "domain":
            names.extend(["*." + name, "*." + name + "."])
        return "dns_query", {"QueryName": names}
    direction = "Source" if kind.startswith("ip-src") else "Destination"
    port = None
    if kind.endswith("|port"):
        value, separator, port = value.rpartition("|")
        if not separator or not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
            raise ValueError("Invalid address/port composite.")
    if "%" in value:
        raise ValueError("Scoped IPv6 is unsupported.")
    address = ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
    field = direction + "Ip" + ("|cidr" if "/" in value else "")
    selection = {field: str(address)}
    if port is not None:
        selection[direction + "Port"] = int(port)
    return "network_connection", selection


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def _generated_rule(category, selection):
    identity = _json({"product": "windows", "category": category, "selection": selection})
    rule_id = str(uuid5(RULE_NAMESPACE, identity))
    rule = {
        "title": "MISP IOC Match - Windows " + category.replace("_", " ").title(),
        "id": rule_id,
        "status": "experimental",
        "description": (
            "Matches a MISP indicator. Review telemetry, field mappings and false positives before deployment."
        ),
        "author": "MISP",
        "logsource": {"product": "windows", "category": category},
        "detection": {"selection": selection, "condition": "selection"},
        "falsepositives": ["Legitimate activity matching the supplied indicator"],
        "level": "medium",
    }
    return "rules/generated_" + rule_id + ".yml", yaml.safe_dump(rule, sort_keys=False, allow_unicode=True).encode(
        "utf-8"
    )


def _source(event, obj, attribute):
    ref = {
        "event": str(event.get("uuid") or event.get("id") or "unknown"),
        "attribute": str(attribute.get("uuid") or attribute.get("id") or "unknown"),
        "misp_type": attribute["type"],
    }
    if obj:
        ref["object"] = str(obj.get("uuid") or obj.get("id") or obj.get("name") or "unknown")
    return ref


def _build(data, mode, include_non_ids):
    files, sources, skipped = {}, {}, Counter()
    total_bytes = 0
    for event, obj, attribute in _attributes(data):
        if boolean(attribute.get("deleted"), "deleted"):
            skipped["deleted"] += 1
            continue
        kind = attribute.get("type")
        if kind == "sigma":
            if mode == "indicators":
                skipped["excluded by mode"] += 1
                continue
            value = attribute.get("value")
            if not isinstance(value, str) or not value.strip() or "\x00" in value:
                skipped["malformed Sigma contents"] += 1
                continue
            # Preserve rule collections, correlation references and formatting.
            # Existing rules are not parsed, validated or rewritten here.
            content = value.encode("utf-8")
            filename = "rules/stored_" + hashlib.sha256(content).hexdigest() + ".yml"
        else:
            if not isinstance(kind, str) or kind not in INDICATOR_TYPES:
                skipped["unsupported type"] += 1
                continue
            if mode == "rules":
                skipped["excluded by mode"] += 1
                continue
            if not boolean(attribute.get("to_ids"), "to_ids") and not include_non_ids:
                skipped["non-IDS"] += 1
                continue
            try:
                category, selection = _selection(kind, attribute.get("value"))
            except ValueError:
                skipped["malformed indicator"] += 1
                continue
            filename, content = _generated_rule(category, selection)
        if len(content) > MAX_RULE_BYTES:
            raise ValueError("A rule exceeds the 1 MiB limit; split the input.")
        if filename not in files:
            total_bytes += len(content)
            if len(files) >= MAX_RULES or total_bytes > MAX_TOTAL_BYTES:
                raise ValueError("Export exceeds 1000 rule files or 20 MiB of rule contents; split the input.")
            files[filename] = content
        else:
            skipped["duplicate rule"] += 1
        ref = _source(event, obj, attribute)
        if ref not in sources.setdefault(filename, []):
            sources[filename].append(ref)
    summary = {
        "stored_rules": sum(name.startswith("rules/stored_") for name in files),
        "generated_rules": sum(name.startswith("rules/generated_") for name in files),
        "skipped": dict(sorted(skipped.items())),
    }
    sources = {name: sorted(refs, key=_json) for name, refs in sorted(sources.items())}
    return files, {"format_version": 1, "module": "sigma_export", "mode": mode, "summary": summary, "sources": sources}


def _archive(files, manifest):
    files = dict(
        files, **{"manifest.json": (json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()}
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, content)
    return output.getvalue()


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        mode = config.get("mode")
        if mode is None or mode == "":
            mode = "rules"
        if mode not in ("rules", "indicators", "both"):
            raise ValueError("mode must be rules, indicators or both.")
        files, manifest = _build(request.get("data"), mode, boolean(config.get("include_non_ids"), "include_non_ids"))
        warnings = [f"Skipped {count}: {reason}" for reason, count in manifest["summary"]["skipped"].items()]
        if not files:
            return {
                "error": "No Sigma rules selected; use indicators or both mode to generate IOC rules.",
                "summary": manifest["summary"],
                "warnings": warnings,
            }
        return {
            "response": [],
            "data": base64.b64encode(_archive(files, manifest)).decode("ascii"),
            "summary": manifest["summary"],
            "warnings": warnings,
        }
    except (ValueError, TypeError, UnicodeError, yaml.YAMLError) as exc:
        return {"error": f"Sigma export: {exc}"}


def introspection():
    return {
        "input": sorted(INDICATOR_TYPES | {"sigma"}),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "zip",
        "responseType": "application/zip",
        "userConfig": {
            "mode": {
                "type": "String",
                "message": "rules (default), indicators or both; generated rules target Windows telemetry",
            },
            "include_non_ids": {
                "type": "Boolean",
                "message": "Include non-IDS indicators when generating rules (default false)",
            },
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
