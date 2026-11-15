"""Export unchanged YARA collections and opt-in literal IOC content searches."""

import base64
import hashlib
import io
import json
import zipfile
from collections import Counter

import yara

from misp_modules.lib.indicator_list import boolean

moduleconfig = ["mode"]
moduleinfo = {
    "version": "1.0",
    "author": "Christophe Vandeplas",
    "description": "Export stored YARA collections and optionally generate literal IOC content searches.",
    "module-type": ["export"],
    "name": "YARA Rule Export",
    "logo": "yara.png",
    "requirements": ["yara-python python library"],
    "features": (
        "Produces a ZIP of unchanged stored YARA collections in separate namespaces, with a provenance and exclusion"
        " manifest. The default rules mode exports yara attributes regardless of to_ids. Select indicators or both"
        " to generate literal, case-sensitive UTF-8 byte searches from supported IDS-marked attributes. A filename"
        " or domain matches bytes in scanned content, not a file's name or DNS activity. Deleted data is excluded."
        " Collections and the complete output are compiled with filesystem includes disabled. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/yara_export.md)."
    ),
    "references": ["https://virustotal.github.io/yara/"],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded ZIP containing rules/*.yara and manifest.json; load using the manifest namespaces.",
}

STRING_TYPES = {
    "hostname",
    "domain",
    "ip",
    "ip-src",
    "ip-dst",
    "url",
    "email",
    "email-src",
    "email-dst",
    "email-subject",
    "email-attachment",
    "email-header",
    "email-reply-to",
    "email-x-mailer",
    "email-mime-boundary",
    "email-thread-index",
    "email-message-id",
    "filename",
    "pattern-in-file",
    "pattern-in-traffic",
    "pattern-in-memory",
}
COMPOSITE_TYPES = {
    "hostname|port",
    "domain|ip",
    "ip-src|port",
    "ip-dst|port",
    *(
        f"filename|{kind}"
        for kind in (
            "md5",
            "sha1",
            "sha256",
            "authentihash",
            "vhash",
            "ssdeep",
            "imphash",
            "impfuzzy",
            "pehash",
            "sha224",
            "sha384",
            "sha512",
            "sha512/224",
            "sha512/256",
            "sha3-224",
            "sha3-256",
            "sha3-384",
            "sha3-512",
            "tlsh",
        )
    ),
    "malware-sample",
}
MATCH_SEMANTICS = (
    "Generated rules match any selected literal UTF-8 byte sequence, case-sensitively, anywhere in scanned content."
    " Filename matches do not inspect the scanned file's name or path; domain matches do not parse DNS, resolve"
    " names or enforce hostname boundaries. There is no wide/nocase matching, normalization, hash verification"
    " or network activity detection. Composites contribute independent alternatives; hashes and ports are omitted."
)
# Maximum decoded text-literal length accepted by the pinned yara-python 4.5.4 compiler.
MAX_IOC_STRING_BYTES = 8190


def _literal(value):
    """Quote UTF-8 bytes using only escapes understood by YARA, including controls."""
    escaped = []
    for byte in str(value).encode("utf-8"):
        if byte in (ord('"'), ord("\\")):
            escaped.append("\\" + chr(byte))
        elif 32 <= byte < 127:
            escaped.append(chr(byte))
        else:
            escaped.append(f"\\x{byte:02x}")
    return '"' + "".join(escaped) + '"'


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _attributes(data):
    is_collection = isinstance(data, list)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ValueError("data must contain an event or a list of events.")
    for index, envelope in enumerate(data):
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        deleted = boolean(event.get("deleted"), "deleted") or boolean(envelope.get("deleted"), "deleted")
        collections = dict(event, **envelope)
        location = f"data[{index}]" if is_collection else "data"
        event_location = f"{location}.Event" if "Event" in envelope else location
        attribute_location = location if "Attribute" in envelope else event_location
        object_location = location if "Object" in envelope else event_location
        containers = [(collections, attribute_location, deleted)]
        for obj_index, obj in enumerate(_records(collections, "Object")):
            containers.append(
                (obj, f"{object_location}.Object[{obj_index}]", deleted or boolean(obj.get("deleted"), "deleted"))
            )
        for container, location, container_deleted in containers:
            for attr_index, attribute in enumerate(_records(container, "Attribute")):
                ref = {
                    "event": str(event.get("uuid") or event.get("id") or index),
                    "attribute": str(attribute.get("uuid") or attribute.get("id") or "unknown"),
                    "type": attribute.get("type"),
                    "location": f"{location}.Attribute[{attr_index}]",
                }
                yield index, dict(collections, **event), attribute, ref, container_deleted


def _strings(kind, value):
    if not isinstance(value, str) or not value:
        raise ValueError("Empty or non-string indicator.")
    if kind in STRING_TYPES:
        return [value], []
    left, separator, right = value.rpartition("|")
    if not separator or not left or not right:
        raise ValueError("Composite requires two nonempty components separated by '|'.")
    if kind == "domain|ip":
        return [left, right], []
    omitted = "md5" if kind == "malware-sample" else kind.split("|", 1)[1]
    return [left], [omitted]


def _generated_rule(event, strings):
    org = event.get("Orgc") or {}
    if not isinstance(org, dict):
        raise ValueError("Orgc must be an object.")
    metadata = {
        "description": event.get("info", ""),
        "author": "MISP - " + str(org.get("name", "")),
        "misp_event_date": event.get("date", ""),
        "misp_event_id": event.get("id", ""),
        "misp_event_uuid": event.get("uuid", ""),
        "match_semantics": MATCH_SEMANTICS,
    }
    # Each generated collection has its own namespace, so a fixed ASCII name is sufficient.
    lines = ["rule MISP_ioc {", "    meta:"]
    lines.extend(f"        {key} = {_literal(value)}" for key, value in metadata.items())
    lines.append("    strings:")
    lines.extend(f"        $ioc_{index} = {_literal(value)}" for index, value in enumerate(strings))
    lines.extend(["    condition:", "        any of them", "}", ""])
    return "\n".join(lines)


def _add_collection(sources, manifest, kind, source, refs):
    namespace = kind + "_" + hashlib.sha256(source.encode("utf-8")).hexdigest()
    sources[namespace] = source
    entry = manifest["collections"].setdefault(
        namespace, {"path": f"rules/{namespace}.yara", "kind": kind, "sources": []}
    )
    entry["sources"].extend(refs)
    return namespace


def _build(data, mode):
    sources, generated, exclusions, reductions = {}, {}, [], []
    manifest = {
        "format_version": 1,
        "module": "yara_export",
        "mode": mode,
        "collections": {},
        "exclusions": exclusions,
        "reductions": reductions,
        "match_semantics": MATCH_SEMANTICS,
        "includes": False,
    }

    def exclude(ref, reason, diagnostic=None):
        entry = {"source": ref, "reason": reason}
        if diagnostic is not None:
            entry["diagnostic"] = str(diagnostic)
        exclusions.append(entry)

    for index, event, attribute, ref, deleted in _attributes(data):
        if deleted or boolean(attribute.get("deleted"), "deleted"):
            exclude(ref, "deleted")
            continue
        kind = attribute.get("type")
        if kind == "yara":
            if mode == "indicators":
                exclude(ref, "excluded by mode")
                continue
            source = attribute.get("value")
            if not isinstance(source, str) or not source.strip():
                exclude(ref, "invalid stored collection", "Expected nonempty YARA source.")
                continue
            try:
                if "\x00" in source:
                    raise ValueError("NUL bytes in stored source are unsupported.")
                # Validate the entire attribute, including private/global rules and their references.
                compiled = yara.compile(source=source, includes=False)
                if not list(compiled):
                    raise ValueError("Collection contains no rules.")
                _add_collection(sources, manifest, "stored", source, [ref])
            except (yara.Error, ValueError, UnicodeError) as exc:
                exclude(ref, "invalid stored collection", exc)
            continue
        if mode == "rules":
            exclude(ref, "excluded by mode")
            continue
        if not isinstance(kind, str) or kind not in STRING_TYPES | COMPOSITE_TYPES:
            exclude(ref, "unsupported type")
            continue
        if not boolean(attribute.get("to_ids"), "to_ids"):
            exclude(ref, "non-IDS")
            continue
        try:
            values, omitted = _strings(kind, attribute.get("value"))
            for value in values:
                # Check decoded bytes before grouping, so one invalid IOC cannot block valid output.
                if len(value.encode("utf-8")) > MAX_IOC_STRING_BYTES:
                    raise ValueError(f"IOC string exceeds YARA's {MAX_IOC_STRING_BYTES}-byte UTF-8 literal limit.")
        except (ValueError, UnicodeError) as exc:
            exclude(ref, "invalid indicator", exc)
            continue
        group = generated.setdefault(index, {"event": event, "strings": [], "refs": []})
        group["strings"].extend(values)
        group["refs"].append(ref)
        if omitted:
            reductions.append({"source": ref, "omitted_components": omitted})

    for group in generated.values():
        source = _generated_rule(group["event"], sorted(set(group["strings"])))
        _add_collection(sources, manifest, "generated", source, group["refs"])
    skipped = Counter(entry["reason"] for entry in exclusions)
    manifest["summary"] = {
        "stored_collections": sum(entry["kind"] == "stored" for entry in manifest["collections"].values()),
        "generated_rules": sum(entry["kind"] == "generated" for entry in manifest["collections"].values()),
        "excluded_attributes": len(exclusions),
        "skipped": dict(sorted(skipped.items())),
    }
    return sources, manifest


def _archive(sources, manifest):
    files = {
        manifest["collections"][namespace]["path"]: source.encode("utf-8") for namespace, source in sources.items()
    }
    files["manifest.json"] = (json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
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
        sources, manifest = _build(request.get("data"), mode)
        report = {
            "summary": manifest["summary"],
            "exclusions": manifest["exclusions"],
            "reductions": manifest["reductions"],
            "warnings": [
                f"Skipped {count}: {reason}; see exclusions for source references and diagnostics."
                for reason, count in manifest["summary"]["skipped"].items()
            ],
        }
        if manifest["summary"]["generated_rules"]:
            report["warnings"].append(MATCH_SEMANTICS)
        if not sources:
            return {
                "error": "No valid YARA collections selected; use indicators or both mode to generate IOC searches.",
                **report,
            }
        try:
            # Validate precisely the namespace-to-source mapping delivered in the archive.
            yara.compile(sources=sources, includes=False)
        except yara.Error as exc:
            return {"error": f"Complete YARA output failed to compile: {exc}", **report}
        return {"response": [], "data": base64.b64encode(_archive(sources, manifest)).decode("ascii"), **report}
    except (TypeError, ValueError, UnicodeError) as exc:
        return {"error": f"YARA export: {exc}"}


def introspection():
    return {
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "zip",
        "responseType": "application/zip",
        "userConfig": {
            "mode": {
                "type": "String",
                "message": "rules (default), indicators or both; IOC searches match bytes in content",
            },
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
