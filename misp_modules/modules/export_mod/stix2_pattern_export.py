"""Export validated, standalone STIX 2.1 patterns using misp-stix mappings."""

import base64
import json
from collections import Counter

from misp_stix_converter import MISPtoSTIX21Parser
from stix2patterns.validator import run_validator

from misp_modules.lib.indicator_list import boolean

moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "STIX2 Pattern Export",
    "description": "Export stored STIX patterns and generate patterns from IDS-marked MISP attributes.",
    "module-type": ["export"],
    "logo": "stix.png",
    "requirements": ["misp-stix (included in the all extra)"],
    "features": (
        "Exports a JSON array of complete, validated STIX 2.1 patterns. Stored stix2-pattern attributes are included"
        " regardless of to_ids, as in the YARA export. Other attributes use the public misp-stix attribute converter"
        " and must be marked to_ids. Object attributes are processed individually; composites remain conjunctions."
        " Deleted data is excluded. Patterns are deduplicated and sorted. Skipped conversions are reported in the"
        " response summary. No external service is contacted. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/stix2_pattern_export.md)."
    ),
    "references": [
        "https://github.com/MISP/misp-stix",
        "https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html",
    ],
    "input": "MISP events and object attributes in standard, bare or legacy export format.",
    "output": "Base64-encoded JSON array of STIX 2.1 pattern strings, plus conversion counts and warnings.",
}


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
        yield from _records(collections, "Attribute")
        for obj in _records(collections, "Object"):
            if not boolean(obj.get("deleted"), "deleted"):
                yield from _records(obj, "Attribute")


def _patterns(attribute):
    kind, value = attribute.get("type"), attribute.get("value")
    if not isinstance(kind, str) or not isinstance(value, str) or not value.strip():
        raise ValueError("Invalid attribute type or value.")
    if kind == "stix2-pattern":
        patterns = [value]
    else:
        parser = MISPtoSTIX21Parser()
        parser.parse_misp_attribute({"type": kind, "value": value, "to_ids": True})
        if parser.errors or parser.warnings:
            raise ValueError("misp-stix reported errors or warnings.")
        patterns = [
            obj["pattern"]
            for obj in parser.stix_objects
            if obj["type"] == "indicator" and obj.get("pattern_type") == "stix"
        ]
    if not patterns or any(run_validator(pattern, stix_version="2.1") for pattern in patterns):
        raise ValueError("No valid STIX 2.1 pattern.")
    return patterns


def handler(q=False):
    if q is False:
        return False
    skipped = Counter()
    patterns = set()
    stored = generated = 0
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or "data" not in request:
            raise ValueError("Provide MISP events in data.")
        for attribute in _attributes(request["data"]):
            if boolean(attribute.get("deleted"), "deleted"):
                skipped["deleted"] += 1
                continue
            is_stored = attribute.get("type") == "stix2-pattern"
            if not is_stored and not boolean(attribute.get("to_ids"), "to_ids"):
                skipped["non-IDS"] += 1
                continue
            try:
                converted = _patterns(attribute)
            except Exception:
                skipped["invalid or unsupported conversion"] += 1
                continue
            patterns.update(converted)
            if is_stored:
                stored += 1
            else:
                generated += 1
        summary = {
            "patterns": len(patterns),
            "stored_attributes": stored,
            "generated_attributes": generated,
            "skipped": dict(skipped),
        }
        if not patterns:
            return {"error": "No valid STIX 2.1 patterns to export.", "summary": summary}
        result = {
            "response": [],
            "data": (
                base64.b64encode(
                    (json.dumps(sorted(patterns), ensure_ascii=False, indent=2) + "\n").encode("utf-8")
                ).decode("ascii")
            ),
            "summary": summary,
        }
        if skipped.get("invalid or unsupported conversion"):
            result["warnings"] = ["Some attributes could not be converted completely; see summary.skipped."]
        return result
    except (TypeError, ValueError) as exc:
        return {"error": str(exc)}


def introspection():
    return {
        "responseType": "application/json",
        "outputFileExtension": "json",
        "inputSource": ["event", "event-collection"],
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
