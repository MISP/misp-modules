"""Generate a STIX 2.1 pattern using the public misp-stix attribute converter."""

import json

from misp_stix_converter import MISPtoSTIX21Parser
from pymisp import MISPAttribute
from stix2patterns.validator import run_validator

from misp_modules.lib.indicator_list import boolean

HASH_TYPES = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512/224",
    "sha512/256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "ssdeep",
    "imphash",
    "authentihash",
    "tlsh",
)
mispattributes = {
    "input": sorted(
        {
            *HASH_TYPES,
            *(f"filename|{kind}" for kind in HASH_TYPES),
            "domain",
            "hostname",
            "domain|ip",
            "hostname|port",
            "ip-src",
            "ip-dst",
            "ip-src|port",
            "ip-dst|port",
            "url",
            "uri",
            "filename",
            "malware-sample",
            "email",
            "email-src",
            "email-dst",
            "email-subject",
            "email-body",
            "email-attachment",
            "email-header",
            "email-reply-to",
            "email-x-mailer",
            "mutex",
            "regkey",
            "regkey|value",
            "AS",
            "mac-address",
            "port",
            "size-in-bytes",
            "user-agent",
            "http-method",
            "x509-fingerprint-md5",
            "x509-fingerprint-sha1",
            "x509-fingerprint-sha256",
        }
    ),
    "output": ["stix2-pattern"],
    "format": "misp_standard",
}
moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "STIX2 Pattern Generator",
    "description": "Generate a validated STIX 2.1 pattern from a MISP attribute.",
    "module-type": ["expansion", "hover"],
    "require_standard_format": True,
    "logo": "stix.png",
    "requirements": ["misp-stix (included in the all extra)"],
    "features": (
        "Uses the public misp-stix MISPtoSTIX21Parser mapping, then validates the complete STIX 2.1 pattern."
        " Composite values remain conjunctions. Supports both standard attribute requests and legacy type/value"
        " requests. Generation is explicit and also works for non-IDS source attributes. Conversion warnings or"
        " errors are returned instead of a partial pattern. No external service is contacted. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/expansion/stix2_pattern.md)."
    ),
    "references": [
        "https://github.com/MISP/misp-stix",
        "https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html",
    ],
    "input": "A supported MISP indicator attribute, including filename/hash and address/port composites.",
    "output": "A stix2-pattern attribute in MISP standard format.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("The request must be an object.")
        if "attribute" in request:
            attribute = request["attribute"]
            if not isinstance(attribute, dict):
                raise ValueError("attribute must be an object.")
        else:
            inputs = [kind for kind in mispattributes["input"] if kind in request]
            if len(inputs) != 1:
                raise ValueError("Provide exactly one supported MISP attribute.")
            kind = inputs[0]
            attribute = {"type": kind, "value": request[kind]}
        kind, value = attribute.get("type"), attribute.get("value")
        if not isinstance(kind, str) or kind not in mispattributes["input"]:
            raise ValueError("Unsupported MISP attribute type.")
        if boolean(attribute.get("deleted"), "deleted"):
            raise ValueError("Deleted attributes cannot be converted.")
        if not isinstance(value, str) or not value.strip():
            raise ValueError("The attribute value must be a non-empty string.")
        # Pass only the indicator value; feed/event metadata is not needed for pattern generation.
        parser = MISPtoSTIX21Parser()
        parser.parse_misp_attribute({"type": kind, "value": value, "to_ids": True})
        if parser.errors or parser.warnings:
            raise ValueError("misp-stix could not convert this value without errors or warnings.")
        patterns = [
            obj["pattern"]
            for obj in parser.stix_objects
            if obj["type"] == "indicator" and obj.get("pattern_type") == "stix"
        ]
        if len(patterns) != 1:
            raise ValueError("misp-stix did not produce a single STIX pattern for this attribute.")
        pattern = patterns[0]
        if run_validator(pattern, stix_version="2.1"):
            raise ValueError("misp-stix produced an invalid STIX 2.1 pattern.")
        result = MISPAttribute()
        result.from_dict(
            type="stix2-pattern",
            value=pattern,
            to_ids=True,
            comment=f"STIX 2.1 pattern generated by misp-stix from a {kind} attribute.",
        )
        return {"results": {"Attribute": [json.loads(result.to_json())]}}
    except (TypeError, ValueError) as exc:
        return {"error": str(exc)}
    except Exception:
        return {"error": "misp-stix could not convert the attribute to a STIX 2.1 pattern."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
