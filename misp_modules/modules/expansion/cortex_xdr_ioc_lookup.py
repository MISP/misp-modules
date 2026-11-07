"""Read Cortex XDR IOC rules for a supplied MISP observable."""

import json
from uuid import UUID

from pymisp import MISPEvent, MISPObject

from misp_modules.lib import cortex_xdr as xdr

mispattributes = {"input": xdr.INPUT_TYPES, "format": "misp_standard"}
moduleconfig = [*xdr.CONFIG, "limit", "timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Cortex XDR IOC Lookup",
    "description": "Look up exact hash, domain and IP IOC rules in a Cortex XDR tenant.",
    "module-type": ["expansion", "hover"],
    "data-source": "external",
    "logo": "",
    "requirements": ["A Cortex XDR API key with Rules Edit permission, as required by the IOC lookup endpoint."],
    "features": (
        "Queries indicators/get with indicator and type filters. Supports Standard and Advanced API keys,"
        " IDNA2008 domain normalization and bounded results. Returns a referenced annotation without modifying"
        " Cortex XDR. IOC rule presence is not evidence of an endpoint detection. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/expansion/cortex_xdr_ioc_lookup.md."
    ),
    "references": [xdr.AUTH_REFERENCE, xdr.IOC_REFERENCE],
    "input": "md5, sha256, domain, hostname, ip-src or ip-dst attribute with UUID.",
    "output": "Original attribute and a non-IDS annotation of matching IOC rules and completeness.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise xdr.XdrError("A JSON object is required.")
        source, config = request.get("attribute"), request.get("config")
        if not isinstance(source, dict) or source.get("type") not in xdr.INPUT_TYPES:
            raise xdr.XdrError("A supported attribute with a UUID is required.")
        UUID(source["uuid"])
        kind, value = xdr.indicator(source["type"], source.get("value"))
        if not isinstance(config, dict):
            raise xdr.XdrError("Cortex XDR connection configuration is required.")
        limit = xdr.integer(config.get("limit"), "limit", 20, 100)
        with xdr.Client(config) as client:
            rows, count, truncated = client.lookup(kind, value, limit)
        report = {
            "provider": "Cortex XDR",
            "indicator": value,
            "type": kind,
            "status": "found" if rows else "not_found",
            "returned": len(rows),
            "objects_count": count,
            "truncated": truncated,
            "rules": [xdr.metadata(row) for row in rows],
        }
        obj = MISPObject("annotation")
        obj.comment = "Cortex XDR IOC rule lookup"
        obj.add_attribute("text", value=json.dumps(report, sort_keys=True), to_ids=False, disable_correlation=True)
        obj.add_reference(source["uuid"], "describes")
        event = MISPEvent()
        event.add_object(obj)
        result = {"results": {"Attribute": [source], "Object": json.loads(event.to_json())["Object"]}}
        if truncated:
            result["warnings"] = ["Cortex XDR lookup reached its result limit or reports additional matching rules."]
        return result
    except xdr.XdrError as exc:
        return {"error": str(exc)}
    except (ValueError, KeyError, TypeError, AttributeError):
        return {"error": "Invalid Cortex XDR lookup request or response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
