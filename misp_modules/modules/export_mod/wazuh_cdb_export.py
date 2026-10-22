"""Export MISP indicators as a typed Wazuh CDB source list."""

import base64
import json

from misp_modules.lib.wazuh_cdb import INPUT_TYPES, build, warnings

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Wazuh CDB Export",
    "description": "Export MISP event and object indicators as a typed Wazuh CDB source list.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Produces a sorted, deduplicated key-only CDB list for one indicator type: IPv4, IPv6, domain, MD5, SHA-1,"
        " SHA-256 or SHA-512. Defaults to to_ids IPv4 attributes. Includes object attributes, normalizes values,"
        " quotes IPv6 keys and excludes deleted data. No Wazuh connection is needed. Register the list and reload"
        " analysisd through the Wazuh API to activate detection. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/wazuh_cdb_export.md)."
    ),
    "references": ["https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html"],
    "input": "MISP events, including object attributes, in standard, bare or legacy format.",
    "output": "Base64-encoded CDB source text, with counts, warnings and provenance outside the file.",
}
moduleconfig = ["indicator_type", "include_non_ids"]


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        output, summary, sources = build(request.get("data"), request.get("config"), allow_non_ids=True)
    except (ValueError, TypeError) as exc:
        return {"error": f"Wazuh CDB export: {exc}"}
    return {
        "response": [],
        "data": base64.b64encode(output).decode("ascii"),
        "summary": summary,
        "sources": sources,
        "warnings": warnings(summary),
    }


def introspection():
    return {
        "input": sorted(INPUT_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "txt",
        "responseType": "text/plain",
        "userConfig": {
            "indicator_type": {
                "type": "String",
                "message": "ipv4 (default), ipv6, domain, md5, sha1, sha256 or sha512",
            },
            "include_non_ids": {"type": "Boolean", "message": "Include non-IDS attributes (default false)"},
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
