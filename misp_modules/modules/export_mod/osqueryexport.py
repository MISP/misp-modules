"""Export MISP events as an osquery JSON query pack or legacy SQL text."""

import base64
import json

from misp_modules.lib.osquery import INPUT_TYPES, build, serialize

moduleinfo = {
    "version": "2.0",
    "author": "Julien Bachmann, Hacknowledge; MISP Project",
    "description": "Export MISP event and object indicators as an osquery query pack.",
    "module-type": ["export"],
    "name": "OSQuery Export",
    "logo": "osquery.png",
    "requirements": [],
    "features": (
        "Produces a JSON query pack with per-query platform selectors and intervals. Validated against osquery 5.24.0."
        " Defaults to IDS-marked attributes, includes object attributes and excludes deleted data. File scans require"
        " an explicit scan_path. Set format=sql for legacy SQL text. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/osqueryexport.md)."
    ),
    "references": ["https://osquery.readthedocs.io/en/stable/deployment/configuration/"],
    "input": "MISP events and object attributes.",
    "output": "Base64-encoded JSON query pack (default) or SQL text, with counts and provenance.",
}
moduleconfig = ["format", "interval", "scan_path", "include_non_ids"]


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        config = request.get("config", {})
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("Configuration must be an object.")
        output_format = config.get("format") or "pack"
        if output_format not in ("pack", "sql"):
            raise ValueError("format must be pack or sql.")
        pack, summary, sources = build(request.get("data"), config)
        output = serialize(pack)
        if output_format == "sql":
            output = "".join(item["query"] + "\n" for item in pack["queries"].values()).encode("utf-8")
    except (ValueError, TypeError) as exc:
        return {"error": f"osquery export: {exc}"}
    return {
        "response": [],
        "data": base64.b64encode(output).decode("ascii"),
        "summary": summary,
        "sources": sources,
        "warnings": [f"Skipped {count}: {reason}" for reason, count in summary["skipped"].items()],
    }


def introspection():
    return {
        "input": sorted(INPUT_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "conf",
        "responseType": "application/json",
        "userConfig": {
            "format": {"type": "String", "message": "pack (default) or sql (legacy text, save as .sql)"},
            "interval": {"type": "String", "message": "Query interval in seconds (default 3600, maximum 604800)"},
            "scan_path": {"type": "String", "message": "Absolute osquery file path pattern, e.g. /tmp/%%"},
            "include_non_ids": {"type": "Boolean", "message": "Include non-IDS attributes (default false)"},
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
