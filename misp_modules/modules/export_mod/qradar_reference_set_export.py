"""Export one typed list of MISP indicators for a QRadar reference set."""

import base64
import csv
import io
import json

from misp_modules.lib.qradar_reference_set import SUPPORTED_TYPES, boolean, collect, indicator_type

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "QRadar Reference Set Export",
    "description": "Export deduplicated, typed MISP indicators as QRadar reference-set CSV or JSON values.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Exports one selected indicator type from supplied event and object attributes, with validation, normalization"
        " and deduplication. Produces a headerless single-column CSV for Reference Set Management, or a JSON value"
        " array. Defaults to IDS-marked IPv4 addresses; IPv6 uses a separate text set. No QRadar connection is"
        " required."
        " See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/qradar_reference_set_export.md)."
    ),
    "references": ["https://www.ibm.com/docs/en/qradar-on-cloud?topic=overview-importing-iocs-reference-set"],
    "input": "MISP events, including object attributes, in standard, bare or legacy format.",
    "output": "Base64-encoded UTF-8 CSV or JSON; counts and provenance are returned separately from the file.",
}
moduleconfig = ["indicator_type", "format", "include_non_ids"]


def handler(q=False):
    if not q:
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
        selected = indicator_type(config.get("indicator_type"))
        output_format = config.get("format")
        if output_format is None or output_format == "":
            output_format = "csv"
        if output_format not in ("csv", "json"):
            raise ValueError("format must be csv or json.")
        values, skipped = collect(
            request.get("data"), selected, boolean(config.get("include_non_ids"), "include_non_ids")
        )
        ordered = sorted(values)
        if output_format == "json":
            output = json.dumps(ordered, ensure_ascii=False) + "\n"
        else:
            buffer = io.StringIO(newline="")
            writer = csv.writer(buffer, lineterminator="\n")
            writer.writerows([value] for value in ordered)
            output = buffer.getvalue()
    except (ValueError, TypeError) as exc:
        return {"error": f"QRadar reference set export: {exc}"}
    result = {
        "response": [],
        "data": base64.b64encode(output.encode("utf-8")).decode("ascii"),
        "summary": {"indicator_type": selected, "format": output_format, "count": len(values), "skipped": skipped},
        "sources": values,
    }
    if skipped:
        result["warnings"] = [f"Skipped {count} {reason} attribute(s)." for reason, count in sorted(skipped.items())]
    return result


def introspection():
    # MISP's download extension/MIME are static; JSON downloads also retain the .csv extension.
    return {
        "input": sorted(SUPPORTED_TYPES),
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "csv",
        "responseType": "text/csv",
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
