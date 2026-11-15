"""Export supported timestamped MISP observations as Timesketch-compatible JSONL."""

from misp_modules.lib.timesketch_exchange import export_findings, loads

moduleconfig = ["misp_url"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Timesketch Observations Export",
    "description": "Export supported timestamped observations as Timesketch JSONL with MISP and source references.",
    "module-type": ["export"],
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Exports existing timesketch-timeline and timesketch_message objects, supported forensic object times and"
        " attribute first_seen/last_seen observations. Emits exact microsecond timestamps and the mandatory"
        " Timesketch fields. MISP modification times are excluded; source identifiers/annotations are namespaced"
        " snapshots. Does not export attachments or contact Timesketch. Complements existing playbooks. See the"
        " [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/timesketch_export.md)."
    ),
    "references": ["https://timesketch.org/guides/user/importing-data/"],
    "input": "MISP events in standard, bare or legacy export format, restricted to the intended selection.",
    "output": "Base64-encoded UTF-8 Timesketch JSONL with mandatory fields, source references and API warnings.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        request = loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an export request object.")
        return export_findings(request)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as error:
        return {"error": f"Unable to export timeline observations: {error}"}


def introspection():
    return {
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "jsonl",
        "responseType": "application/x-ndjson",
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
