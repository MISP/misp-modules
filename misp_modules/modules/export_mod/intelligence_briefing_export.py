"""Export a cited intelligence briefing and its analyst review status."""

import base64
import json

from misp_modules.lib.indicator_list import boolean
from misp_modules.lib.intelligence_briefing import build_briefing

CONFIGURATION = ["report_uuid", "require_reviewed"]
MAX_REQUEST = 16 * 1024 * 1024
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Cited Intelligence Briefing Export",
    "description": "Export an intelligence briefing with key judgments, evidence citations and analyst review checks.",
    "module-type": ["export"],
    "require_standard_format": True,
    "fetch_options": {
        "includeAnalystData": True,
        "noEventReports": False,
        "includeAttachments": False,
        "includeEventCorrelations": False,
        "includeGranularCorrelations": False,
    },
    "features": (
        "Builds a Markdown briefing from a selected Event Report, referenced intelligence judgments, Analyst Data,"
        " and INTREP source assessments. Flags missing or unresolved citations, confidence and alternatives."
        " Checks an Analyst Opinion against the briefing's SHA-256 fingerprint before marking it reviewed."
    ),
    "references": [
        "https://www.intelligence.gov/mission/our-values/objectivity",
        "https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/intelligence_briefing_export.md",
    ],
    "input": "One MISP event with an Event Report, judgment objects, and the analyst data and evidence it cites.",
    "output": "Base64-encoded Markdown with linked citations and release checks.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        if not isinstance(q, (str, bytes)) or len(q) > MAX_REQUEST:
            raise ValueError("Expected an export request of at most 16 MiB.")
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an export request object.")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        require_reviewed = boolean(config.get("require_reviewed"), "require_reviewed")
        text, summary, warnings = build_briefing(request.get("data"), config.get("report_uuid"))
        if require_reviewed and summary["status"] != "reviewed":
            return {"error": "Briefing release checks failed.", "summary": summary, "warnings": warnings}
        return {
            "response": [],
            "data": base64.b64encode(text.encode("utf-8")).decode("ascii"),
            "summary": summary,
            "warnings": warnings,
        }
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        return {"error": f"Unable to export intelligence briefing. {error}"}


def introspection():
    return {"responseType": "text/markdown", "outputFileExtension": "md", "inputSource": ["event"], "userConfig": {}}


def version():
    return dict(moduleinfo, config=CONFIGURATION)
