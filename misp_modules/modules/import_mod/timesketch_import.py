"""Import selected Timesketch and Plaso timeline exports without a service connection."""

import binascii
import csv

from pymisp.exceptions import PyMISPError

from misp_modules.lib.timesketch_exchange import import_findings, loads

moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Timesketch and Plaso Findings Import",
    "description": (
        "Import selected or annotated Timesketch/Plaso entries with source references and annotation context."
    ),
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Accepts Timesketch search JSON, JSONL and CSV exports and Plaso psort json_line output. Reuses the"
        " timesketch-timeline object, preserving event/sketch/timeline identifiers, annotations, raw entries and"
        " microsecond timestamps. Selection can include all supplied entries, explicit selections or annotations."
        " Source annotations remain context, not malicious verdicts. Includes a compatible template and requires no"
        " API credentials or tool execution. Complements existing Timesketch playbooks. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/timesketch_import.md)."
    ),
    "references": ["https://timesketch.org/", "https://plaso.readthedocs.io/"],
    "input": "Base64-encoded UTF-8 JSON, JSONL or CSV in data; optional filename and selection/source settings.",
    "output": "Source file and timesketch-timeline objects, with unnormalized times retained and reported.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        request = loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an import request object.")
        return import_findings(request)
    except (
        ValueError,
        TypeError,
        UnicodeError,
        binascii.Error,
        csv.Error,
        PyMISPError,
        RecursionError,
        OverflowError,
    ) as error:
        return {"error": f"Unable to import timeline findings: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "format": {"type": "String", "message": "auto (default), json, jsonl or csv"},
            "selection": {"type": "String", "message": "all (default), selected or annotated"},
            "datetime_unit": {
                "type": "String",
                "message": "Explicit numeric datetime unit: s, ms, us or ns; empty for ISO dates",
            },
            "sketch_id": {"type": "String", "message": "Optional source sketch ID when absent from the export"},
            "timeline_id": {"type": "String", "message": "Optional source timeline ID when absent from the export"},
            "source_url": {"type": "String", "message": "Optional source selection/event URL; never fetched"},
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
