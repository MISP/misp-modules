"""Import selected Zeek logs without opening captures or contacting a sensor."""

import binascii
from decimal import InvalidOperation

from pymisp.exceptions import PyMISPError

from misp_modules.lib.network_observation import import_observations, loads

moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Zeek Observations Import",
    "description": "Import selected Zeek records with timestamps, connection/Community IDs and capture provenance.",
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Accepts native JSON/JSONL and typed Zeek ASCII logs, including escaped/unset fields. Preserves raw records,"
        " stream/sensor context, exact timestamps, UIDs, Community IDs, notices/signatures and capture references."
        " Reuses network-connection and pcap-metadata with a bundled network-observation template. UID selection"
        " omits the full source attachment when records are excluded. All observations remain unreviewed and"
        " non-IDS. No Zeek execution, capture access or network calls. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/zeek_import.md)."
    ),
    "references": ["https://docs.zeek.org/en/stable/logs/index.html"],
    "input": "Base64-encoded UTF-8 Zeek JSON/JSONL or ASCII log; JSON requires explicit stream context.",
    "output": "Source file, network-observation, network-connection and optional pcap-metadata objects.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        request = loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an import request object.")
        return import_observations(request, "zeek")
    except (
        ValueError,
        TypeError,
        UnicodeError,
        binascii.Error,
        PyMISPError,
        InvalidOperation,
        RecursionError,
        OverflowError,
    ) as error:
        return {"error": f"Unable to import Zeek observations: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "format": {"type": "String", "message": "auto (default), json, jsonl or tsv"},
            "log_type": {
                "type": "String",
                "message": "Stream such as conn/dns/http/ssl/notice; required without native #path or explicit _path",
            },
            "timestamp_unit": {
                "type": "String",
                "message": "Numeric JSON time unit: s (default), ms, us or ns; TSV always uses seconds",
            },
            "sensor": {"type": "String", "message": "Optional source sensor identity"},
            "tool_version": {"type": "String", "message": "Optional producing Zeek version"},
            "capture_file": {"type": "String", "message": "Optional source capture reference; never opened"},
            "capture_sha256": {
                "type": "String",
                "message": "Optional producer-supplied capture SHA-256, distinct from log hash",
            },
            "capture_url": {"type": "String", "message": "Optional capture/investigation URL; never fetched"},
            "uids": {
                "type": "String",
                "message": "Optional comma-separated UIDs to retain; default includes all supplied records",
            },
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
