"""Import selected Suricata EVE evidence without executing the IDS engine."""

import binascii
from decimal import InvalidOperation

from pymisp.exceptions import PyMISPError

from misp_modules.lib.network_observation import import_observations, loads

moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Suricata EVE Observations Import",
    "description": (
        "Import selected Suricata EVE findings with timestamps, flow/Community IDs, signatures and capture references."
    ),
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Accepts native EVE JSON/JSONL, preserving flow/packet/transaction IDs, alert SID/GID/revision/message,"
        " severity, action, sensor/capture context and raw protocol records. Reuses network-connection and"
        " pcap-metadata with a bundled network-observation template. Event-type/flow-ID selection omits the full"
        " attachment when records are excluded. Sensor alerts remain unreviewed observations, not confirmed malicious"
        " findings. All attributes are non-IDS and non-correlating. No Suricata execution, capture access or network"
        " calls. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/suricata_import.md)."
    ),
    "references": ["https://docs.suricata.io/en/latest/output/eve/eve-json-format.html"],
    "input": "Base64-encoded UTF-8 EVE JSON/JSONL, optionally selected by event type or flow ID.",
    "output": "Source file, network-observation, network-connection and optional pcap-metadata objects.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        request = loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an import request object.")
        return import_observations(request, "suricata")
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
        return {"error": f"Unable to import Suricata observations: {error}"}


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "format": {"type": "String", "message": "auto (default), json or jsonl"},
            "sensor": {"type": "String", "message": "Optional sensor default when native EVE host is absent"},
            "tool_version": {"type": "String", "message": "Optional producing Suricata version"},
            "capture_file": {
                "type": "String",
                "message": "Optional capture default when native pcap_filename is absent; never opened",
            },
            "capture_sha256": {
                "type": "String",
                "message": "Optional producer-supplied capture SHA-256, distinct from log hash",
            },
            "capture_url": {"type": "String", "message": "Optional capture/investigation URL; never fetched"},
            "event_types": {
                "type": "String",
                "message": "Optional comma-separated event types, e.g. alert,flow,dns; default all supplied",
            },
            "flow_ids": {"type": "String", "message": "Optional comma-separated unsigned 64-bit flow IDs to retain"},
        },
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
