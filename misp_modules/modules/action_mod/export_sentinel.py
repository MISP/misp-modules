"""Microsoft Sentinel direct publishing or the existing MISP2* script wrapper."""

import copy
import json
import os
import subprocess

from misp_modules.modules.action_mod import sentinel_publish

DEFAULT_VENV = "/var/www/MISP/misp-custom/misp2sentinel/venv/"
DEFAULT_SCRIPT = "/var/www/MISP/misp-custom/misp2sentinel/script.py"
moduleconfig = {
    "params": {
        "mode": {
            "type": "string",
            "description": "wrapper (existing MISP2Sentinel/MISP2Defender) or direct (Sentinel STIX API)",
            "value": "wrapper",
        },
        "misp2_venv": {
            "type": "string",
            "description": "MISP2Sentinel or MISP2Defender Python virtual environment",
            "value": DEFAULT_VENV,
        },
        "misp2_script": {
            "type": "string",
            "description": "MISP2Sentinel or MISP2Defender script path",
            "value": DEFAULT_SCRIPT,
        },
        **copy.deepcopy(sentinel_publish.moduleconfig["params"]),
    },
    "blocking": False,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"
moduleinfo = {
    "version": "0.2",
    "author": "Koen Van Impe, MISP Project",
    "description": (
        "Export to Sentinel or Defender using the existing script wrapper, or directly to Sentinel's STIX API."
    ),
    "module-type": ["action"],
    "name": "Export to Sentinel or Defender",
    "logo": "",
    "requirements": ["requests", "MISP2Sentinel/MISP2Defender for wrapper mode, or Entra credentials for direct mode"],
    "features": (
        "Preserves wrapper mode and its boolean success response by default. Direct mode publishes supplied IDS"
        " attributes to Microsoft Sentinel without an external script, using the same implementation as"
        " sentinel_publish. Filtered/extracted payloads are rejected because neither path applies workflow filters. See"
        " the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/sentinel_publish.md)."
    ),
    "references": [
        "https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api",
        "https://github.com/cudeso/misp2sentinel",
    ],
    "input": "An event UUID in wrapper mode, or supplied MISP events/object attributes in direct mode.",
    "output": "Boolean wrapper success, or a direct publishing summary with per-indicator outcomes.",
}


def _paths(params):
    venv = params.get("misp2_venv")
    script = params.get("misp2_script")
    if venv is None or venv == "":
        venv = DEFAULT_VENV
    if script is None or script == "":
        script = DEFAULT_SCRIPT
    if not isinstance(venv, str) or not isinstance(script, str) or not os.path.isabs(venv) or not os.path.isabs(script):
        raise ValueError("Wrapper virtual-environment and script paths must be absolute.")
    if "\x00" in venv or "\x00" in script:
        raise ValueError("Wrapper paths must not contain NUL characters.")
    return os.path.join(venv, "bin", "python"), script


def export_to_sentinel(request, event_uuid):
    """Keep the existing wrapper helper's boolean contract without logging secrets."""
    try:
        python, script = _paths(request.get("params", {}))
        if not os.path.isfile(python) or not os.path.isfile(script):
            return False
        result = subprocess.run(
            [python, script, event_uuid],
            cwd=os.path.dirname(script),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=240,
            check=False,
        )
        return result.returncode == 0
    except (ValueError, TypeError, OSError, subprocess.SubprocessError):
        return False


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        if "filteredItems" in request or "matchingData" in request:
            raise ValueError("Workflow filters/extracted data are unsupported; select the intended events upstream.")
        params = request.get("params", {})
        if not isinstance(params, dict):
            raise ValueError("params must be an object.")
        mode = params.get("mode")
        if mode is None or mode == "":
            mode = "wrapper"
        if mode == "direct":
            return sentinel_publish.handler(q)
        if mode != "wrapper":
            raise ValueError("mode must be wrapper or direct.")
        if sentinel_publish._boolean(params.get("dry_run")):
            raise ValueError("dry_run is available in direct mode; wrapper mode runs the configured script.")
        data = request.get("data")
        if not isinstance(data, dict) or not isinstance(event := data.get("Event", data), dict):
            raise ValueError("Wrapper mode requires one event; use direct mode for event collections.")
        identifier = sentinel_publish._uuid(event.get("uuid"), "event UUID")
        _paths(params)
    except (ValueError, TypeError) as exc:
        return {"data": False, "error": f"Sentinel/Defender export: {exc}"}
    success = export_to_sentinel(request, identifier)
    if not success:
        return {
            "data": False,
            "error": "Sentinel/Defender wrapper failed, timed out or is unavailable; check its installation and logs.",
        }
    return {"data": True}


def introspection():
    return {"config": moduleconfig}


def version():
    return dict(moduleinfo, config=moduleconfig)
