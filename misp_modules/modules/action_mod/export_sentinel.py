import json
import os
import subprocess
from uuid import UUID

"""
    Synchronise with Microsoft Sentinel or Defender: A wrapper around an existing installation of MISP2Sentinel or MISP2Defender

    Calls the script configured by EXPORT_SENTINEL_SCRIPT using the virtual environment EXPORT_SENTINEL_VENV.
    These settings belong to the module server environment, never to a workflow request.
    Uses the event UUID from the MISP event to export the indicators
    Preferably run as Ad-Hoc workflow
"""

misperrors = {"error": "Error"}

moduleconfig = {
    "params": {},
    # Blocking modules break the exection of the current of action
    "blocking": False,
    # Indicates whether parts of the data passed to this module should be extracted. Extracted data can be found under the `filteredItems` key
    "support_filters": True,
    # Indicates whether the data passed to this module should be compliant with the MISP core format
    "expect_misp_core_format": False,
}

returns = "boolean"

moduleinfo = {
    "version": "0.2",
    "author": "Koen Van Impe",
    "description": (
        "Export indicators to Microsoft Sentinel or Microsoft Defender. Requires an existing installation of"
        " MISP2Sentinel or MISP2Defender."
    ),
    "module-type": ["action"],
    "name": "Export to Sentinel or Defender",
    "logo": "",
    "requirements": [],
    "features": (
        "The module server must set EXPORT_SENTINEL_VENV and EXPORT_SENTINEL_SCRIPT. Workflow paths are not accepted."
    ),
    "references": [],
    "input": "",
    "output": "",
}


def export_to_sentinel(event_uuid):
    if not isinstance(event_uuid, str):
        print("Error: Event UUID must be a UUID string")
        return False
    try:
        event_uuid = str(UUID(event_uuid))
    except ValueError:
        print("Error: Invalid event UUID")
        return False

    misp2_venv = os.getenv("EXPORT_SENTINEL_VENV", "")
    misp2_script = os.getenv("EXPORT_SENTINEL_SCRIPT", "")
    if not os.path.isabs(misp2_venv) or not os.path.isabs(misp2_script):
        print("Error: Set absolute EXPORT_SENTINEL_VENV and EXPORT_SENTINEL_SCRIPT paths on the module server")
        return False

    script_dir = os.path.dirname(misp2_script)
    python_executable = os.path.join(misp2_venv, "bin", "python")

    if not os.path.isfile(python_executable) or not os.access(python_executable, os.X_OK):
        print(f"Error: Python executable missing or not executable at {python_executable}")
        return False

    if not os.path.isfile(misp2_script) or not os.access(misp2_script, os.R_OK):
        print(f"Error: Script missing or not readable at {misp2_script}")
        return False

    print(f"Exporting event {event_uuid} to Sentinel or Defender...")
    print(f"Using Python: {python_executable}")
    print(f"Running script: {misp2_script}")
    print(f"Working directory: {script_dir}")

    try:
        result = subprocess.run(
            [python_executable, misp2_script, event_uuid],
            cwd=script_dir,
            capture_output=True,
            text=True,
            timeout=300,
            shell=False,
        )

        if result.returncode == 0:
            print(f"Successfully exported event {event_uuid}")
            if result.stdout:
                print(f"Output: {result.stdout}")
            return True
        else:
            print(f"Export failed with return code {result.returncode}")
            if result.stderr:
                print(f"Error: {result.stderr}")
            if result.stdout:
                print(f"Output: {result.stdout}")
            return False

    except subprocess.TimeoutExpired:
        print("Export timed out")
        return False
    except Exception as e:
        print(f"Error executing script: {str(e)}")
        return False


def handler(q=False):
    if q is False:
        return False

    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"data": False}
    if not isinstance(request, dict):
        return {"data": False}

    for key in ("params", "config"):
        settings = request.get(key, {})
        if not isinstance(settings, dict):
            return {"data": False}
        if {"misp2_venv", "misp2_script"}.intersection(settings):
            print("Error: Workflow paths are no longer supported; configure the module server environment")
            return {"data": False}

    success = False

    data = request.get("data", {})
    if not isinstance(data, dict) or not isinstance(data.get("Event", {}), dict):
        return {"data": False}
    event_uuid = data.get("Event", {}).get("uuid")
    if event_uuid:
        success = export_to_sentinel(event_uuid)
    else:
        print("Error: No event UUID found in request data")

    return {"data": success}


def introspection():
    modulesetup = {}
    try:
        modulesetup["config"] = moduleconfig
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
