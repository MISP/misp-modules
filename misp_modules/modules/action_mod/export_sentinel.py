import json
import subprocess
import os

'''
    Synchronise with Microsoft Sentinel or Defender: A wrapper around an existing installation of MISP2Sentinel or MISP2Defender

    Calls the script from MISP2Sentinel or MISP2Defender (misp2_script) using the Python virtual environment (misp2_venv)
    Uses the event UUID from the MISP event to export the indicators
    Preferably run as Ad-Hoc workflow
'''

misperrors = {"error": "Error"}

moduleconfig = {
    "params": {
        "misp2_venv": {"type": "string", "description": "Where is the MISP2Sentinel or MISP2Defender Python virtual environment?", "value": "/var/www/MISP/misp-custom/misp2sentinel/venv/"},
        "misp2_script": {"type": "string", "description": "Where is the MISP2Sentinel or MISP2Defender installation?", "value": "/var/www/MISP/misp-custom/misp2sentinel/script.py"},
    },
    # Blocking modules break the exection of the current of action
    "blocking": False,
    # Indicates whether parts of the data passed to this module should be extracted. Extracted data can be found under the `filteredItems` key
    "support_filters": True,
    # Indicates whether the data passed to this module should be compliant with the MISP core format
    "expect_misp_core_format": False,
}

returns = "boolean"

moduleinfo = {
    "version": "0.1",
    "author": "Koen Van Impe",
    "description": "Export indicators to Microsoft Sentinel or Microsoft Defender. Requires an existing installation of MISP2Sentinel or MISP2Defender.",
    "module-type": ["action"],
    "name": "Export to Sentinel or Defender",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}


def export_to_sentinel(request, event_uuid):
    params = request["params"]
    misp2_venv = params["misp2_venv"]
    misp2_script = params["misp2_script"]

    script_dir = os.path.dirname(misp2_script)
    python_executable = os.path.join(misp2_venv, "bin", "python")

    if not os.path.exists(python_executable):
        print(f"Error: Python executable not found at {python_executable}")
        return False

    if not os.path.exists(misp2_script):
        print(f"Error: Script not found at {misp2_script}")
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
            timeout=300
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

    request = json.loads(q)
    success = False

    event_uuid = request.get("data", {}).get("Event", {}).get("uuid")
    if event_uuid:
        success = export_to_sentinel(request, event_uuid)
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
