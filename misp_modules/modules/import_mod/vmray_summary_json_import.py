import json

from _vmray.parser import VMRayParseError, VMRayParser

misperrors = {"error": "Error"}

moduleconfig = ["disable_tags"]

moduleinfo = {
    "version": "0.1",
    "author": "VMRay",
    "description": "Import a VMRay Summary JSON report.",
    "module-type": ["import"],
    "name": "VMRay Summary JSON Import",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}

mispattributes = {
    "inputSource": ["file"],
    "output": ["MISP objects", "MISP attributes"],
    "format": "misp_standard",
}

user_config = {
    "Analysis ID": {
        "type": "Boolean",
        "message": "Include Analysis ID",
        "checked": "True",
    },
    "VTI": {
        "type": "Boolean",
        "message": "Include VMRay Threat Identifiers",
        "checked": "True",
    },
    "IOCs": {"type": "Boolean", "message": "Include IOCs", "checked": "True"},
    "Artifacts": {
        "type": "Boolean",
        "message": "Include other Artifacts",
    },
    "Analysis Details": {
        "type": "Boolean",
        "message": "Include Analysis Details",
    },
    "Attach Report": {
        "type": "Boolean",
        "message": "Include the original imported file as attachment",
    },
}


def handler(q=False):
    # In case there's no data
    if q is False:
        return False

    q = json.loads(q)

    parser = VMRayParser()
    try:
        parser.from_base64_string(q["config"], q["data"], q["filename"])
        parser.parse()
    except VMRayParseError as exc:
        misperrors["error"] = str(exc)
        return misperrors

    event = parser.to_json()
    return event


def introspection():
    mispattributes["userConfig"] = user_config
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
