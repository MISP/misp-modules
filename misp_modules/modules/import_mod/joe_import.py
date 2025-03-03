# -*- coding: utf-8 -*-
import base64
import json

from joe_parser import JoeParser

misperrors = {"error": "Error"}
userConfig = {
    "Import Executable": {
        "type": "Boolean",
        "message": "Import Executable Information (PE, elf or apk for instance)",
    },
    "Mitre Att&ck": {
        "type": "Boolean",
        "message": "Import Mitre Att&ck techniques",
    },
}

inputSource = ["file"]

moduleinfo = {
    "version": "0.2",
    "author": "Christian Studer",
    "description": "A module to import data from a Joe Sandbox analysis json report.",
    "module-type": ["import"],
    "name": "Joe Sandbox Import",
    "logo": "joesandbox.png",
    "requirements": [],
    "features": (
        "Module using the new format of modules able to return attributes and objects.\n\nThe module returns the same"
        " results as the expansion module"
        " [joesandbox_query](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/joesandbox_query.py)"
        " using the submission link of the analysis to get the json report."
    ),
    "references": ["https://www.joesecurity.org", "https://www.joesandbox.com/"],
    "input": "Json report of a Joe Sandbox analysis.",
    "output": "MISP attributes & objects parsed from the analysis report.",
}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    config = {
        "import_executable": bool(int(q["config"]["Import Executable"])),
        "mitre_attack": bool(int(q["config"]["Mitre Att&ck"])),
    }

    data = base64.b64decode(q.get("data")).decode("utf-8")
    if not data:
        return json.dumps({"success": 0})

    joe_parser = JoeParser(config)
    joe_parser.parse_data(json.loads(data)["analysis"])
    joe_parser.finalize_results()
    return {"results": joe_parser.results}


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup["inputSource"] = inputSource
    except NameError:
        pass
    modulesetup["format"] = "misp_standard"
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
