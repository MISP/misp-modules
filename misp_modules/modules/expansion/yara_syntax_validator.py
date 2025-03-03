import json

import yara

misperrors = {"error": "Error"}
mispattributes = {"input": ["yara"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Dennis Rand",
    "description": "An expansion hover module to perform a syntax check on if yara rules are valid or not.",
    "module-type": ["hover"],
    "name": "YARA Syntax Validator",
    "logo": "yara.png",
    "requirements": ["yara_python python library"],
    "features": (
        "This modules simply takes a YARA rule as input, and checks its syntax. It returns then a confirmation if the"
        " syntax is valid, otherwise the syntax error is displayed."
    ),
    "references": ["http://virustotal.github.io/yara/"],
    "input": "YARA rule attribute.",
    "output": "Text to inform users if their rule is valid.",
}
moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("yara"):
        misperrors["error"] = "Yara rule missing"
        return misperrors

    try:
        yara.compile(source=request.get("yara"))
        summary = "Syntax valid"
    except Exception as e:
        summary = "Syntax error: " + str(e)

    r = {"results": [{"types": mispattributes["output"], "values": summary}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
