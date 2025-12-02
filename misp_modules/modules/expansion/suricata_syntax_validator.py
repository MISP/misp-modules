import json
from suricataparser import parse_rule

misperrors = {"error": "Error"}
mispattributes = {"input": ["suricata"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Theo Geffe",
    "module-type": ["expansion", "hover"],
    "name": "Suricata Syntax Validator",
    "description": "An expansion hover module to perform a syntax check on Suricata IDS/IPS rules.",
    "logo": "suricata.png",
    "requirements": ["suricataparser python library"],
    "features": (
        "This module takes a Suricata rule attribute as input and performs a syntax validation on it.\n\n"
        "It displays whether the rule is valid, or the parser error if the rule contains syntax issues."
    ),
    "references": [
        "https://suricata.readthedocs.io/",
        "https://github.com/OISF/suricataparser"
    ],
    "input": "A Suricata rule as a text attribute.",
    "output": "Text describing the validity of the Suricata rule.",
}
moduleconfig = []


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    if not request.get("suricata"):
        misperrors["error"] = "Suricata rule missing"
        return misperrors

    rule_text = request.get("suricata")

    try:
        parsed = parse_rule(rule_text)

        result = f"Syntax valid: {parsed}"
    except Exception as e:
        result = "Syntax error: {}".format(str(e))

    return {"results": [{"types": mispattributes["output"], "values": result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo