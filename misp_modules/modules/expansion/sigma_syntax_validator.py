import json

import yaml
from sigma.configuration import SigmaConfiguration
from sigma.parser.rule import SigmaParser

misperrors = {"error": "Error"}
mispattributes = {"input": ["sigma"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Christian Studer",
    "module-type": ["expansion", "hover"],
    "name": "Sigma Syntax Validator",
    "description": "An expansion hover module to perform a syntax check on sigma rules.",
    "logo": "sigma.png",
    "requirements": ["Sigma python library", "Yaml python library"],
    "features": (
        "This module takes a Sigma rule attribute as input and performs a syntax check on it.\n\nIt displays then that"
        " the rule is valid if it is the case, and the error related to the rule otherwise."
    ),
    "references": ["https://github.com/Neo23x0/sigma/wiki"],
    "input": "A Sigma attribute.",
    "output": "Text describing the validity of the Sigma rule.",
}
moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("sigma"):
        misperrors["error"] = "Sigma rule missing"
        return misperrors
    config = SigmaConfiguration()
    try:
        parser = SigmaParser(yaml.safe_load(request.get("sigma")), config)
        result = "Syntax valid: {}".format(parser.values)
    except Exception as e:
        result = "Syntax error: {}".format(str(e))
    return {"results": [{"types": mispattributes["output"], "values": result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
