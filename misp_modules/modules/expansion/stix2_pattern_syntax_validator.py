import json

from stix2patterns.validator import run_validator

misperrors = {"error": "Error"}
mispattributes = {"input": ["stix2-pattern"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Christian Studer",
    "module-type": ["hover"],
    "name": "STIX2 Pattern Syntax Validator",
    "description": "An expansion hover module to perform a syntax check on stix2 patterns.",
    "logo": "stix.png",
    "requirements": ["stix2patterns python library"],
    "features": (
        "This module takes a STIX2 pattern attribute as input and performs a syntax check on it.\n\nIt displays then"
        " that the rule is valid if it is the case, and the error related to the rule otherwise."
    ),
    "references": [
        "[STIX2.0 patterning"
        " specifications](http://docs.oasis-open.org/cti/stix/v2.0/cs01/part5-stix-patterning/stix-v2.0-cs01-part5-stix-patterning.html)"
    ],
    "input": "A STIX2 pattern attribute.",
    "output": "Text describing the validity of the STIX2 pattern.",
}
moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("stix2-pattern"):
        misperrors["error"] = "STIX2 pattern missing"
        return misperrors
    pattern = request.get("stix2-pattern")
    syntax_errors = []
    for p in pattern[1:-1].split(" AND "):
        syntax_validator = run_validator("[{}]".format(p))
        if syntax_validator:
            for error in syntax_validator:
                syntax_errors.append(error)
    if syntax_errors:
        s = "s" if len(syntax_errors) > 1 else ""
        s_errors = ""
        for error in syntax_errors:
            s_errors += "{}\n".format(error[6:])
        result = "Syntax error{}: \n{}".format(s, s_errors[:-1])
    else:
        result = "Syntax valid"
    return {"results": [{"types": mispattributes["output"], "values": result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
