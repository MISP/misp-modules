import json

import requests

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5"], "output": ["text"]}
moduleinfo = {
    "version": "0.2",
    "author": "Alexandre Dulaunoy",
    "description": "A hover module to check hashes against hashdd.com including NSLR dataset.",
    "module-type": ["hover"],
    "name": "Hashdd Lookup",
    "logo": "",
    "requirements": [],
    "features": (
        "This module takes a hash attribute as input to check its known level, using the hashdd API. This information"
        " is then displayed."
    ),
    "references": ["https://hashdd.com/"],
    "input": "A hash MISP attribute (md5).",
    "output": "Text describing the known level of the hash in the hashdd databases.",
}
moduleconfig = []
hashddapi_url = "https://api.hashdd.com/v1/knownlevel/nsrl/"


def handler(q=False):
    if q is False:
        return False
    v = None
    request = json.loads(q)
    for input_type in mispattributes["input"]:
        if request.get(input_type):
            v = request[input_type].upper()
            break
    if v is None:
        misperrors["error"] = "Hash value is missing."
        return misperrors
    r = requests.get(hashddapi_url + v)
    if r.status_code == 200:
        state = json.loads(r.text)
        summary = state["knownlevel"] if state and state["result"] == "SUCCESS" else state["message"]
    else:
        misperrors["error"] = "{} API not accessible".format(hashddapi_url)
        return misperrors["error"]

    r = {"results": [{"types": mispattributes["output"], "values": summary}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
