import base64
import json

misperrors = {"error": "Error"}
userConfig = {}

inputSource = ["file"]

moduleinfo = {
    "version": "0.1",
    "author": "Richard van den Berg",
    "description": "Module to import MISP JSON format for merging MISP events.",
    "module-type": ["import"],
    "name": "MISP JSON Import",
    "logo": "",
    "requirements": [],
    "features": (
        "The module simply imports MISP Attributes from an other MISP Event in order to merge events together. There is"
        " thus no special feature to make it work."
    ),
    "references": [],
    "input": "MISP Event",
    "output": "MISP Event attributes",
}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    r = {"results": []}
    request = json.loads(q)
    try:
        mfile = base64.b64decode(request["data"]).decode("utf-8")
        misp = json.loads(mfile)
        event = misp["response"][0]["Event"]
        for a in event["Attribute"]:
            tmp = {}
            tmp["values"] = a["value"]
            tmp["categories"] = a["category"]
            tmp["types"] = a["type"]
            tmp["to_ids"] = a["to_ids"]
            tmp["comment"] = a["comment"]
            if a.get("data"):
                tmp["data"] = a["data"]
            r["results"].append(tmp)
    except Exception:
        pass
    return r


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
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


if __name__ == "__main__":
    x = open("test.json", "r")
    r = handler(q=x.read())
    print(json.dumps(r))
