import json

import requests

misperrors = {"error": "Error"}
mispattributes = {"input": ["mac-address"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Aurélien Schwab",
    "description": "Module to access Macvendors API.",
    "module-type": ["hover"],
    "name": "Macvendors Lookup",
    "logo": "macvendors.png",
    "requirements": [],
    "features": (
        "The module takes a MAC address as input and queries macvendors.com for some information about it. The API"
        " returns the name of the vendor related to the address."
    ),
    "references": ["https://macvendors.com/", "https://macvendors.com/api"],
    "input": "A MAC address.",
    "output": "Additional information about the MAC address.",
}
moduleconfig = ["user-agent"]

macvendors_api_url = "https://api.macvendors.com/"
default_user_agent = "MISP-Module"


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    for input_type in mispattributes["input"]:
        if input_type in request:
            mac = request[input_type]
            break
    else:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors
    user_agent = (
        request["config"]["user-agent"]
        if request.get("config") and request["config"].get("user-agent")
        else default_user_agent
    )
    r = requests.get(macvendors_api_url + mac, headers={"user-agent": user_agent})  # Real request
    if r.status_code == 200:  # OK (record found)
        response = r.text
        if response:
            return {"results": [{"types": mispattributes["output"], "values": response}]}
    elif r.status_code == 404:  # Not found (not an error)
        return {"results": [{"types": mispattributes["output"], "values": "Not found"}]}
    else:  # Real error
        misperrors["error"] = "MacVendors API not accessible (HTTP " + str(r.status_code) + ")"
        return misperrors["error"]


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
