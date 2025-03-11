# -*- coding: utf-8 -*-

import json

from pyeupi import PyEUPI

misperrors = {"error": "Error"}
mispattributes = {"input": ["hostname", "domain", "url"], "output": ["freetext"]}
moduleinfo = {
    "version": "0.1",
    "author": "Raphaël Vinot",
    "description": "A module to query the Phishing Initiative service (https://phishing-initiative.lu).",
    "module-type": ["expansion", "hover"],
    "name": "EUPI Lookup",
    "logo": "eupi.png",
    "requirements": [
        "pyeupi: eupi python library",
        "An access to the Phishing Initiative API (apikey & url)",
    ],
    "features": (
        "This module takes a domain, hostname or url MISP attribute as input to query the Phishing Initiative API. The"
        " API returns then the result of the query with some information about the value queried.\n\nPlease note that"
        " composite attributes containing domain or hostname are also supported."
    ),
    "references": ["https://phishing-initiative.eu/?lang=en"],
    "input": "A domain, hostname or url MISP attribute.",
    "output": "Text containing information about the input, resulting from the query on Phishing Initiative.",
}

moduleconfig = ["apikey", "url"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get("hostname"):
        toquery = request["hostname"]
    elif request.get("domain"):
        toquery = request["domain"]
    elif request.get("url"):
        toquery = request["url"]
    else:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors

    if not request.get("config") and not (request["config"].get("apikey") and request["config"].get("url")):
        misperrors["error"] = "EUPI authentication is missing"
        return misperrors

    pyeupi = PyEUPI(request["config"]["apikey"], request["config"]["url"])

    if "event_id" in request:
        return handle_expansion(pyeupi, toquery)
    else:
        return handle_hover(pyeupi, toquery)


def handle_expansion(pyeupi, url):
    results = pyeupi.search_url(url=url)

    if results.get("results"):
        to_return = ""
        for r in results["results"]:
            if r["tag_label"] != "phishing":
                continue
            to_return += " {} {} {} ".format(r["url"], r["domain"], r["ip_address"])
        if to_return:
            return {"results": [{"types": mispattributes["output"], "values": to_return}]}
        else:
            misperrors["error"] = "Unknown in the EUPI service"
            return misperrors
    else:
        return {"results": [{"types": mispattributes["output"], "values": ""}]}


def handle_hover(pyeupi, url):
    try:
        result = pyeupi.lookup(url=url)["results"][0]
    except (KeyError, IndexError):
        misperrors["error"] = "Error in EUPI lookup"
        return misperrors

    return {"results": [{"types": mispattributes["output"], "values": result["tag_label"].title()}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
