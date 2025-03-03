# -*- coding: utf-8 -*-
"""Backscatter.io Module."""
import json

from backscatter import Backscatter

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst"], "output": ["freetext"]}
moduleinfo = {
    "version": "1",
    "author": "brandon@backscatter.io",
    "description": "Backscatter.io module to bring mass-scanning observations into MISP.",
    "module-type": ["expansion", "hover"],
    "name": "Backscatter.io",
    "logo": "backscatter_io.png",
    "requirements": ["backscatter python library"],
    "features": (
        "The module takes a source or destination IP address as input and displays the information known by"
        " backscatter.io."
    ),
    "references": ["https://pypi.org/project/backscatter/"],
    "input": "IP addresses.",
    "output": (
        "Text containing a history of the IP addresses especially on scanning based on backscatter.io information ."
    ),
}
moduleconfig = ["api_key"]
query_playbook = [
    {
        "inputs": ["ip-src", "ip-dst"],
        "services": ["observations", "enrichment"],
        "name": "generic",
    }
]


def check_query(request):
    """Check the incoming request for a valid configuration."""
    output = {"success": False}
    config = request.get("config", None)
    if not config:
        misperrors["error"] = "Configuration is missing from the request."
        return output
    for item in moduleconfig:
        if config.get(item, None):
            continue
        misperrors["error"] = "Backscatter.io authentication is missing."
        return output
    if not request.get("ip-src") and request.get("ip-dst"):
        misperrors["error"] = "Unsupported attributes type."
        return output
    profile = {"success": True, "config": config, "playbook": "generic"}
    if "ip-src" in request:
        profile.update({"value": request.get("ip-src")})
    else:
        profile.update({"value": request.get("ip-dst")})
    return profile


def handler(q=False):
    """Handle gathering data."""
    if not q:
        return q
    request = json.loads(q)
    checks = check_query(request)
    if not checks["success"]:
        return misperrors

    try:
        bs = Backscatter(checks["config"]["api_key"])
        response = bs.get_observations(query=checks["value"], query_type="ip")
        if not response["success"]:
            misperrors["error"] = "%s: %s" % (response["error"], response["message"])
            return misperrors
        output = {"results": [{"types": mispattributes["output"], "values": [str(response)]}]}
    except Exception as e:
        misperrors["error"] = str(e)
        return misperrors

    return output


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
