import json
from urllib.parse import quote

from pyintel471 import PyIntel471
from requests.exceptions import RequestException

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "hostname",
        "domain",
        "url",
        "ip-src",
        "ip-dst",
        "email-src",
        "email-dst",
        "target-email",
        "whois-registrant-email",
        "whois-registrant-name",
        "md5",
        "sha1",
        "sha256",
    ],
    "output": ["freetext"],
}
moduleinfo = {
    "version": "0.2",
    "author": "Raphaël Vinot",
    "description": "Module to access Intel 471",
    "module-type": ["hover", "expansion"],
    "name": "Intel471 Lookup",
    "logo": "intel471.png",
    "requirements": ["The intel471 python library"],
    "features": (
        "The module uses the Intel471 python library to query /v1/search with the value of the input attribute"
        " as global search text. This includes results from reports, malware intelligence, sources and news"
        " available to the account. Results are returned as freetext so the Freetext import parses them."
    ),
    "references": ["https://public.intel471.com/"],
    "input": (
        "A MISP attribute whose type is included in the following list:\n- hostname\n- domain\n- url\n- ip-src\n-"
        " ip-dst\n- email-src\n- email-dst\n- target-email\n- whois-registrant-email\n- whois-registrant-name\n- md5\n-"
        " sha1\n- sha256"
    ),
    "output": "Freetext",
    "descrption": (
        "An expansion module to query Intel471 in order to get additional information about a domain, ip address, email"
        " address, url or hash."
    ),
}
moduleconfig = ["email", "authkey"]


def cleanup(response):
    """Remove internal UIDs from every collection so they are not imported as hashes."""
    j = response.json(object_hook=lambda obj: {key: value for key, value in obj.items() if key != "uid"})
    if not isinstance(j, dict):
        raise ValueError("Invalid Intel 471 search response")
    # Global search can return indicators, reports, news, etc. even when iocTotalCount is zero.
    if not any(isinstance(value, list) and value for value in j.values()):
        return "Nothing has been found."
    return json.dumps(j, indent=2)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    for input_type in mispattributes["input"]:
        if input_type in request:
            to_query = request[input_type]
            break
    else:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors

    config = request.get("config") or {}
    if not config.get("email") or not config.get("authkey"):
        return {"error": "Intel 471 authentication is missing"}

    intel471 = PyIntel471(email=config["email"], authkey=config["authkey"])
    # PyIntel471 interpolates filter values without URL encoding.
    search_filters = intel471.search_filters(text=quote(to_query, safe=""))
    try:
        res = intel471.search(filters=search_filters)
        res.raise_for_status()
        to_return = cleanup(res)
    except RequestException:
        return {"error": "Intel 471 API request failed"}
    except ValueError:
        return {"error": "Invalid Intel 471 search response"}

    r = {"results": [{"types": mispattributes["output"], "values": to_return}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
