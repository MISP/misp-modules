import json

import requests

misperrors = {"error": "Error"}
mispattributes = {"input": ["hostname", "domain"]}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "1",
    "author": "Hannah Ward",
    "description": "Module to expand country codes.",
    "module-type": ["hover"],
    "name": "Country Code",
    "logo": "",
    "requirements": [],
    "features": (
        "The module takes a domain or a hostname as input, and returns the country it belongs to.\n\nFor non country"
        " domains, a list of the most common possible extensions is used."
    ),
    "references": [],
    "input": "Hostname or domain attribute.",
    "output": "Text with the country code the input belongs to.",
}

# config fields that your code expects from the site admin
moduleconfig = []

common_tlds = {
    "com": "Commercial (Worldwide)",
    "org": "Organisation (Worldwide)",
    "net": "Network (Worldwide)",
    "int": "International (Worldwide)",
    "edu": "Education (Usually USA)",
    "gov": "Government (USA)",
}


def parse_country_code(extension):
    # Retrieve a json full of country info
    try:
        codes = requests.get("http://www.geognos.com/api/en/countries/info/all.json").json()
    except Exception:
        return "http://www.geognos.com/api/en/countries/info/all.json not reachable"
    if not codes.get("StatusMsg") or not codes["StatusMsg"] == "OK":
        return "Not able to get the countrycode references from http://www.geognos.com/api/en/countries/info/all.json"
    for country in codes["Results"].values():
        if country["CountryCodes"]["tld"] == extension:
            return country["Name"]
    return "Unknown"


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    domain = request["domain"] if "domain" in request else request["hostname"]

    # Get the extension
    ext = domain.split(".")[-1]

    # Check if it's a common, non country one
    val = common_tlds[ext] if ext in common_tlds.keys() else parse_country_code(ext)
    r = {"results": [{"types": ["text"], "values": [val]}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
