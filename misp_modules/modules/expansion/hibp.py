# -*- coding: utf-8 -*-
import json

import requests

misperrors = {"error": "Error"}
mispattributes = {"input": ["email-dst", "email-src"], "output": ["text"]}
moduleinfo = {
    "version": "0.2",
    "author": "Corsin Camichel, Aurélien Schwab",
    "description": "Module to access haveibeenpwned.com API.",
    "module-type": ["hover"],
    "name": "Have I Been Pwned Lookup",
    "logo": "hibp.png",
    "requirements": [],
    "features": (
        "The module takes an email address as input and queries haveibeenpwned.com API to find additional information"
        " about it. This additional information actually tells if any account using the email address has already been"
        " compromised in a data breach."
    ),
    "references": ["https://haveibeenpwned.com/"],
    "input": "An email address",
    "output": "Additional information about the email address.",
}
moduleconfig = ["api_key"]

haveibeenpwned_api_url = "https://haveibeenpwned.com/api/v3/breachedaccount/"
API_KEY = ""  # details at https://www.troyhunt.com/authentication-and-the-have-i-been-pwned-api/


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    for input_type in mispattributes["input"]:
        if input_type in request:
            email = request[input_type]
            break
    else:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors

    if request.get("config") is None or request["config"].get("api_key") is None:
        misperrors["error"] = "Have I Been Pwned authentication is incomplete (no API key)"
        return misperrors
    else:
        API_KEY = request["config"].get("api_key")

    r = requests.get(haveibeenpwned_api_url + email, headers={"hibp-api-key": API_KEY})
    if r.status_code == 200:
        breaches = json.loads(r.text)
        if breaches:
            return {"results": [{"types": mispattributes["output"], "values": breaches}]}
    elif r.status_code == 404:
        return {"results": [{"types": mispattributes["output"], "values": "OK (Not Found)"}]}
    else:
        misperrors["error"] = f"haveibeenpwned.com API not accessible (HTTP {str(r.status_code)})"
        return misperrors["error"]


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
