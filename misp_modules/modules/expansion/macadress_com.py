import json

import requests

misperrors = {"error": "Error"}

mispattributes = {"input": ["mac-address"], "output": ["text"]}

moduleinfo = {
    "version": "1.0",
    "author": "Samy Massoud",
    "description": "Module to access macadress.com API.",
    "module-type": ["hover"],
    "name": "macadress.com Lookup",
    "logo": "macadress_com.png",
    "requirements": ["An access to the macadress.com API (apikey)"],
    "features": (
        "This module takes a MAC address attribute as input and queries macadress.com for additional"
        " information.\n\nThis information contains data about:\n- Vendor identity (organization, OUI, matched"
        " registry prefix, country)\n- Device category inference\n- Virtualization/container-network detection\n-"
        " Special-use address classification (broadcast, multicast, VRRP, HSRP, STP, LACP, 802.1X, LLDP)\n-"
        " Randomization confidence (locally administered / SLAP quadrant signals)"
    ),
    "references": ["https://macadress.com/", "https://macadress.com/docs"],
    "input": "A MAC address.",
    "output": "Additional information about the MAC address.",
}

moduleconfig = ["api_key"]

macadress_api_url = "https://api.macadress.com/v1/mac/"
request_timeout = 15


def _get(dct, *path):
    cur = dct
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    if request.get("mac-address"):
        mac_address = request["mac-address"]
    else:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors

    if request.get("config") and request["config"].get("api_key"):
        api_key = request["config"]["api_key"]
    else:
        misperrors["error"] = "Authorization required"
        return misperrors

    try:
        r = requests.get(
            macadress_api_url + mac_address,
            headers={
                "Authorization": "Bearer " + api_key,
                "User-Agent": "MISP-Module (macadress.com)",
            },
            timeout=request_timeout,
        )
    except requests.exceptions.RequestException as exc:
        misperrors["error"] = "macadress.com API not accessible (%s)" % exc
        return misperrors

    if r.status_code == 401:
        misperrors["error"] = "Authorization required"
        return misperrors
    if r.status_code == 429:
        misperrors["error"] = "macadress.com quota or rate limit exceeded"
        return misperrors
    if r.status_code == 400:
        misperrors["error"] = "Invalid MAC address"
        return misperrors
    if r.status_code != 200:
        misperrors["error"] = "macadress.com API not accessible (HTTP %d)" % r.status_code
        return misperrors

    response = r.json()

    results = {
        "results": [
            {
                "types": mispattributes["output"],
                "values": {
                    "Valid MAC address": response.get("valid"),
                    "Registered": response.get("registered"),
                    "OUI": response.get("oui"),
                    "Matched prefix": response.get("matched_prefix"),
                    "Organization": response.get("organization"),
                    "Vendor country": response.get("country"),
                    "Block type": response.get("block_type"),
                    "Locally administered": response.get("locally_administered"),
                    "Administration type": response.get("administration_type"),
                    "Transmission type": response.get("transmission_type"),
                    "Potentially randomized": response.get("potentially_randomized"),
                    "Randomization confidence": response.get("randomization_confidence"),
                    "Device category": _get(response, "device", "category"),
                    "Device confidence": _get(response, "device", "confidence"),
                    "Virtualization platform": _get(response, "virtualization", "platform"),
                    "Special-use type": _get(response, "special_use", "type"),
                    "Explanation": response.get("explanation"),
                },
            }
        ]
    }

    return results


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
