# -*- coding: utf-8 -*-
import json

import requests

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "md5",
        "sha1",
        "sha256",
        "domain",
        "url",
        "email-src",
        "ip-dst|port",
        "ip-src|port",
    ],
    "output": ["text"],
}
moduleinfo = {
    "version": "0.1",
    "author": "Corsin Camichel",
    "description": "Module to search for an IOC on ThreatFox by abuse.ch.",
    "module-type": ["hover", "expansion"],
    "name": "ThreadFox Lookup",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}
moduleconfig = []

API_URL = "https://threatfox-api.abuse.ch/api/v1/"


# copied from
# https://github.com/marjatech/threatfox2misp/blob/main/threatfox2misp.py
def confidence_level_to_tag(level: int) -> str:
    confidence_tagging = {
        0: 'misp:confidence-level="unconfident"',
        10: 'misp:confidence-level="rarely-confident"',
        37: 'misp:confidence-level="fairly-confident"',
        63: 'misp:confidence-level="usually-confident"',
        90: 'misp:confidence-level="completely-confident"',
    }

    confidence_tag = ""
    for tag_minvalue, tag in confidence_tagging.items():
        if level >= tag_minvalue:
            confidence_tag = tag
    return confidence_tag


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)
    ret_val = ""

    for input_type in mispattributes["input"]:
        if input_type in request:
            to_query = request[input_type]
            break
    else:
        misperrors["error"] = "Unsupported attributes type:"
        return misperrors

    data = {"query": "search_ioc", "search_term": f"{to_query}"}
    response = requests.post(API_URL, data=json.dumps(data))
    if response.status_code == 200:
        result = json.loads(response.text)
        if result["query_status"] == "ok":
            confidence_tag = confidence_level_to_tag(result["data"][0]["confidence_level"])
            ret_val = {
                "results": [
                    {
                        "types": mispattributes["output"],
                        "values": [result["data"][0]["threat_type_desc"]],
                        "tags": [
                            result["data"][0]["malware"],
                            result["data"][0]["malware_printable"],
                            confidence_tag,
                        ],
                    }
                ]
            }

    return ret_val


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
