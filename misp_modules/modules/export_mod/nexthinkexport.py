"""
Export module for coverting MISP events into Nexthink NXQL queries.
Source: https://github.com/HacknowledgeCH/misp-modules/blob/master/misp_modules/modules/export_mod/nexthinkexport.py
Config['Period'] : allows to define period over witch to look for IOC from now (15m, 1d, 2w, 30d, ...), see Nexthink data model documentation
"""

import base64
import json

misperrors = {"error": "Error"}

types_to_use = ["sha1", "sha256", "md5", "domain"]

userConfig = {}

moduleconfig = ["Period"]
inputSource = ["event"]

outputFileExtension = "nxql"
responseType = "application/txt"

moduleinfo = {
    "version": "1.0",
    "author": "Julien Bachmann, Hacknowledge",
    "description": "Nexthink NXQL query export module",
    "module-type": ["export"],
    "name": "Nexthink NXQL Export",
    "logo": "nexthink.svg",
    "requirements": [],
    "features": (
        "This module export an event as Nexthink NXQL queries that can then be used in your own python3 tool or from"
        " wget/powershell"
    ),
    "references": ["https://doc.nexthink.com/Documentation/Nexthink/latest/APIAndIntegrations/IntroducingtheWebAPIV2"],
    "input": "MISP Event attributes",
    "output": "Nexthink NXQL queries",
}


def handle_sha1(value, period):
    query = """select ((binary (executable_name version)) (user (name)) (device (name last_ip_address)) (execution (binary_path start_time)))
(from (binary user device execution)
(where binary (eq sha1 (sha1 %s)))
(between now-%s now))
(limit 1000)
    """ % (
        value,
        period,
    )
    return query.replace("\n", " ")


def handle_sha256(value, period):
    query = """select ((binary (executable_name version)) (user (name)) (device (name last_ip_address)) (execution (binary_path start_time)))
(from (binary user device execution)
(where binary (eq sha256 (sha256 %s)))
(between now-%s now))
(limit 1000)
    """ % (
        value,
        period,
    )
    return query.replace("\n", " ")


def handle_md5(value, period):
    query = """select ((binary (executable_name version)) (user (name)) (device (name last_ip_address)) (execution (binary_path start_time)))
(from (binary user device execution)
(where binary (eq hash (md5 %s)))
(between now-%s now))
(limit 1000)
    """ % (
        value,
        period,
    )
    return query.replace("\n", " ")


def handle_domain(value, period):
    query = """select ((device name) (device (name last_ip_address)) (user name)(user department) (binary executable_name)(binary application_name)(binary description)(binary application_category)(binary (executable_name version)) (binary #"Suspicious binary")(binary first_seen)(binary last_seen)(binary threat_level)(binary hash) (binary paths)
(destination name)(domain name) (domain domain_category)(domain hosting_country)(domain protocol)(domain threat_level) (port port_number)(web_request incoming_traffic)(web_request outgoing_traffic))
(from (web_request device user binary executable destination domain port)
(where domain (eq name(string %s)))
(between now-%s now))
(limit 1000)
    """ % (
        value,
        period,
    )
    return query.replace("\n", " ")


handlers = {
    "sha1": handle_sha1,
    "sha256": handle_sha256,
    "md5": handle_md5,
    "domain": handle_domain,
}


def handler(q=False):
    if q is False:
        return False
    r = {"results": []}
    request = json.loads(q)
    config = request.get("config", {"Period": ""})
    output = ""

    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in types_to_use:
                output = output + handlers[attribute["type"]](attribute["value"], config["Period"]) + "\n"
    r = {"response": [], "data": str(base64.b64encode(bytes(output, "utf-8")), "utf-8")}
    return r


def introspection():
    modulesetup = {}
    try:
        responseType
        modulesetup["responseType"] = responseType
    except NameError:
        pass
    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    try:
        outputFileExtension
        modulesetup["outputFileExtension"] = outputFileExtension
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
