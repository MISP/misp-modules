"""
Export module for coverting MISP events into Defender for Endpoint KQL queries.
Config['Period'] : allows to define period over witch to look for IOC from now
"""

import base64
import json

misperrors = {"error": "Error"}

types_to_use = ["sha256", "sha1", "md5", "domain", "ip-src", "ip-dst", "url"]

userConfig = {}

moduleconfig = ["Period"]
inputSource = ["event"]

outputFileExtension = "kql"
responseType = "application/txt"

moduleinfo = {
    "version": "1.1",
    "author": "Julien Bachmann, Hacknowledge, Maik Wuerth",
    "description": "Defender for Endpoint KQL hunting query export module",
    "module-type": ["export"],
    "name": "Microsoft Defender for Endpoint KQL Export",
    "logo": "defender_endpoint.png",
    "requirements": [],
    "features": (
        "This module export an event as Defender for Endpoint KQL queries that can then be used in your own python3 or"
        " Powershell tool. If you are using Microsoft Sentinel, you can directly connect your MISP instance to Sentinel"
        " and then create queries using the `ThreatIntelligenceIndicator` table to match events against imported IOC."
    ),
    "references": [
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/advanced-hunting-schema-reference"
    ],
    "input": "MISP Event attributes",
    "output": "Defender for Endpoint KQL queries",
}


def handle_sha256(value, period):
    query = f"""find in (DeviceEvents, DeviceAlertEvents,AlertInfo, AlertEvidence,  DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents)
        where (SHA256 == '{value}' or InitiatingProcessSHA1 == '{value}') and
        Timestamp between(ago({period}) .. now())"""
    return query.replace("\n", " ")


def handle_sha1(value, period):
    query = f"""find in (DeviceEvents, DeviceAlertEvents, AlertInfo, AlertEvidence, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents)
        where (SHA1 == '{value}' or InitiatingProcessSHA1 == '{value}') and
        Timestamp between(ago({period}) .. now())"""
    return query.replace("\n", " ")


def handle_md5(value, period):
    query = f"""find in (DeviceEvents, DeviceAlertEvents, AlertInfo, AlertEvidence, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents)
        where (MD5 == '{value}' or InitiatingProcessMD5 == '{value}') and
        Timestamp between(ago({period}) .. now())"""
    return query.replace("\n", " ")


def handle_domain(value, period):
    query = f"""find in (DeviceAlertEvents, AlertInfo, AlertEvidence, DeviceNetworkEvents)
        where RemoteUrl contains '{value}' and
        Timestamp between(ago({period}) .. now())"""
    return query.replace("\n", " ")


def handle_ip(value, period):
    query = f"""find in (DeviceAlertEvents, AlertInfo, AlertEvidence, DeviceNetworkEvents)
        where RemoteIP == '{value}' and
        Timestamp between(ago({period}) .. now())"""
    return query.replace("\n", " ")


def handle_url(value, period):
    query = f"""let url = '{value}';
        search in (EmailUrlInfo,UrlClickEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceEvents,BehaviorEntities, AlertInfo, AlertEvidence, DeviceAlertEvents)
        Timestamp between(ago({period}) .. now()) and
        RemoteUrl has url
        or FileOriginUrl has url
        or FileOriginReferrerUrl has url
        or Url has url"""
    return query.replace("\n", " ")


handlers = {
    "sha256": handle_sha256,
    "sha1": handle_sha1,
    "md5": handle_md5,
    "domain": handle_url,
    "ip-src": handle_ip,
    "ip-dst": handle_ip,
    "url": handle_url,
}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    config = request.get("config", {"Period": ""})
    output = ""

    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in types_to_use:
                output = output + handlers[attribute["type"]](attribute["value"], config["Period"]) + "\n"
        for obj in event["Object"]:
            for attribute in obj["Attribute"]:
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
