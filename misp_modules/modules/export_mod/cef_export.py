import base64
import datetime
import json

misperrors = {"error": "Error"}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "1",
    "author": "Hannah Ward",
    "description": "Module to export a MISP event in CEF format.",
    "module-type": ["export"],
    "name": "CEF Export",
    "logo": "",
    "requirements": [],
    "features": (
        "The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined"
        " types is then exported in Common Event Format.\nThus, there is no particular feature concerning MISP Events"
        " since any event can be exported. However, 4 configuration parameters recognized by CEF format are required"
        " and should be provided by users before exporting data: the device vendor, product and version, as well as the"
        " default severity of data."
    ),
    "references": [
        "https://community.softwaregrp.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Guide/ta-p/1589306?attachment-id=65537"
    ],
    "input": "MISP Event attributes",
    "output": "Common Event Format file",
}

# config fields that your code expects from the site admin
moduleconfig = ["Default_Severity", "Device_Vendor", "Device_Product", "Device_Version"]

cefmapping = {
    "ip-src": "src",
    "ip-dst": "dst",
    "hostname": "dhost",
    "domain": "dhost",
    "md5": "fileHash",
    "sha1": "fileHash",
    "sha256": "fileHash",
    "url": "request",
}

mispattributes = {"input": list(cefmapping.keys())}
outputFileExtension = "cef"
responseType = "application/txt"


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if "config" in request:
        config = request["config"]
    else:
        config = {
            "Default_Severity": 1,
            "Device_Vendor": "MISP",
            "Device_Product": "MISP",
            "Device_Version": 1,
        }

    data = request["data"]
    response = ""
    for ev in data:
        event = ev["Attribute"]
        for attr in event:
            if attr["type"] in cefmapping:
                response += "{} host CEF:0|{}|{}|{}|{}|{}|{}|{}={}\n".format(
                    datetime.datetime.fromtimestamp(int(attr["timestamp"])).strftime("%b %d %H:%M:%S"),
                    config["Device_Vendor"],
                    config["Device_Product"],
                    config["Device_Version"],
                    attr["category"],
                    attr["category"],
                    config["Default_Severity"],
                    cefmapping[attr["type"]],
                    attr["value"],
                )

    r = {
        "response": [],
        "data": str(base64.b64encode(bytes(response, "utf-8")), "utf-8"),
    }
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
