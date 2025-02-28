"""
Export module for coverting MISP events into OSQuery queries.
Source: https://github.com/0xmilkmix/misp-modules/blob/master/misp_modules/modules/export_mod/osqueryexport.py
"""

import base64
import json
import re

misperrors = {"error": "Error"}

types_to_use = [
    "regkey",
    "regkey|value",
    "mutex",
    "windows-service-displayname",
    "windows-scheduled-task",
    "yara",
]

userConfig = {}

moduleconfig = []
inputSource = ["event"]

outputFileExtension = "conf"
responseType = "application/txt"


moduleinfo = {
    "version": "1.0",
    "author": "Julien Bachmann, Hacknowledge",
    "description": "OSQuery export of a MISP event.",
    "module-type": ["export"],
    "name": "OSQuery Export",
    "logo": "osquery.png",
    "requirements": [],
    "features": (
        "This module export an event as osquery queries that can be used in packs or in fleet management solution like"
        " Kolide."
    ),
    "references": [],
    "input": "MISP Event attributes",
    "output": "osquery SQL queries",
}


def handle_regkey(value):
    rep = {"HKCU": "HKEY_USERS\\%", "HKLM": "HKEY_LOCAL_MACHINE"}
    rep = dict((re.escape(k), v) for k, v in rep.items())
    pattern = re.compile("|".join(rep.keys()))
    value = pattern.sub(lambda m: rep[re.escape(m.group(0))], value)
    return "SELECT * FROM registry WHERE path LIKE '%s';" % value


def handle_regkeyvalue(value):
    key, value = value.split("|")
    rep = {"HKCU": "HKEY_USERS\\%", "HKLM": "HKEY_LOCAL_MACHINE"}
    rep = dict((re.escape(k), v) for k, v in rep.items())
    pattern = re.compile("|".join(rep.keys()))
    key = pattern.sub(lambda m: rep[re.escape(m.group(0))], key)
    return "SELECT * FROM registry WHERE path LIKE '%s' AND data LIKE '%s';" % (
        key,
        value,
    )


def handle_mutex(value):
    return "SELECT * FROM winbaseobj WHERE object_name LIKE '%s';" % value


def handle_service(value):
    return "SELECT * FROM services WHERE display_name LIKE '%s' OR name like '%s';" % (
        value,
        value,
    )


def handle_yara(value):
    return "not implemented yet, not sure it's easily feasible w/o dropping the sig on the hosts first"


def handle_scheduledtask(value):
    return "SELECT * FROM scheduled_tasks WHERE name LIKE '%s';" % value


handlers = {
    "regkey": handle_regkey,
    "regkey|value": handle_regkeyvalue,
    "mutex": handle_mutex,
    "windows-service-displayname": handle_service,
    "windows-scheduled-task": handle_scheduledtask,
    "yara": handle_yara,
}


def handler(q=False):
    if q is False:
        return False
    r = {"results": []}
    request = json.loads(q)
    output = ""

    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in types_to_use:
                output = output + handlers[attribute["type"]](attribute["value"]) + "\n"
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
