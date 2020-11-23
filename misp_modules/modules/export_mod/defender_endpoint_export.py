"""
Export module for coverting MISP events into Defender for Endpoint KQL queries.
Config['Period'] : allows to define period over witch to look for IOC from now
"""

import base64
import json

misperrors = {"error": "Error"}

types_to_use = ['sha1', 'md5', 'domain', 'ip', 'url']

userConfig = {

}

moduleconfig = ["Period"]
inputSource = ['event']

outputFileExtension = 'kql'
responseType = 'application/txt'

moduleinfo = {'version': '1.0', 'author': 'Julien Bachmann, Hacknowledge',
              'description': 'Defender for Endpoint KQL hunting query export module',
              'module-type': ['export']}

def handle_sha1(value, period):
    query = f"""find in (DeviceAlertEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents)
        where SHA1 == '{value}' or InitiatingProcessSHA1 == '{value}'"""
    return query.replace('\n', ' ')

def handle_md5(value, period):
    query = f"""find in (DeviceAlertEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents)
        where MD5 == '{value}' or InitiatingProcessMD5 == '{value}'"""
    return query.replace('\n', ' ')

def handle_domain(value, period):
    query = f"""find in (DeviceAlertEvents, DeviceNetworkEvents)
        where RemoteUrl contains '{value}'"""
    return query.replace('\n', ' ')

def handle_ip(value, period):
    query = f"""find in (DeviceAlertEvents, DeviceNetworkEvents)
        where RemoteIP == '{value}'"""
    return query.replace('\n', ' ')

def handle_url(value, period):
    query = f"""find in (DeviceAlertEvents, DeviceNetworkEvents)
        where RemoteUrl startswith '{value}'"""
    return query.replace('\n', ' ')

handlers = {
    'sha1': handle_sha1,
    'md5': handle_md5,
    'domain': handle_domain,
    'ip': handle_ip,
    'url': handle_url
}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    config = request.get("config", {"Period": ""})
    output = ''

    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute['type'] in types_to_use:
                output = output + handlers[attribute['type']](attribute['value'], config['Period']) + '\n'
    r = {"response": [], "data": str(base64.b64encode(bytes(output, 'utf-8')), 'utf-8')}
    return r

def introspection():
    modulesetup = {}
    try:
        responseType
        modulesetup['responseType'] = responseType
    except NameError:
        pass
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        outputFileExtension
        modulesetup['outputFileExtension'] = outputFileExtension
    except NameError:
        pass
    try:
        inputSource
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
