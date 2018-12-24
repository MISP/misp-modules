"""
Export module for coverting MISP events into Nexthink NXQL queries.
Source: https://github.com/HacknowledgeCH/misp-modules/blob/master/misp_modules/modules/export_mod/nexthinkexport.py
Config['Period'] : allows to define period over witch to look for IOC from now (15m, 1d, 2w, 30d, ...)
"""

import base64
import json
import re

misperrors = {"error": "Error"}

types_to_use = ['sha1']

userConfig = {

}

moduleconfig = ["Period"]
inputSource = ['event']

outputFileExtension = 'conf'
responseType = 'application/txt'


moduleinfo = {'version': '1.0', 'author': 'Julien Bachmann, Hacknowledge',
              'description': 'Nexthink NXQL query export module',
              'module-type': ['export']}


def handle_sha1(value, period):
    return '''
    (select ((binary (executable_name version)) (user (name)) (device (name last_ip_address)) (execution (binary_path start_time)))
	(from (binary user device execution)
    (where binary (eq hash (sha1 %s))))
    (between now-%s now)
	(limit 1000))
    ''' % (value, period)

handlers = {
    'sha1': handle_sha1
}

def handler(q=False):
    if q is False:
        return False
    r = {'results': []}
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
