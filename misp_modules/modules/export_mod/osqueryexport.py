"""
Export module for coverting MISP events into OSQuery query pack.
Source: https://github.com/0xmilkmix/misp-modules/blob/master/misp_modules/modules/export_mod/osqueryexport.py
"""

import base64
import json
import csv
import re


misperrors = {"error": "Error"}

types_to_use = ['regkey', 'mutex']


userConfig = {

};

moduleconfig = []

# fixed for now, options in the future:
# event, attribute, event-collection, attribute-collection
inputSource = ['event']

outputFileExtension = 'conf'
responseType = 'application/txt'


moduleinfo = {'version': '0.1', 'author': 'Julien Bachmann, Hacknowledge',
              'description': 'OSQuery query export module',
              'module-type': ['export']}

# test : http://misp.vm/events/view/23
def handle_regkey(value):
    rep = {'HKCU': 'HKEY_USERS\\%', 'HKLM': 'HKEY_LOCAL_MACHINE'}
    rep = dict((re.escape(k), v) for k, v in rep.items())
    pattern = re.compile("|".join(rep.keys()))
    value = pattern.sub(lambda m: rep[re.escape(m.group(0))], value)
    return 'SELECT * FROM registry WHERE path LIKE \'%s\';' % value

def handle_mutex(value):
    return '#waiting acceptance of Scott Lundgren PR that would allow to query Kernel Objects'

handlers = {
    'regkey' : handle_regkey,
    'mutex' : handle_mutex
}

def handler(q=False):
    if q is False:
        return False
    r = {'results': []}
    request = json.loads(q)
    output = ''

    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute['type'] in types_to_use:
                    output = output + handlers[attribute['type']](attribute['value']) + '\n'
    r = {"response":[], "data":str(base64.b64encode(bytes(output, 'utf-8')), 'utf-8')}
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
