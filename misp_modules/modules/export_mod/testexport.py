import json
import base64
import csv

misperrors = {'error': 'Error'}


userConfig = {

};

moduleconfig = []

# fixed for now, options in the future:
# event, attribute, event-collection, attribute-collection
inputSource = ['event']

outputFileExtension = 'txt'
responseType = 'application/txt'


moduleinfo = {'version': '0.1', 'author': 'Andras Iklody',
              'description': 'Skeleton export module',
              'module-type': ['export']}


def handler(q=False):
    if q is False:
        return False
    r = {'results': []}
    result = json.loads(q)
    output = ''; # Insert your magic here!
    r = {"data":base64.b64encode(output.encode('utf-8')).decode('utf-8')}
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
