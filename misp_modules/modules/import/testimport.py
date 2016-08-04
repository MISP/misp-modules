import json
import base64
import csv

misperrors = {'error': 'Error'}
userConfig = {
               'value': {
                 'type': 'Integer',
                 'regex': '/^[0-4]$/i',
                 'errorMessage': 'Expected a number in range [0-4]',
                 'message': 'Column number used for value'
               },
               'category': {
                 'type': 'Integer',
                 'message': 'Column number used for category'
               },
               'type': {
                 'type': 'Integer',
                 'message': 'Column number used for type'
               },
               'comment': {
                 'type': 'Integer',
                 'message': 'Column number used for comment'
               }
             };

inputSource = ['file', 'paste']

moduleinfo = {'version': '0.2', 'author': 'Andras Iklody',
              'description': 'Simple CSV import tool with mapable columns',
              'module-type': ['import']}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    r = {'results': []}
    request = json.loads(q)
    request["data"] = base64.b64decode(request["data"])
    fields = ["value", "category", "type", "comment"]
    r = {"results":[{"values":["192.168.56.1"], "types":["ip-src"], "categories":["Network activity"]}]}
    return r


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
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
