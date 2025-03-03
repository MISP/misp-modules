import base64
import json

from pymisp import MISPEvent

misperrors = {"error": "Error"}
userConfig = {
    "number1": {
        "type": "Integer",
        "regex": "/^[0-4]$/i",
        "errorMessage": "Expected a number in range [0-4]",
        "message": "Column number used for value",
    },
    "some_string": {"type": "String", "message": "A text field"},
    "boolean_field": {"type": "Boolean", "message": "Boolean field test"},
    "comment": {"type": "Integer", "message": "Column number used for comment"},
}

mispattributes = {
    "inputSource": ["file", "paste"],
    "output": ["MISP Format"],
    "format": "misp_standard",
}


moduleinfo = {
    "version": "0.1",
    "author": "Sami Mokaddem",
    "description": "Generic blueprint to be copy-pasted to quickly boostrap creation of import module.",
    "module-type": ["import"],
    "name": "Import Blueprint",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}

moduleconfig = []


def generateData(event, data, config):
    # attr = MISPAttribute()
    # attr.from_dict(**{
    #     'type': 'ip-src',
    #     'value': '8.8.8.8',
    #     'distribution': 2
    # })
    # event.add_attribute(attr)
    pass


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    data = getUploadedData(request)
    config = getPassedConfig(request)
    event = MISPEvent()
    generateData(event, data, config)
    return {"results": json.loads(event.to_json())}


def getUploadedData(request):
    return base64.b64decode(request["data"]).decode("utf8")


def getPassedConfig(request):
    return request["config"]


def introspection():
    modulesetup = mispattributes
    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
