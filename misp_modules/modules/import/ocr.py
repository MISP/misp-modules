import json
import base64

from PIL import Image

from pytesseract import image_to_string
from io import BytesIO
misperrors = {'error': 'Error'}
userConfig = { };

inputSource = ['file']

moduleinfo = {'version': '0.1', 'author': 'Alexandre Dulaunoy',
              'description': 'Optical Character Recognition (OCR) module for MISP',
              'module-type': ['import']}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    r = {'results': []}
    request = json.loads(q)
    image = base64.b64decode(request["data"])
    image_file = BytesIO(image)
    image_file.seek(0)
    ocrized = image_to_string(Image.open(image_file))
    freetext = {}
    freetext['values'] = ocrized
    freetext['types'] = ['freetext']
    r['results'].append(freetext)
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

if __name__ == '__main__':
    x = open('test.json', 'r')
    handler(q=x.read())
