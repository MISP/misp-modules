import json
import base64
import magic

from PIL import Image

from wand.image import Image as WImage

from pytesseract import image_to_string
from io import BytesIO
misperrors = {'error': 'Error'}
userConfig = { };

inputSource = ['file']

moduleinfo = {'version': '0.2', 'author': 'Alexandre Dulaunoy',
              'description': 'Optical Character Recognition (OCR) module for MISP',
              'module-type': ['import']}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    r = {'results': []}
    request = json.loads(q)
    document = base64.b64decode(request["data"])
    if magic.from_buffer(document, mime=True).split("/")[1] == 'pdf':
        print("PDF Detected")
        with WImage(blob=document) as pdf:
            pages=len(pdf.sequence)
            img = WImage(width=pdf.width, height=pdf.height * pages)
            for p in range(pages):
                img.composite(pdf.sequence[p], top=pdf.height * p, left=0)
    image = document

    image_file = BytesIO(image)
    image_file.seek(0)

    try:
        im = WImage(blob=image_file)
    except IOError:
        misperrors['error'] = "Corrupt or not an image file."
        return misperrors


    ocrized = image_to_string(im)

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
