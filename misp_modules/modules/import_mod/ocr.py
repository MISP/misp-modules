import sys
import json
import base64
from io import BytesIO

import logging

log = logging.getLogger('ocr')
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {'error': 'Error'}
userConfig = {};

inputSource = ['file']

moduleinfo = {'version': '0.2', 'author': 'Alexandre Dulaunoy',
              'description': 'Optical Character Recognition (OCR) module for MISP',
              'module-type': ['import']}

moduleconfig = []


def handler(q=False):
    # try to import modules and return errors if module not found
    try:
        from PIL import Image
    except ImportError:
        misperrors['error'] = "Please pip(3) install pillow"
        return misperrors

    try:
        # Official ImageMagick module
        from wand.image import Image as WImage
    except ImportError:
        misperrors['error'] = "Please pip(3) install wand"
        return misperrors

    try:
        from pytesseract import image_to_string
    except ImportError:
        misperrors['error'] = "Please pip(3) install pytesseract"
        return misperrors

    if q is False:
        return False
    r = {'results': []}
    request = json.loads(q)
    document = base64.b64decode(request["data"])
    document = WImage(blob=document)
    if document.format == 'PDF':
        with document as pdf:
            # Get number of pages
            pages=len(pdf.sequence)
            log.debug(f"PDF with {pages} page(s) detected")
            # Create new image object where the height will be the number of pages. With huge PDFs this will overflow, break, consume silly memory etc…
            img = WImage(width=pdf.width, height=pdf.height * pages)
            # Cycle through pages and stitch it together to one big file
            for p in range(pages):
                log.debug(f"Stitching page {p+1}")
                image = img.composite(pdf.sequence[p], top=pdf.height * p, left=0)
            # Create a png blob
            image = img.make_blob('png')
            log.debug(f"Final image size is {pdf.width}x{pdf.height*(p+1)}")
    else:
        image = document

    image_file = BytesIO(image)
    image_file.seek(0)

    try:
        im = Image.open(image_file)
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
