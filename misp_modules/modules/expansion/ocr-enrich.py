import json
import binascii
import cv2
import np
import pytesseract

misperrors = {'error': 'Error'}
mispattributes = {'input': ['attachment'],
                  'output': ['freetext', 'text']}
moduleinfo = {'version': '0.1', 'author': 'Sascha Rommelfangen',
              'description': 'OCR decoder',
              'module-type': ['expansion']}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    filename = q['attachment']
    try:
        img_array = np.frombuffer(binascii.a2b_base64(q['data']), np.uint8)
    except Exception as e:
        print(e)
        err = "Couldn't fetch attachment (JSON 'data' is empty). Are you using the 'Query enrichment' action?"
        misperrors['error'] = err
        print(err)
        return misperrors

    image = img_array
    image = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
    try:
        decoded = pytesseract.image_to_string(image)
        return {'results': [{'types': ['freetext'], 'values': decoded, 'comment': "OCR from file " + filename},
                {'types': ['text'], 'values': decoded, 'comment': "ORC from file " + filename}]}
    except Exception as e:
        print(e)
        err = "Couldn't analyze file type. Only images are supported right now."
        misperrors['error'] = err
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
