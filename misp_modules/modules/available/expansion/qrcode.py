import json
from pyzbar import pyzbar
import cv2
import re
import binascii
import np

misperrors = {'error': 'Error'}
mispattributes = {'input': ['attachment'],
                  'output': ['url', 'btc']}
moduleinfo = {'version': '0.1', 'author': 'Sascha Rommelfangen',
              'description': 'QR code decoder',
              'module-type': ['expansion', 'hover']}

debug = True
debug_prefix = "[DEBUG] QR Code module: "
# format example: bitcoin:1GXZ6v7FZzYBEnoRaG77SJxhu7QkvQmFuh?amount=0.15424
# format example: http://example.com
cryptocurrencies = ['bitcoin']
schemas = ['http://', 'https://', 'ftp://']
moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    filename = q['attachment']
    try:
        img_array = np.fromstring(binascii.a2b_base64(q['data']), np.uint8)
    except Exception as e:
        err = "Couldn't fetch attachment (JSON 'data' is empty). Are you using the 'Query enrichment' action?"
        misperrors['error'] = err
        print(err)
        print(e)
        return misperrors
    image = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
    if q:
        barcodes = pyzbar.decode(image)
    for item in barcodes:
        try:
            result = item.data.decode()
        except Exception as e:
            print(e)
            return
        if debug:
            print(debug_prefix + result)
        for item in cryptocurrencies:
            if item in result:
                try:
                    currency, address, extra = re.split(r'\:|\?', result)
                except Exception as e:
                    print(e)
                if currency in cryptocurrencies:
                    try:
                        amount = re.split('=', extra)[1]
                        if debug:
                            print(debug_prefix + address)
                            print(debug_prefix + amount)
                        return {'results': [{'types': ['btc'], 'values': address, 'comment': "BTC: " + amount + " from file " + filename}]}
                    except Exception as e:
                        print(e)
                else:
                    print(address)
        for item in schemas:
            if item in result:
                try:
                    url = result
                    if debug:
                        print(debug_prefix + url)
                    return {'results': [{'types': ['url'], 'values': url, 'comment': "from QR code of file " + filename}]}
                except Exception as e:
                    print(e)
            else:
                try:
                    return {'results': [{'types': ['text'], 'values': result, 'comment': "from QR code of file " + filename}]}
                except Exception as e:
                    print(e)
    misperrors['error'] = "Couldn't decode QR code in attachment."
    return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
