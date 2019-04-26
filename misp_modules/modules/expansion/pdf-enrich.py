import json
import binascii
import np
import pdftotext
import io

misperrors = {'error': 'Error'}
mispattributes = {'input': ['attachment'],
                  'output': ['freetext', 'text']}
moduleinfo = {'version': '0.1', 'author': 'Sascha Rommelfangen',
              'description': 'PDF to freetext-import IOC extractor',
              'module-type': ['expansion']}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    filename = q['attachment']
    try:
        pdf_array = np.frombuffer(binascii.a2b_base64(q['data']), np.uint8)
    except Exception as e:
        print(e)
        err = "Couldn't fetch attachment (JSON 'data' is empty). Are you using the 'Query enrichment' action?"
        misperrors['error'] = err
        print(err)
        return misperrors

    pdf_file = io.BytesIO(pdf_array)
    try:
        pdf_content = "\n\n".join(pdftotext.PDF(pdf_file))
        return {'results': [{'types': ['freetext'], 'values': pdf_content, 'comment': "PDF-to-text from file " + filename}]}
    except Exception as e:
        print(e)
        err = "Couldn't analyze file as PDF. Error was: " + str(e)
        misperrors['error'] = err
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
