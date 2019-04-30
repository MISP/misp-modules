import json
import binascii
import np
import ezodf
import pandas_ods_reader
import io

misperrors = {'error': 'Error'}
mispattributes = {'input': ['attachment'],
                  'output': ['freetext', 'text']}
moduleinfo = {'version': '0.1', 'author': 'Sascha Rommelfangen',
              'description': '.ods to freetext-import IOC extractor',
              'module-type': ['expansion']}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    filename = q['attachment']
    try:
        ods_array = np.frombuffer(binascii.a2b_base64(q['data']), np.uint8)
    except Exception as e:
        print(e)
        err = "Couldn't fetch attachment (JSON 'data' is empty). Are you using the 'Query enrichment' action?"
        misperrors['error'] = err
        print(err)
        return misperrors

    ods_content = ""
    ods_file = io.BytesIO(ods_array)
    doc = ezodf.opendoc(ods_file)
    num_sheets = len(doc.sheets)
    try:
        for i in range(0, num_sheets):
            ods = pandas_ods_reader.read_ods(ods_file, i, headers=False)
            ods_content = ods_content + "\n" + ods.to_string(max_rows=None)
        print(ods_content)
        return {'results': [{'types': ['freetext'], 'values': ods_content, 'comment': ".ods-to-text from file " + filename},
                            {'types': ['text'], 'values': ods_content, 'comment': ".ods-to-text from file " + filename}]}
    except Exception as e:
        print(e)
        err = "Couldn't analyze file as .ods. Error was: " + str(e)
        misperrors['error'] = err
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
