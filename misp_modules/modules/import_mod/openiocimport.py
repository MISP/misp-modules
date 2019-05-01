import json
import base64

from pymisp.tools import openioc

misperrors = {'error': 'Error'}
userConfig = {'not save ioc': {'type': 'Boolean',
                               'message': 'If you check this box, IOC file will not save as an attachment in MISP'
                               },
              'default tag': {
                  'type': 'String',
                  'message': 'Add tags spaced by a comma (tlp:white,misp:threat-level="no-risk")',
                  'validation': '0'}
              }

inputSource = ['file']

moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot',
              'description': 'Import OpenIOC package',
              'module-type': ['import']}

moduleconfig = []


def handler(q=False):
    # Just in case we have no data
    if q is False:
        return False

    # The return value
    r = {'results': []}

    # Load up that JSON
    q = json.loads(q)

    # It's b64 encoded, so decode that stuff
    package = base64.b64decode(q.get("data")).decode('utf-8')

    # If something really weird happened
    if not package:
        return json.dumps({"success": 0})

    pkg = openioc.load_openioc(package)

    if q.get('config'):
        if q['config'].get('not save ioc') == "0":
            addFile = {"values": [q.get('filename')],
                       "types": ['attachment'],
                       "categories": ['Support Tool'],
                       "data": q.get('data')}
            # add tag
            if q['config'].get('default tag') is not None:
                addFile["tags"] = q['config']['default tag'].split(",")
            # add file as attachment
            r["results"].append(addFile)

    # return all attributes
    for attrib in pkg.attributes:
        toAppend = {
            "values": [attrib.value],
            "types": [attrib.type],
            "categories": [attrib.category],
            "comment": getattr(attrib, 'comment', '')}
        # add tag
        if q.get('config') and q['config'].get('default tag') is not None:
            toAppend["tags"] = q['config']['default tag'].split(",")

        r["results"].append(toAppend)
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
