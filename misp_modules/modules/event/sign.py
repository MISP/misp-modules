# -*- coding: utf-8 -*-

import json

from pymisp import MISPEvent, EncodeUpdate

misperrors = {'error': 'Error'}

moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot',
              'description': 'Sign a MISP Event',
              'module-type': ['event']}

moduleconfig = ['uid', 'passphrase']

'''
NOTE:
* requires pyme3 + dependencies
* working gpg-agent
* private key for signing
'''


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)  # Assuming request has two keys: config & mispevent (mispevent being the json dump of the event)
    mispevent = MISPEvent()
    mispevent.load(request['mispevent'])
    mispevent.sign(request['config']['uid'], request['config']['passphrase'])
    return json.dumps(mispevent, cls=EncodeUpdate)


def introspection():
    return moduleconfig


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
