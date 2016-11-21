# -*- coding: utf-8 -*-

import json

from pymisp import MISPEvent

misperrors = {'error': 'Error'}

moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot',
              'description': 'Verify the signature of a MISP Event',
              'module-type': ['event']}

moduleconfig = ['uid']

'''
NOTE:
* requires pyme3 + dependencies
* working gpg-agent
* the public key which signed the event in the keyring
'''


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)  # Assuming request has two keys: config & mispevent (mispevent being the json dump of the event)
    mispevent = MISPEvent()
    mispevent.load(request['mispevent'])
    verified = mispevent.verify(mispevent.Org['uuid'])
    return json.dumps(verified)


def introspection():
    return moduleconfig


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
