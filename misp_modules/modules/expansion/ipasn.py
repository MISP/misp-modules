# -*- coding: utf-8 -*-

import json
from pyipasnhistory import IPASNHistory

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-src', 'ip-dst'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot',
              'description': 'Query an IP ASN history service (https://github.com/CIRCL/IP-ASN-history.git)',
              'module-type': ['expansion', 'hover']}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('ip-src'):
        toquery = request['ip-src']
    elif request.get('ip-dst'):
        toquery = request['ip-dst']
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    ipasn = IPASNHistory()
    values = ipasn.query(toquery)

    if not values:
        misperrors['error'] = 'Unable to find the history of this IP'
        return misperrors
    return {'results': [{'types': mispattributes['output'], 'values': [str(values)]}]}


def introspection():
    return mispattributes


def version():
    return moduleinfo
