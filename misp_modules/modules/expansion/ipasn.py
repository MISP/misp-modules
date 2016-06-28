# -*- coding: utf-8 -*-

import json
from ipasn_redis import IPASN

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-src', 'ip-dst'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot',
              'description': 'Query an IP ASN history service (https://github.com/CIRCL/IP-ASN-history.git)',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['host', 'port', 'db']


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

    if not request.get('config') and not (request['config'].get('host') and
                                          request['config'].get('port') and
                                          request['config'].get('db')):
        misperrors['error'] = 'IP ASN history configuration is missing'
        return misperrors

    ipasn = IPASN(host=request['config'].get('host'),
                  port=request['config'].get('port'), db=request['config'].get('db'))

    values = []
    for first_seen, last_seen, asn, block in ipasn.aggregate_history(toquery):
        values.append('{} {} {} {}'.format(first_seen.decode(), last_seen.decode(), asn.decode(), block))

    if not values:
        misperrors['error'] = 'Unable to find the history of this IP'
        return misperrors
    return {'results': [{'types': mispattributes['output'], 'values': values}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
