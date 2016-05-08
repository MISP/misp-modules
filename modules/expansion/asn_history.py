# -*- coding: utf-8 -*-

import json
from asnhistory import ASNHistory

misperrors = {'error': 'Error'}
mispattributes = {'input': ['asn'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot',
              'description': 'Query an ASN Description history service (https://github.com/CIRCL/ASN-Description-History.git)',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['host', 'port', 'db']


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('asn'):
        toquery = request['asn']
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    if not request.get('config') and not (request['config'].get('host') and
                                          request['config'].get('port') and
                                          request['config'].get('db')):
        misperrors['error'] = 'ASN description history configuration is missing'
        return misperrors

    asnhistory = ASNHistory(host=request['config'].get('host'),
                            port=request['config'].get('port'), db=request['config'].get('db'))

    values = ['{} {}'.format(date.isoformat(), description) for date, description in asnhistory.get_all_descriptions(toquery)]

    if not values:
        misperrors['error'] = 'Unable to find descriptions for this ASN'
        return misperrors
    return {'results': [{'types': mispattributes['output'], 'values': values}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
