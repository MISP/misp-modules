# -*- coding: utf-8 -*-

import json
from datetime import date, timedelta
from pybgpranking import BGPRanking

misperrors = {'error': 'Error'}
mispattributes = {'input': ['AS'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot',
              'description': 'Query an ASN Description history service (https://github.com/CIRCL/ASN-Description-History.git)',
              'module-type': ['expansion', 'hover']}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('AS'):
        toquery = request['AS']
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    bgpranking = BGPRanking()
    values = bgpranking.query(toquery, date=(date.today() - timedelta(1)).isoformat())

    if not values:
        misperrors['error'] = 'Unable to find the ASN in BGP Ranking'
        return misperrors
    return {'results': [{'types': mispattributes['output'], 'values': values}]}


def introspection():
    return mispattributes


def version():
    return moduleinfo
