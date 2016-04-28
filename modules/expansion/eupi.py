# -*- coding: utf-8 -*-

import json
from pyeupi import PyEUPI

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', 'url'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot',
              'description': 'Query the Phishing Initiative service (https://phishing-initiative.lu)',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['apikey', 'url']


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('hostname'):
        toquery = request['hostname']
    elif request.get('domain'):
        toquery = request['domain']
    elif request.get('url'):
        toquery = request['url']
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    if not request.get('config') and not (request['config'].get('apikey') and request['config'].et('url')):
        misperrors['error'] = 'Phishing Initiative authentication is missing'
        return misperrors

    p = PyEUPI(request['config']['apikey'], request['config']['url'])
    results = p.search_url(url=toquery)

    if results.get('results'):
        to_return = ''
        for r in results['results']:
            if r['tag_label'] != 'phishing':
                continue
            to_return += ' {} {} {} '.format(r['url'], r['domain'], r['ip_address'])

        r = {'results': [{'types': mispattributes['output'], 'values': to_return}]}
        return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
