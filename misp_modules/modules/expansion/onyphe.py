import json
# -*- coding: utf-8 -*-

import json
try:
    from onyphe import Onyphe
except ImportError:
    print("pyonyphe module not installed.")

misperrors = {'error': 'Error'}

mispattributes = {'input': ['ip-src', 'ip-dst', 'hostname', 'domains'], 'output': ['hostname', 'domain', 'ip-src', 'ip-dst','url']}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Sebastien Larinier @sebdraven',
              'description': 'Query on Onyphe',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ['apikey']



def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if not request.get('config') and not (request['config'].get('apikey')):
        misperrors['error'] = 'Onyphe authentication is missing'
        return misperrors

    api = Onyphe(request['config'].get('apikey'))

    if not api:
        misperrors['error'] = 'Onyphe Error instance api'

    ip = ''
    if request.get('ip-src'):
        ip = request['ip-src']
    elif request.get('ip-dst'):
        ip = request['ip-dst']
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    return handle_expansion(api, ip, misperrors)


def handle_expansion(api, ip, misperrors):
    result = api.ip(ip)

    if result['status'] == 'nok':
        misperrors['error'] = result['message']
        return misperrors

    categories = list(set([item['@category'] for item in result['results']]))

    result_filtered =  {"results": []}
    urls_pasties = []
    for r in result['results']:
        if r['@category'] == 'pastries':
            if r['@type'] == 'pastebin':
                urls_pasties.append('https://pastebin.com/raw/%s' % r['key'])
            result_filtered['results'].append({'types': ['url'], 'values': urls_pasties})

    return result_filtered


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo