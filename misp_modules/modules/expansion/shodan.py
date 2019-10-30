# -*- coding: utf-8 -*-

import json
try:
    import shodan
except ImportError:
    print("shodan module not installed.")

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-src', 'ip-dst'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot',
              'description': 'Query on Shodan',
              'module-type': ['expansion']}

moduleconfig = ['apikey']


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

    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = 'Shodan authentication is missing'
        return misperrors
    api = shodan.Shodan(request['config'].get('apikey'))

    return handle_expansion(api, toquery)


def handle_expansion(api, domain):
    return {'results': [{'types': mispattributes['output'], 'values': json.dumps(api.host(domain))}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
