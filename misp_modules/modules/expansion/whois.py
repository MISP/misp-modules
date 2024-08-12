# -*- coding: utf-8 -*-

import json
try:
    from uwhois import Uwhois
except ImportError:
    print("uwhois module not installed.")

misperrors = {'error': 'Error'}
mispattributes = {'input': ['domain', 'ip-src', 'ip-dst'], 'output': ['freetext']}
moduleinfo = {
    'version': '0.1',
    'author': 'Raphaël Vinot',
    'description': 'Module to query a local instance of uwhois (https://github.com/rafiot/uwhoisd).',
    'module-type': ['expansion'],
    'name': 'Whois Lookup',
    'logo': '',
    'requirements': ['uwhois: A whois python library'],
    'features': "This module takes a domain or IP address attribute as input and queries a 'Univseral Whois proxy server' to get the correct details of the Whois query on the input value (check the references for more details about this whois server).",
    'references': ['https://github.com/rafiot/uwhoisd'],
    'input': 'A domain or IP address attribute.',
    'output': 'Text describing the result of a whois request for the input value.',
}

moduleconfig = ['server', 'port']


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('domain'):
        toquery = request['domain']
    elif request.get('ip-src'):
        toquery = request['ip-src']
    elif request.get('ip-dst'):
        toquery = request['ip-dst']
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    if not request.get('config') or (not request['config'].get('server') and not request['config'].get('port')):
        misperrors['error'] = 'Whois local instance address is missing'
        return misperrors

    uwhois = Uwhois(request['config']['server'], int(request['config']['port']))

    if 'event_id' in request:
        return handle_expansion(uwhois, toquery)


def handle_expansion(w, domain):
    return {'results': [{'types': mispattributes['output'], 'values': w.query(domain)}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
