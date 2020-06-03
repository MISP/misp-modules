import requests
import json

misperrors = {'error': 'Error'}
mispattributes = {'input': ['mac-address'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Aurélien Schwab', 'description': 'Module to access Macvendors API.', 'module-type': ['hover']}
moduleconfig = ['user-agent']

macvendors_api_url = 'https://api.macvendors.com/'
default_user_agent = 'MISP-Module'


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    for input_type in mispattributes['input']:
        if input_type in request:
            mac = request[input_type]
            break
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    user_agent = request['config']['user-agent'] if request.get('config') and request['config'].get('user-agent') else default_user_agent
    r = requests.get(macvendors_api_url + mac, headers={'user-agent': user_agent})  # Real request
    if r.status_code == 200:  # OK (record found)
        response = r.text
        if response:
            return {'results': [{'types': mispattributes['output'], 'values': response}]}
    elif r.status_code == 404:  # Not found (not an error)
        return {'results': [{'types': mispattributes['output'], 'values': 'Not found'}]}
    else:  # Real error
        misperrors['error'] = 'MacVendors API not accessible (HTTP ' + str(r.status_code) + ')'
        return misperrors['error']


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
