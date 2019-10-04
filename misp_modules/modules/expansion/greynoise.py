import requests
import json

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-dst', 'ip-src'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Aurélien Schwab <aurelien.schwab+dev@gmail.com>', 'description': 'Module to access GreyNoise.io API.', 'module-type': ['hover']}
moduleconfig = ['user-agent']  # TODO take this into account in the code

greynoise_api_url = 'http://api.greynoise.io:8888/v1/query/ip'
default_user_agent = 'MISP-Module'


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    for input_type in mispattributes['input']:
        if input_type in request:
            ip = request[input_type]
            break
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    data = {'ip': ip}
    r = requests.post(greynoise_api_url, data=data, headers={'user-agent': default_user_agent})  # Real request
    if r.status_code == 200:  # OK (record found)
        response = r.text
        if response:
            return {'results': [{'types': mispattributes['output'], 'values': response}]}
    elif r.status_code == 404:  # Not found (not an error)
        return {'results': [{'types': mispattributes['output'], 'values': 'No data'}]}
    else:  # Real error
        misperrors['error'] = 'GreyNoise API not accessible (HTTP ' + str(r.status_code) + ')'
        return misperrors['error']


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
