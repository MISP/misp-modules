import requests
import json

misperrors = {'error': 'Error'}
mispattributes = {'input': ['email-dst', 'email-src'], 'output': ['text']}#All mails as input
moduleinfo = {'version': '0.1', 'author': 'Aurélien Schwab', 'description': 'Module to access haveibeenpwned.com API.', 'module-type': ['hover']}
moduleconfig = ['user-agent']#TODO take this into account in the code

haveibeenpwned_api_url = 'https://api.haveibeenpwned.com/api/v2/breachedaccount/'
default_user_agent = 'MISP-Module'#User agent (must be set, requiered by API))

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    for input_type in mispattributes['input']:
        if input_type in request:
            email = request[input_type]
            break
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    r = requests.get(haveibeenpwned_api_url + email, headers={'user-agent': default_user_agent})#Real request
    if r.status_code == 200:##OK (record found)
        breaches = json.loads(r.text)
        if breaches:
            return {'results': [{'types': mispattributes['output'], 'values': breaches}]}
    elif r.status_code == 404:#Not found (not an error)
        return {'results': [{'types': mispattributes['output'], 'values': 'OK (Not Found)'}]}
    else:#Real error
        misperrors['error'] = 'haveibeenpwned.com API not accessible (HTTP ' + str(r.status_code) + ')'
        return misperrors['error']

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
