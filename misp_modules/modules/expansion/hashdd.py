import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['md5'], 'output': ['text']}
moduleinfo = {'version': '0.2', 'author': 'Alexandre Dulaunoy', 'description': 'An expansion module to check hashes against hashdd.com including NSLR dataset.', 'module-type': ['hover']}
moduleconfig = []
hashddapi_url = 'https://api.hashdd.com/v1/knownlevel/nsrl/'


def handler(q=False):
    if q is False:
        return False
    v = None
    request = json.loads(q)
    for input_type in mispattributes['input']:
        if request.get(input_type):
            v = request[input_type].upper()
            break
    if v is None:
        misperrors['error'] = 'Hash value is missing.'
        return misperrors
    r = requests.get(hashddapi_url + v)
    if r.status_code == 200:
        state = json.loads(r.text)
        summary = state['knownlevel'] if state and state['result'] == "SUCCESS" else state['message']
    else:
        misperrors['error'] = '{} API not accessible'.format(hashddapi_url)
        return misperrors['error']

    r = {'results': [{'types': mispattributes['output'], 'values': summary}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
