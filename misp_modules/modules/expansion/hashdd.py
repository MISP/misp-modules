import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['md5'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Alexandre Dulaunoy', 'description': 'An expansion module to check hashes against hashdd.com including NSLR dataset.', 'module-type': ['hover']}
moduleconfig = []
hashddapi_url = 'https://api.hashdd.com/'


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('md5'):
        misperrors['error'] = 'MD5 hash value is missing missing'
        return misperrors
    v = request.get('md5').upper()
    r = requests.post(hashddapi_url, data={'hash':v})
    if r.status_code == 200:
        state = json.loads(r.text)
        if state:
            if state.get(v):
                summary = state[v]['known_level']
        else:
            summary = 'Unknown hash'
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
