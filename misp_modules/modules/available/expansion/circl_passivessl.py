import json
import pypssl

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-src', 'ip-dst'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot', 'description': 'Module to access CIRCL Passive SSL', 'module-type': ['expansion', 'hover']}
moduleconfig = ['username', 'password']


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

    if request.get('config'):
        if (request['config'].get('username') is None) or (request['config'].get('password') is None):
            misperrors['error'] = 'CIRCL Passive SSL authentication is missing'
            return misperrors

    x = pypssl.PyPSSL(basic_auth=(request['config']['username'], request['config']['password']))
    res = x.query(toquery)
    out = res.get(toquery)

    r = {'results': [{'types': mispattributes['output'], 'values': out}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
