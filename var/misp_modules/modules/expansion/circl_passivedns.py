import json
import pypdns

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', 'ip-src', 'ip-dst'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'Alexandre Dulaunoy', 'description': 'Module to access CIRCL Passive DNS', 'module-type': ['expansion', 'hover']}
moduleconfig = ['username', 'password']


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('hostname'):
        toquery = request['hostname']
    elif request.get('domain'):
        toquery = request['domain']
    elif request.get('ip-src'):
        toquery = request['ip-src']
    elif request.get('ip-dst'):
        toquery = request['ip-dst']
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    if (request.get('config')):
        if (request['config'].get('username') is None) or (request['config'].get('password') is None):
            misperrors['error'] = 'CIRCL Passive DNS authentication is missing'
            return misperrors

    x = pypdns.PyPDNS(basic_auth=(request['config']['username'], request['config']['password']))
    res = x.query(toquery)
    out = ''
    for v in res:
            out = out + "{} ".format(v['rdata'])

    r = {'results': [{'types': mispattributes['output'], 'values': out}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
