import json
import requests

misperrors = {'error' : 'Error'}
mispattributes = {'input': ['hostname', 'domain', 'ip-src', 'ip-dst', 'module-username','module-password'], 'output': ['ip-src', 'ip-dst', 'hostname', 'domain']}
moduleinfo = {'version': '0.1', 'author': 'Alexandre Dulaunoy', 'description': 'SPassiveTotal expansion service to expand values with multiple Passive DNS sources'}
passivetotal_url = 'https://api.passivetotal.org/v2/dns/passive?query='

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if (request.get('module-username') is False) or (request.get('module-password') is False):
        misperrors['error'] = 'Passivetotal authentication is missing'
        return misperrors
    if request.get('hostname'):
        toquery = request['hostname']
        queryhost = True
    elif request.get('domain'):
        toquery = request['domain']
        queryhost = True
    elif request.get('ip-src'):
        toquery = request['ip-src']
        queryhost = False
    elif request.get('ip-dst'):
        toquery = request['ip-dst']
        queryhost = False
    else:
        return False

    r = requests.get(passivetotal_url+toquery, auth=(request.get('module-username'),request.get('module-password')))
    if r.status_code == 200:
        x = json.loads(r.text)
        a = []
        if queryhost:
            mispattributes['output'] = ['ip-src', 'ip-dst']
        else:
            mispattributes['output'] = ['hostname']

        for y in x['results']:
            if queryhost:
                a.append(y['resolve'])
            else:
                a.append(y['resolve'])
    elif r.status_code >= 400 and r.status_code < 404 :
        misperrors['error'] = 'Passivetotal.org incorrect authentication'
        return misperrors['error']
    else:
        misperrors['error'] = 'Passivetotal.org is not reachable'
        return misperrors['error']

    r = {'results': [{'types': mispattributes['output'], 'values': a}]}
    return r


def introspection():
    return mispattributes


def version():
    return moduleinfo
