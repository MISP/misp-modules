import json
import dns.resolver

mispattributes = {'input': ['hostname', 'domain'], 'output': ['ip-src', 'ip-dst']}
moduleinfo = "0.1"


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('hostname'):
        toquery = request['hostname']
    elif request.get('domain'):
        toquery = request['domain']
    else:
        return False
    r = dns.resolver.Resolver()
    r.nameservers = ['8.8.8.8']
    try:
        answer = r.query(toquery, 'A')
    except dns.resolver.NXDOMAIN:
        return False
    except dns.exception.Timeout:
        return False
    r = {'results': [{'types': mispattributes['output'], 'values':[str(answer[0])]}]}
    return r


def introspection():
    return mispattributes


def version():
    return moduleinfo
