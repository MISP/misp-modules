import json
from ._dnsdb_query.dnsdb_query import DnsdbClient, QueryError


misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', 'ip-src', 'ip-dst'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'Christophe Vandeplas', 'description': 'Module to access Farsight DNSDB Passive DNS', 'module-type': ['expansion', 'hover']}
moduleconfig = ['apikey']

server = 'https://api.dnsdb.info'

# TODO return a MISP object with the different attributes


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = 'Farsight DNSDB apikey is missing'
        return misperrors
    client = DnsdbClient(server, request['config']['apikey'])
    if request.get('hostname'):
        res = lookup_name(client, request['hostname'])
    elif request.get('domain'):
        res = lookup_name(client, request['domain'])
    elif request.get('ip-src'):
        res = lookup_ip(client, request['ip-src'])
    elif request.get('ip-dst'):
        res = lookup_ip(client, request['ip-dst'])
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    out = ''
    for v in set(res):  # uniquify entries
        out = out + "{} ".format(v)
    r = {'results': [{'types': mispattributes['output'], 'values': out}]}
    return r


def lookup_name(client, name):
    try:
        res = client.query_rrset(name)  # RRSET = entries in the left-hand side of the domain name related labels
        for item in res:
            if item.get('rrtype') in ['A', 'AAAA', 'CNAME']:
                for i in item.get('rdata'):
                    yield(i.rstrip('.'))
            if item.get('rrtype') in ['SOA']:
                for i in item.get('rdata'):
                    # grab email field and replace first dot by @ to convert to an email address
                    yield(i.split(' ')[1].rstrip('.').replace('.', '@', 1))
    except QueryError:
        pass

    try:
        res = client.query_rdata_name(name)  # RDATA = entries on the right-hand side of the domain name related labels
        for item in res:
            if item.get('rrtype') in ['A', 'AAAA', 'CNAME']:
                yield(item.get('rrname').rstrip('.'))
    except QueryError:
        pass


def lookup_ip(client, ip):
    try:
        res = client.query_rdata_ip(ip)
        for item in res:
            yield(item['rrname'].rstrip('.'))
    except QueryError:
        pass


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
