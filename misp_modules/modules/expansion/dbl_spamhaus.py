import json
import sys

try:
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 0.2
    resolver.lifetime = 0.2
except ImportError:
    print("dnspython3 is missing, use 'pip install dnspython3' to install it.")
    sys.exit(0)

misperrors = {'error': 'Error'}
mispattributes = {'input': ['domain', 'domain|ip', 'hostname', 'hostname|port'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'Checks Spamhaus DBL for a domain name.',
              'module-type': ['expansion', 'hover']}
moduleconfig = []

dbl = 'dbl.spamhaus.org'
dbl_mapping = {'127.0.1.2': 'spam domain',
               '127.0.1.4': 'phish domain',
               '127.0.1.5': 'malware domain',
               '127.0.1.6': 'botnet C&C domain',
               '127.0.1.102': 'abused legit spam',
               '127.0.1.103': 'abused spammed redirector domain',
               '127.0.1.104': 'abused legit phish',
               '127.0.1.105': 'abused legit malware',
               '127.0.1.106': 'abused legit botnet C&C',
               '127.0.1.255': 'IP queries prohibited!'}


def fetch_requested_value(request):
    for attribute_type in mispattributes['input']:
        if request.get(attribute_type):
            return request[attribute_type].split('|')[0]
    return None


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    requested_value = fetch_requested_value(request)
    if requested_value is None:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    query = "{}.{}".format(requested_value, dbl)
    try:
        query_result = resolver.query(query, 'A')[0]
        result = "{} - {}".format(requested_value, dbl_mapping[str(query_result)])
    except dns.resolver.NXDOMAIN as e:
        result = e.msg
    except Exception:
        return {'error': 'Not able to reach dbl.spamhaus.org or something went wrong'}
    return {'results': [{'types': mispattributes.get('output'), 'values': result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
