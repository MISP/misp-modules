import json
import sys

try:
    from dns.resolver import Resolver, NXDOMAIN
    from dns.name import LabelTooLong
    resolver = Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
except ImportError:
    sys.exit("dnspython3 in missing. use 'pip install dnspython3' to install it.")

misperrors = {'error': 'Error'}
mispattributes = {'input': ['btc'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'Checks if a BTC address is referenced as a scam.',
              'module-type': ['hover']}
moduleconfig = []

url = 'bl.btcblack.it'

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    btc = request['btc']
    query = f"{btc}.{url}"
    try:
        result = ' - '.join([str(r) for r in resolver.query(query, 'TXT')])[1:-1]
    except NXDOMAIN:
        result = f"{btc} is not known as a scam address."
    except LabelTooLong:
        result = f"{btc} is probably not a valid BTC address."
    return {'results': [{'types': mispattributes['output'], 'values': result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
