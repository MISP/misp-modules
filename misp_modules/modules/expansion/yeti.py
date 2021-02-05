import json

try:
    import pyeti
except ImportError:
    print("pyeti module not installed.")

misperrors = {'error': 'Error'}

mispattributes = {'input': ['ip-src', 'ip-dst', 'hostname', 'domain'],
                  'output': ['hostname', 'domain', 'ip-src', 'ip-dst', 'url']}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Sebastien Larinier @sebdraven',
              'description': 'Query on yeti',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['apikey', 'url']


class Yeti:

    def __init__(self, url, key):
        self.api = pyeti.YetiApi(url, api_key=key)
        self.dict = {'Ip': 'ip-src', 'Domain': 'domain', 'Hostname': 'hostname'}

    def search(self, value):
        obs = self.api.observable_search(value=value)
        if obs:
            return obs


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    attribute = request['attribute']


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

def introspection():
    return mispattributes