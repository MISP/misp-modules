# -*- coding: utf-8 -*-

import json

from pymisp import MISPEvent

try:
    from onyphe import Onyphe
except ImportError:
    print("pyonyphe module not installed.")

misperrors = {'error': 'Error'}

mispattributes = {'input': ['ip-src', 'ip-dst', 'hostname', 'domain'],
                  'output': ['hostname', 'domain', 'ip-src', 'ip-dst', 'url'],
                  'format': 'misp_standard'}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '2', 'author': 'Sebastien Larinier @sebdraven',
              'description': 'Query on Onyphe',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ['apikey']


class OnypheClient:

    def __init__(self, api_key, attribute):
        self.onyphe_client = Onyphe(api_key=api_key)
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)

    def parser_results(self):
        pass

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if key in event}
        return results


def handler(q=False):
    if q:

        request = json.loads(q)
        attribute = request['attribute']

        if not request.get('config') or not request['config'].get('apikey'):
            misperrors['error'] = 'Onyphe authentication is missing'
            return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
