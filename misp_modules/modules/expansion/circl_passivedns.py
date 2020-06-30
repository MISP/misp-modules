import json
import pypdns
from pymisp import MISPAttribute, MISPEvent, MISPObject

mispattributes = {'input': ['hostname', 'domain', 'ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'], 'format': 'misp_standard'}
moduleinfo = {'version': '0.2', 'author': 'Alexandre Dulaunoy',
              'description': 'Module to access CIRCL Passive DNS',
              'module-type': ['expansion', 'hover']}
moduleconfig = ['username', 'password']


class PassiveDNSParser():
    def __init__(self, attribute, authentication):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.attribute)
        self.pdns = pypdns.PyPDNS(basic_auth=authentication)

    def get_results(self):
        if hasattr(self, 'result'):
            return self.result
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object')}
        return {'results': results}

    def parse(self):
        value = self.attribute.value.split('|')[0] if '|' in self.attribute.type else self.attribute.value

        try:
            results = self.pdns.query(value)
        except Exception:
            self.result = {'error': 'There is an authentication error, please make sure you supply correct credentials.'}
            return

        if not results:
            self.result = {'error': 'Not found'}
            return

        mapping = {'count': 'counter', 'origin': 'text',
                   'time_first': 'datetime', 'rrtype': 'text',
                   'rrname': 'text', 'rdata': 'text',
                   'time_last': 'datetime'}
        for result in results:
            pdns_object = MISPObject('passive-dns')
            for relation, attribute_type in mapping.items():
                pdns_object.add_attribute(relation, type=attribute_type, value=result[relation])
            pdns_object.add_reference(self.attribute.uuid, 'associated-to')
            self.misp_event.add_object(**pdns_object)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config'):
        return {'error': 'CIRCL Passive DNS authentication is missing.'}
    if not request['config'].get('username') or not request['config'].get('password'):
        return {'error': 'CIRCL Passive DNS authentication is incomplete, please provide your username and password.'}
    authentication = (request['config']['username'], request['config']['password'])
    if not request.get('attribute'):
        return {'error': 'Unsupported input.'}
    attribute = request['attribute']
    if not any(input_type == attribute['type'] for input_type in mispattributes['input']):
        return {'error': 'Unsupported attributes type'}
    pdns_parser = PassiveDNSParser(attribute, authentication)
    pdns_parser.parse()
    return pdns_parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
