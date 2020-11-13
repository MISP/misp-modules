import dnsdb2
import json
from . import check_input_attribute, standard_error_message
from pymisp import MISPEvent, MISPObject

misperrors = {'error': 'Error'}
mispattributes = {
    'input': ['hostname', 'domain', 'ip-src', 'ip-dst'],
    'format': 'misp_standard'
}
moduleinfo = {
    'version': '0.4',
    'author': 'Christophe Vandeplas',
    'description': 'Module to access Farsight DNSDB Passive DNS',
    'module-type': ['expansion', 'hover']
}
moduleconfig = ['apikey', 'server', 'limit', 'flex_queries']

DEFAULT_DNSDB_SERVER = 'https://api.dnsdb.info'
DEFAULT_LIMIT = 10


class FarsightDnsdbParser():
    def __init__(self, attribute):
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.passivedns_mapping = {
            'bailiwick': {'type': 'text', 'object_relation': 'bailiwick'},
            'count': {'type': 'counter', 'object_relation': 'count'},
            'raw_rdata': {'type': 'text', 'object_relation': 'raw_rdata'},
            'rdata': {'type': 'text', 'object_relation': 'rdata'},
            'rrname': {'type': 'text', 'object_relation': 'rrname'},
            'rrtype': {'type': 'text', 'object_relation': 'rrtype'},
            'time_first': {'type': 'datetime', 'object_relation': 'time_first'},
            'time_last': {'type': 'datetime', 'object_relation': 'time_last'},
            'zone_time_first': {'type': 'datetime', 'object_relation': 'zone_time_first'},
            'zone_time_last': {'type': 'datetime', 'object_relation': 'zone_time_last'}
        }
        self.type_to_feature = {
            'domain': 'domain name',
            'hostname': 'hostname',
            'ip-src': 'IP address',
            'ip-dst': 'IP address'
        }
        self.comment = 'Result from an %s lookup on DNSDB about the %s: %s'

    def parse_passivedns_results(self, query_response):
        for query_type, results in query_response.items():
            comment = self.comment % (query_type, self.type_to_feature[self.attribute['type']], self.attribute['value'])
            for result in results:
                passivedns_object = MISPObject('passive-dns')
                if result.get('rdata') and isinstance(result['rdata'], list):
                    for rdata in result.pop('rdata'):
                        passivedns_object.add_attribute(**self._parse_attribute(comment, 'rdata', rdata))
                for feature, value in result.items():
                    passivedns_object.add_attribute(**self._parse_attribute(comment, feature, value))
                passivedns_object.add_reference(self.attribute['uuid'], 'related-to')
                self.misp_event.add_object(passivedns_object)

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object')}
        return {'results': results}

    def _parse_attribute(self, comment, feature, value):
        attribute = {'value': value, 'comment': comment}
        attribute.update(self.passivedns_mapping[feature])
        return attribute


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = 'Farsight DNSDB apikey is missing'
        return misperrors
    if not request.get('attribute') or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
    attribute = request['attribute']
    if attribute['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attributes type'}
    config = request['config']
    if not config.get('server'):
        config['server'] = DEFAULT_DNSDB_SERVER
    client_args = {feature: config[feature] for feature in ('apikey', 'server')}
    client = dnsdb2.Client(**client_args)
    flex = add_flex_queries(config.get('flex_queries'))
    if not config.get('limit'):
        config['limit'] = DEFAULT_LIMIT
    lookup_args = {
        'limit': config['limit'],
        'offset': 0,
        'ignore_limited': True
    }
    to_query = lookup_ip if attribute['type'] in ('ip-src', 'ip-dst') else lookup_name
    try:
        response = to_query(client, attribute['value'], lookup_args, flex)
    except dnsdb2.DnsdbException as e:
        return {'error': e.__str__()}
    if not response:
        return {'error': f"Empty results on Farsight DNSDB for the {self.type_to_feature[attribute['type']]}: {attribute['value']}."}
    parser = FarsightDnsdbParser(attribute)
    parser.parse_passivedns_results(response)
    return parser.get_results()


def add_flex_queries(flex):
    if not flex:
        return False
    if flex in ('True', 'true', True, '1', 1):
        return True
    return False


def flex_queries(client, name, lookup_args):
    response = {}
    rdata = list(client.flex_rdata_regex(name.replace('.', '\.'), **lookup_args))
    if rdata:
        response['flex_rdata'] = rdata
    rrnames = list(client.flex_rrnames_regex(name.replace('.', '\.'), **lookup_args))
    if rrnames:
        response['flex_rrnames'] = rrnames
    return response


def lookup_name(client, name, lookup_args, flex):
    response = {}
    # RRSET = entries in the left-hand side of the domain name related labels
    rrset_response = list(client.lookup_rrset(name, **lookup_args))
    if rrset_response:
        response['rrset'] = rrset_response
    # RDATA = entries on the right-hand side of the domain name related labels
    rdata_response = client.lookup_rdata_name(name, **lookup_args)
    if rdata_response:
        response['rdata'] = rdata_response
    if flex:
        response.update(flex_queries(client, name, lookup_args))
    return response


def lookup_ip(client, ip, lookup_args, flex):
    response = {}
    res = list(client.lookup_rdata_ip(ip, **lookup_args))
    if res:
        response['rdata'] = res
    if flex:
        response.update(flex_queries(client, ip, lookup_args))
    return response


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
