import json
from ._dnsdb_query.dnsdb_query import DEFAULT_DNSDB_SERVER, DnsdbClient, QueryError
from . import check_input_attribute, standard_error_message
from pymisp import MISPEvent, MISPObject

misperrors = {'error': 'Error'}
mispattributes = {
    'input': ['hostname', 'domain', 'ip-src', 'ip-dst']#,
    # 'format': 'misp_standard'
}
moduleinfo = {
    'version': '0.2',
    'author': 'Christophe Vandeplas',
    'description': 'Module to access Farsight DNSDB Passive DNS',
    'module-type': ['expansion', 'hover']
}
moduleconfig = ['apikey', 'server', 'limit']

DEFAULT_LIMIT = 10


class FarsightDnsdbParser():
    def __init__(self, attribute):
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.passivedns_mapping = {
            'bailiwick': {'type': 'text', 'object_relation': 'bailiwick'},
            'count': {'type': 'counter', 'object_relation': 'count'},
            'rdata': {'type': 'text', 'object_relation': 'rdata'},
            'rrname': {'type': 'text', 'object_relation': 'rrname'},
            'rrtype': {'type': 'text', 'object_relation': 'rrtype'},
            'time_first': {'type': 'datetime', 'object_relation': 'time_first'},
            'time_last': {'type': 'datetime', 'object_relation': 'time_last'},
            'zone_time_first': {'type': 'datetime', 'object_relation': 'zone_time_first'},
            'zone_time_last': {'type': 'datetime', 'object_relation': 'zone_time_last'}
        }

    def parse_passivedns_results(self, query_response):
        default_fields = ('count', 'rrname', 'rrname')
        optional_fields = (
            'bailiwick',
            'time_first',
            'time_last',
            'zone_time_first',
            'zone_time_last'
        )
        for result in query_response:
            passivedns_object = MISPObject('passive-dns')
            for feature in default_fields:
                passivedns_object.add_attribute(**self._parse_attribute(feature, result[feature]))
            for feature in optional_fields:
                if result.get(feature):
                    passivedns_object.add_attribute(**self._parse_attribute(
                        feature,
                        result[feature]
                    ))
            if isinstance(result['rdata'], list):
                for rdata in result['rdata']:
                    passivedns_object.add_attribute(**self._parse_attribute('rdata', rdata))
            else:
                passivedns_object.add_attribute(**self._parse_attribute('rdata', result['rdata']))
            self.misp_event.add_object(passivedns_object)

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object')}
        return {'results': results}

    def _parse_attribute(self, feature, value):
        attribute = {'value': value}
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
    args = {'apikey': config['apikey']}
    for feature, default in zip(('server', 'limit'), (DEFAULT_DNSDB_SERVER, DEFAULT_LIMIT)):
        args[feature] = config[feature] if config.get(feature) else default
    client = DnsdbClient(**args)
    to_query = lookup_ip if attribute['type'] in ('ip-src', 'ip-dst') else lookup_name
    response = to_query(client, attribute['value'])
    if not response:
        return {'error': f"Empty results on Farsight DNSDB for the queries {attribute['type']}: {attribute['value']}."}
    parser = FarsightDnsdbParser(attribute)
    parser.parse_passivedns_results(response)
    return parser.get_results()


def lookup_name(client, name):
    try:
        res = client.query_rrset(name)  # RRSET = entries in the left-hand side of the domain name related labels
        response = list(res)
    except QueryError:
        response = []
    try:
        res = client.query_rdata_name(name)  # RDATA = entries on the right-hand side of the domain name related labels
        response.extend(list(res))
    except QueryError:
        pass
    return response


def lookup_ip(client, ip):
    try:
        res = client.query_rdata_ip(ip)
        response = list(res)
    except QueryError:
        response = []
    return response


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
