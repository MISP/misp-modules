import json
import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

misperrors = {'error': 'Error'}
mispattributes = {'input': ['domain', 'hostname'], 'format': 'misp_standard'}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'On demand query API for APIVoid.',
              'module-type': ['expansion', 'hover']}
moduleconfig = ['apikey']


class APIVoidParser():
    def __init__(self, attribute):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.attribute)
        self.url = 'https://endpoint.apivoid.com/{}/v1/pay-as-you-go/?key={}&'

    def get_results(self):
        if hasattr(self, 'result'):
            return self.result
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object')}
        return {'results': results}

    def parse_domain(self, apikey):
        feature = 'dnslookup'
        if requests.get(f'{self.url.format(feature, apikey)}stats').json()['credits_remained'] < 0.13:
            self.result = {'error': 'You do not have enough APIVoid credits to proceed your request.'}
            return
        mapping = {'A': 'resolution-of', 'MX': 'mail-server-of', 'NS': 'server-name-of'}
        dnslookup = requests.get(f'{self.url.format(feature, apikey)}action=dns-any&host={self.attribute.value}').json()
        for item in dnslookup['data']['records']['items']:
            record_type = item['type']
            try:
                relationship = mapping[record_type]
            except KeyError:
                continue
            self._handle_dns_record(item, record_type, relationship)
        ssl = requests.get(f'{self.url.format("sslinfo", apikey)}host={self.attribute.value}').json()
        self._parse_ssl_certificate(ssl['data']['certificate'])

    def _handle_dns_record(self, item, record_type, relationship):
        dns_record = MISPObject('dns-record')
        dns_record.add_attribute('queried-domain', type='domain', value=item['host'])
        attribute_type, feature = ('ip-dst', 'ip') if record_type == 'A' else ('domain', 'target')
        dns_record.add_attribute(f'{record_type.lower()}-record', type=attribute_type, value=item[feature])
        dns_record.add_reference(self.attribute.uuid, relationship)
        self.misp_event.add_object(**dns_record)

    def _parse_ssl_certificate(self, certificate):
        x509 = MISPObject('x509')
        fingerprint = 'x509-fingerprint-sha1'
        x509.add_attribute(fingerprint, type=fingerprint, value=certificate['fingerprint'])
        x509_mapping = {'subject': {'name': ('text', 'subject')},
                        'issuer': {'common_name': ('text', 'issuer')},
                        'signature': {'serial': ('text', 'serial-number')},
                        'validity': {'valid_from': ('datetime', 'validity-not-before'),
                                     'valid_to': ('datetime', 'validity-not-after')}}
        certificate = certificate['details']
        for feature, subfeatures in x509_mapping.items():
            for subfeature, mapping in subfeatures.items():
                attribute_type, relation = mapping
                x509.add_attribute(relation, type=attribute_type, value=certificate[feature][subfeature])
        x509.add_reference(self.attribute.uuid, 'seen-by')
        self.misp_event.add_object(**x509)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config', {}).get('apikey'):
        return {'error': 'An API key for APIVoid is required.'}
    attribute = request.get('attribute')
    apikey = request['config']['apikey']
    apivoid_parser = APIVoidParser(attribute)
    apivoid_parser.parse_domain(apikey)
    return apivoid_parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
