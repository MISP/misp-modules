import json
import pypssl
from pymisp import MISPAttribute, MISPEvent, MISPObject

mispattributes = {'input': ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'], 'format': 'misp_standard'}
moduleinfo = {'version': '0.2', 'author': 'Raphaël Vinot',
              'description': 'Module to access CIRCL Passive SSL',
              'module-type': ['expansion', 'hover']}
moduleconfig = ['username', 'password']


class PassiveSSLParser():
    def __init__(self, attribute, authentication):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.attribute)
        self.pssl = pypssl.PyPSSL(basic_auth=authentication)
        self.cert_hash = 'x509-fingerprint-sha1'
        self.cert_type = 'pem'
        self.mapping = {'issuer': ('text', 'issuer'),
                        'keylength': ('text', 'pubkey-info-size'),
                        'not_after': ('datetime', 'validity-not-after'),
                        'not_before': ('datetime', 'validity-not-before'),
                        'subject': ('text', 'subject')}

    def get_results(self):
        if hasattr(self, 'result'):
            return self.result
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object')}
        return {'results': results}

    def parse(self):
        value = self.attribute.value.split('|')[0] if '|' in self.attribute.type else self.attribute.value

        try:
            results = self.pssl.query(value)
        except Exception:
            self.result = {'error': 'There is an authentication error, please make sure you supply correct credentials.'}
            return

        if not results:
            self.result = {'error': 'Not found'}
            return

        if 'error' in results:
            self.result = {'error': results['error']}
            return

        for ip_address, certificates in results.items():
            ip_uuid = self._handle_ip_attribute(ip_address)
            for certificate in certificates['certificates']:
                self._handle_certificate(certificate, ip_uuid)

    def _handle_certificate(self, certificate, ip_uuid):
        x509 = MISPObject('x509')
        x509.add_attribute(self.cert_hash, type=self.cert_hash, value=certificate)
        cert_details = self.pssl.fetch_cert(certificate)
        info = cert_details['info']
        for feature, mapping in self.mapping.items():
            attribute_type, object_relation = mapping
            x509.add_attribute(object_relation, type=attribute_type, value=info[feature])
        x509.add_attribute(self.cert_type, type='text', value=self.cert_type)
        x509.add_reference(ip_uuid, 'seen-by')
        self.misp_event.add_object(**x509)

    def _handle_ip_attribute(self, ip_address):
        if ip_address == self.attribute.value:
            return self.attribute.uuid
        ip_attribute = MISPAttribute()
        ip_attribute.from_dict(**{'type': self.attribute.type, 'value': ip_address})
        self.misp_event.add_attribute(**ip_attribute)
        return ip_attribute.uuid


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config'):
        return {'error': 'CIRCL Passive SSL authentication is missing.'}
    if not request['config'].get('username') or not request['config'].get('password'):
        return {'error': 'CIRCL Passive SSL authentication is incomplete, please provide your username and password.'}
    authentication = (request['config']['username'], request['config']['password'])
    if not request.get('attribute'):
        return {'error': 'Unsupported input.'}
    attribute = request['attribute']
    if not any(input_type == attribute['type'] for input_type in mispattributes['input']):
        return {'error': 'Unsupported attributes type'}
    pssl_parser = PassiveSSLParser(attribute, authentication)
    pssl_parser.parse()
    return pssl_parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
