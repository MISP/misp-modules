from pymisp import MISPAttribute, MISPEvent, MISPObject
import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['domain', 'hostname', 'ip-src', 'ip-dst', 'md5', 'sha256', 'url'],
                  'output': ['url', 'filename', 'md5', 'sha256'],
                  'format': 'misp_standard'}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'Query of the URLhaus API to get additional information about some attributes.',
              'module-type': ['expansion', 'hover']}
moduleconfig = []

file_keys = ('filename', 'response_size', 'response_md5', 'response_sha256')
file_relations = ('filename', 'size-in-bytes', 'md5', 'sha256')
vt_keys = ('result', 'link')
vt_types = ('text', 'link')
vt_relations = ('detection-ratio', 'permalink')


class URLhaus():
    def __init__(self):
        super(URLhaus, self).__init__()
        self.misp_event = MISPEvent()

    @staticmethod
    def _create_vt_object(virustotal):
        vt_object = MISPObject('virustotal-report')
        for key, vt_type, relation in zip(vt_keys, vt_types, vt_relations):
            vt_object.add_attribute(relation, **{'type': vt_type, 'value': virustotal[key]})
        return vt_object

    def get_result(self):
        event = json.loads(self.misp_event.to_json())['Event']
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}


class HostQuery(URLhaus):
    def __init__(self, attribute):
        super(HostQuery, self).__init__()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.url = 'https://urlhaus-api.abuse.ch/v1/host/'

    def query_api(self):
        response = requests.post(self.url, data={'host': self.attribute.value}).json()
        if 'urls' in response and response['urls']:
            for url in response['urls']:
                self.misp_event.add_attribute(type='url', value=url['url'])


class PayloadQuery(URLhaus):
    def __init__(self, attribute):
        super(PayloadQuery, self).__init__()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.url = 'https://urlhaus-api.abuse.ch/v1/payload/'

    def query_api(self):
        hash_type = self.attribute.type
        file_object = MISPObject('file')
        if self.attribute.event_id != '0':
            file_object.id = self.attribute.object_id
        response = requests.post(self.url, data={'{}_hash'.format(hash_type): self.attribute.value}).json()
        other_hash_type = 'md5' if hash_type == 'sha256' else 'sha256'
        for key, relation in zip(('{}_hash'.format(other_hash_type), 'file_size'), (other_hash_type, 'size-in-bytes')):
            if response[key]:
                file_object.add_attribute(relation, **{'type': relation, 'value': response[key]})
        if response['virustotal']:
            vt_object = self._create_vt_object(response['virustotal'])
            file_object.add_reference(vt_object.uuid, 'analyzed-with')
            self.misp_event.add_object(**vt_object)
        _filename_ = 'filename'
        for url in response['urls']:
            attribute = MISPAttribute()
            attribute.from_dict(type='url', value=url['url'])
            self.misp_event.add_attribute(**attribute)
            file_object.add_reference(attribute.uuid, 'retrieved-from')
            if url[_filename_]:
                file_object.add_attribute(_filename_, **{'type': _filename_, 'value': url[_filename_]})
        if any((file_object.attributes, file_object.references)):
            self.misp_event.add_object(**file_object)


class UrlQuery(URLhaus):
    def __init__(self, attribute):
        super(UrlQuery, self).__init__()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.url = 'https://urlhaus-api.abuse.ch/v1/url/'

    @staticmethod
    def _create_file_object(payload):
        file_object = MISPObject('file')
        for key, relation in zip(file_keys, file_relations):
            if payload[key]:
                file_object.add_attribute(relation, **{'type': relation, 'value': payload[key]})
        return file_object

    def query_api(self):
        response = requests.post(self.url, data={'url': self.attribute.value}).json()
        if 'payloads' in response and response['payloads']:
            for payload in response['payloads']:
                file_object = self._create_file_object(payload)
                if payload['virustotal']:
                    vt_object = self._create_vt_object(payload['virustotal'])
                    file_object.add_reference(vt_object.uuid, 'analyzed-with')
                    self.misp_event.add_object(**vt_object)
                if any((file_object.attributes, file_object.references)):
                    self.misp_event.add_object(**file_object)


_misp_type_mapping = {'url': UrlQuery, 'md5': PayloadQuery, 'sha256': PayloadQuery,
                      'domain': HostQuery, 'hostname': HostQuery,
                      'ip-src': HostQuery, 'ip-dst': HostQuery}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    attribute = request['attribute']
    urlhaus_parser = _misp_type_mapping[attribute['type']](attribute)
    urlhaus_parser.query_api()
    return urlhaus_parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
