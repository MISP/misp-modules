from collections import defaultdict
from pymisp import MISPAttribute, MISPObject
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


def _create_file_object(file_attributes):
    return _create_object(file_attributes, 'file')


def _create_object(attributes, name):
    misp_object = MISPObject(name)
    for relation, attribute in attributes.items():
        misp_object.add_attribute(relation, **attribute)
    return [misp_object]


def _create_objects_with_relationship(file_attributes, vt_attributes):
    vt_object = _create_vt_object(vt_attributes)[0]
    vt_uuid = vt_object.uuid
    file_object = _create_file_object(file_attributes)[0]
    file_object.add_reference(vt_uuid, 'analysed-with')
    return [file_object, vt_object]


def _create_url_attribute(value):
    attribute = MISPAttribute()
    attribute.from_dict(type='url', value=value)
    return attribute


def _create_vt_object(vt_attributes):
    return _create_object(vt_attributes, 'virustotal_report')


def _handle_payload_urls(response):
    filenames = []
    urls = []
    if response:
        for url in response:
            urls.append(url['url'])
            if url['filename']:
                filenames.append(url['filename'])
    return filenames, urls


def _query_host_api(attribute):
    response = requests.post('https://urlhaus-api.abuse.ch/v1/host/', data={'host': attribute['value']}).json()
    attributes = []
    if 'urls' in response and response['urls']:
        for url in response['urls']:
            attributes.append(_create_url_attribute(url['url']).to_dict())
    return {'results': {'Attribute': attributes}}


def _query_payload_api(attribute):
    hash_type = attribute['type']
    response = requests.post('https://urlhaus-api.abuse.ch/v1/payload/', data={'{}_hash'.format(hash_type): attribute['value']}).json()
    results = defaultdict(list)
    filenames, urls = _handle_payload_urls(response['urls'])
    other_hash_type = 'md5' if hash_type == 'sha256' else 'sha256'
    file_object = MISPObject('file')
    if attribute['object_id'] != '0':
        file_object.id = attribute['object_id']
    for key, relation in zip(('{}_hash'.format(other_hash_type), 'file_size'), (other_hash_type, 'size-in-bytes')):
        if response[key]:
            file_object.add_attribute(relation, **{'type': relation, 'value': response[key]})
    for filename in filenames:
        file_object.add_attribute('filename', **{'type': 'filename', 'value': filename})
    for url in urls:
        attribute = _create_url_attribute(url)
        results['Attribute'].append(attribute.to_dict())
        file_object.add_reference(attribute.uuid, 'retrieved-from')
    results['Object'].append(file_object.to_dict())
    return {'results': results}


def _query_url_api(attribute):
    response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data={'url': attribute['value']}).json()
    results = defaultdict(list)
    if 'payloads' in response and response['payloads']:
        objects_mapping = {1: _create_file_object, 2: _create_vt_object, 3: _create_objects_with_relationship}
        file_keys = ('filename', 'response_size', 'response_md5', 'response_sha256')
        file_relations = ('filename', 'size-in-bytes', 'md5', 'sha256')
        vt_keys = ('result', 'link')
        vt_types = ('text', 'link')
        vt_relations = ('detection-ratio', 'permalink')
        for payload in response['payloads']:
            args = []
            object_score = 0
            file_attributes = {relation: {'type': relation, 'value': payload[key]} for key, relation in zip(file_keys, file_relations) if payload[key]}
            if file_attributes:
                object_score += 1
                args.append(file_attributes)
            if payload['virustotal']:
                virustotal = payload['virustotal']
                vt_attributes = {relation: {'type': vt_type, 'value': virustotal[key]} for key, vt_type, relation in zip(vt_keys, vt_types, vt_relations)}
                if vt_attributes:
                    object_score += 2
                    args.append(vt_attributes)
            try:
                results['Object'].extend([misp_object.to_dict() for misp_object in objects_mapping[object_score](*args)])
            except KeyError:
                continue
    return {'results': results}


_misp_type_mapping = {'url': _query_url_api, 'md5': _query_payload_api, 'sha256': _query_payload_api,
                      'domain': _query_host_api, 'hostname': _query_host_api,
                      'ip-src': _query_host_api, 'ip-dst': _query_host_api}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    attribute = request['attribute']
    return _misp_type_mapping[attribute['type']](attribute)


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
