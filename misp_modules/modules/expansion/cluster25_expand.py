import json
import requests
import uuid
from . import check_input_attribute, standard_error_message
from pymisp import MISPAttribute, MISPEvent, MISPObject

moduleinfo = {'version': '0.1',
              'author': 'Milo Volpicelli',
              'description': 'Module to query Cluster25CTI',
              'module-type': ['expansion', 'hover']}
moduleconfig = ['api_id', 'apikey', 'base_url']
misperrors = {'error': 'Error'}
misp_type_in = ['domain', 'email-src', 'email-dst', 'filename', 'md5', 'sha1', 'sha256',  'ip-src', 'ip-dst', 'url',
                'vulnerability', 'btc', 'xmr', 'ja3-fingerprint-md5']

mapping_out = {  # mapping between the MISP attributes type and the compatible Cluster25 indicator types.
    'domain': {'type': 'domain', 'to_ids': True},
    'email-src': {'type': 'email-src', 'to_ids': True},
    'email-dst': {'type': 'email-dst', 'to_ids': True},
    'filename': {'type': 'filename', 'to_ids': True},
    'md5': {'type': 'md5', 'to_ids': True},
    'sha1': {'type': 'sha1', 'to_ids': True},
    'sha256': {'type': 'sha256', 'to_ids': True},
    'ip-src': {'type': 'ip-src', 'to_ids': True},
    'ip-dst': {'type': 'ip-dst', 'to_ids': True},
    'url': {'type': 'url', 'to_ids': True},
    'cve': {'type': 'vulnerability', 'to_ids': True},
    'btcaddress': {'type': 'btc', 'to_ids': True},
    'xmraddress': {'type': 'xmr', 'to_ids': True},
    'ja3': {'type': 'ja3-fingerprint-md5', 'to_ids': True},
}
misp_type_out = [item['type'] for item in mapping_out.values()]
misp_attributes = {'input': misp_type_in, 'format': 'misp_standard'}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    # validate Cluster25 params
    if request.get('config'):
        if request['config'].get('apikey') is None:
            misperrors['error'] = 'Cluster25 apikey is missing'
            return misperrors
        if request['config'].get('api_id') is None:
            misperrors['error'] = 'Cluster25 api_id is missing'
            return misperrors
        if request['config'].get('base_url') is None:
            misperrors['error'] = 'Cluster25 base_url is missing'
            return misperrors

    # validate attribute
    if not request.get('attribute') or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
    attribute = request.get('attribute')
    if not any(input_type == attribute.get('type') for input_type in misp_type_in):
        return {'error': 'Unsupported attribute type.'}

    client = Cluster25CTI(request['config']['api_id'], request['config']['apikey'], request['config']['base_url'])

    return lookup_indicator(client, request.get('attribute'))


def format_content(content):
    if isinstance(content, str) or isinstance(content, bool) or isinstance(content, int):
        return content
    ret = ""
    tmp_ret = []
    if content is None:
        return ret
    is_dict = isinstance(content, dict)
    is_list = isinstance(content, list)
    for index, key in enumerate(content):
        if is_dict:
            if isinstance(content[key], dict):
                ret = format_content(content[key])

            elif isinstance(content[key], list):
                for list_item in content[key]:
                    tmp_ret.append(format_content(list_item))
            else:
                tmp_ret.append(f"{key}: {content[key]}")
        elif is_list:
            if isinstance(content[index], str):
                ret = ", ".join(content)
            else:
                ret = format_content(content)
    if tmp_ret:
        ret = " ".join(tmp_ret)
    return ret


def lookup_indicator(client, attr):

    result = client.investigate(attr)
    if result.get('error'):
        return result
    misp_event = MISPEvent()
    attribute = MISPAttribute()
    attribute.from_dict(**attr)
    misp_event.add_attribute(**attribute)

    misp_object_g = MISPObject('c25_generic_info')
    misp_object_g.template_uuid = uuid.uuid4()
    misp_object_g.description = 'c25_generic_info'
    setattr(misp_object_g, 'meta-category', 'network')

    misp_objects = []
    for ind, entry in enumerate(result):
        if isinstance(result[entry], dict):
            tmp_obj = MISPObject(f"c25_{entry}")
            tmp_obj.template_uuid = uuid.uuid4()
            tmp_obj.description = f"c25_{entry}"
            setattr(tmp_obj, 'meta-category', 'network')
            tmp_obj.add_reference(attribute['uuid'], 'related-to')
            for key in result[entry]:
                if isinstance(result[entry][key], dict):
                    for index, key2 in enumerate(result[entry][key]):
                        if result[entry][key][key2]:
                            tmp_obj.add_attribute(f"{entry}_{key}_{key2}", **{'type': 'text', 'value': format_content(
                                result[entry][key][key2])})

                elif isinstance(result[entry][key], list):
                    for index, key2 in enumerate(result[entry][key]):
                        if isinstance(key2, dict):
                            tmp_obj_2 = MISPObject(f"c25_{entry}_{key}_{index+1}")
                            tmp_obj_2.template_uuid = uuid.uuid4()
                            tmp_obj_2.description = f"c25_{entry}_{key}"
                            setattr(tmp_obj_2, 'meta-category', 'network')
                            tmp_obj_2.add_reference(attribute['uuid'], 'related-to')
                            for k in key2:
                                if key2[k]:
                                    tmp_obj_2.add_attribute(k, **{'type': 'text', 'value': format_content(key2[k])})
                            misp_objects.append(tmp_obj_2)
                        elif key2 is not None:
                            tmp_obj.add_attribute(f"{entry}_{key}", **{'type': 'text', 'value': format_content(key2)})
                elif result[entry][key] is not None:
                    tmp_obj.add_attribute(key, **{'type': 'text', 'value': result[entry][key]})

            if tmp_obj.attributes:
                misp_objects.append(tmp_obj)

        elif isinstance(result[entry], list):
            for index, key in enumerate(result[entry]):
                if isinstance(key, dict):
                    tmp_obj = MISPObject(f"c25_{entry}_{index+1}")
                    tmp_obj.template_uuid = uuid.uuid4()
                    tmp_obj.description = f"c25_{entry}_{index+1}"
                    setattr(tmp_obj, 'meta-category', 'network')
                    tmp_obj.add_reference(attribute['uuid'], 'related-to')
                    for key2 in key:
                        if key[key2]:
                            tmp_obj.add_attribute(key2, **{'type': 'text', 'value': format_content(key[key2])})
                    tmp_obj.add_reference(attribute['uuid'], 'related-to')
                    misp_objects.append(tmp_obj)
                elif key is not None:
                    misp_object_g.add_attribute(entry, **{'type': 'text', 'value': format_content(key)})
        else:
            if result[entry]:
                misp_object_g.add_attribute(entry, **{'type': 'text', 'value': result[entry]})

    misp_object_g.add_reference(attribute['uuid'], 'related-to')
    misp_event.add_object(misp_object_g)
    for misp_object in misp_objects:
        misp_event.add_object(misp_object)

    event = json.loads(misp_event.to_json())
    results = {key: event[key] for key in ('Attribute', 'Object')}
    return {'results': results}


def introspection():
    return misp_attributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


class Cluster25CTI:
    def __init__(self, customer_id=None, customer_key=None, base_url=None):
        self.client_id = customer_id
        self.client_secret = customer_key
        self.base_url = base_url
        self.current_token = self._get_cluster25_token()
        self.headers = {"Authorization": f"Bearer {self.current_token}"}

    def _get_cluster25_token(self):
        payload = {"client_id": self.client_id, "client_secret": self.client_secret}
        r = requests.post(url=f"{self.base_url}/token", json=payload, headers={"Content-Type": "application/json"})
        if r.status_code != 200:
            return {'error': f"Unable to retrieve the token from C25 platform, status {r.status_code}"}
        return r.json()["data"]["token"]

    def investigate(self, indicator) -> dict:
        params = {'indicator': indicator.get('value')}
        r = requests.get(url=f"{self.base_url}/investigate", params=params, headers=self.headers)
        if r.status_code != 200:
            return{'error': f"Unable to retrieve investigate result for indicator '{indicator.get('value')}' "
                            f"from C25 platform, status {r.status_code}"}
        return r.json()["data"]
