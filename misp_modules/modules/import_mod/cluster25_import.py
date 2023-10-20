import json
import requests
from typing import List
from . import standard_error_message
from pymisp import MISPAttribute, MISPEvent

moduleinfo = {'version': '0.1',
              'author': 'Milo Volpicelli',
              'description': 'Module to query and import indicators from Cluster25CTI',
              'module-type': ['import']}
moduleconfig = ['api_id', 'apikey', 'base_url']
misperrors = {'error': 'Error'}
misp_type_in = ['domain', 'email', 'filename', 'md5', 'sha1', 'sha256',  'ip', 'url', 'vulnerability', 'btc',
                'xmr', 'ja3-fingerprint-md5']
mapping_out = {  # mapping between the MISP attributes type and the compatible Cluster25 indicator types.
    'domain': {'type': 'domain', 'to_ids': True},
    'email': {'type': 'email', 'to_ids': True},
    'filename': {'type': 'filename', 'to_ids': True},
    'md5': {'type': 'md5', 'to_ids': True},
    'sha1': {'type': 'sha1', 'to_ids': True},
    'sha256': {'type': 'sha256', 'to_ids': True},
    'ipv4': {'type': 'ip', 'to_ids': True},
    'ipv6': {'type': 'ip', 'to_ids': True},
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
    if not request.get('params') or not not request.get('params', {}).get('type'):
        return {'error': f'{standard_error_message}, which should contain a type'}
    attribute = request.get('params')
    if not any(input_type == attribute.get('type') for input_type in misp_type_in):
        return {'error': 'Unsupported attribute type.'}

    client = Cluster25CTI(request['config']['api_id'], request['config']['apikey'], request['config']['base_url'])

    r = {"results": []}
    valid_type = False

    try:
        for k in misp_type_in:
            if attribute.type == k:
                # map the MISP type to the Cluster25 type
                r['results'].append(lookup_indicator(client, attribute))
                valid_type = True
    except Exception as e:
        return {'error': f"{e}"}

    if not valid_type:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    return {'results': r.get('results').pop()}


def lookup_indicator(client, ref_attribute):
    limit = ref_attribute.limit
    if not limit:
        limit = 1000
    result = client.search_indicators(ref_attribute.type, limit)
    misp_event = MISPEvent()

    for item in result:
        if mapping_out.get(item.get('type')):
            r = mapping_out[item.get('type')].copy()
            r['value'] = item
            attribute = MISPAttribute()
            attribute.from_dict(**r)
            misp_event.add_attribute(**attribute)

    event = json.loads(misp_event.to_json())
    return {'Object': event.get('Object', []), 'Attribute': event.get('Attribute', [])}


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

    def _get_cluster25_token(self) -> str:
        payload = {"client_id": self.client_id, "client_secret": self.client_secret}
        r = requests.post(url=f"{self.base_url}/token", json=payload, headers={"Content-Type": "application/json"})

        if r.status_code != 200:
            raise Exception(
                f"Unable to retrieve the token from C25 platform, status {r.status_code}"
            )
        return r.json()["data"]["token"]

    def search_indicators(self, indicator_type, limit) -> List[dict]:
        headers = {"Authorization": f"Bearer {self.current_token}"}
        params = {'type': indicator_type, 'limit': limit}
        r = requests.get(url=f"{self.base_url}/indicators", params=params, headers=headers)

        if r.status_code != 200:
            raise Exception(
                f"Unable to retrieve the indicators from C25 platform, status {r.status_code}"
            )
        return r.json()["data"]


