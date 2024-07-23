import json
import requests
from . import check_input_attribute, standard_error_message
from ._vulnerability_parser.vulnerability_parser import (
    VulnerabilityMapping, VulnerabilityParser)
from pymisp import MISPObject

misperrors = {'error': 'Error'}
mispattributes = {'input': ['vulnerability'], 'format': 'misp_standard'}
moduleinfo = {'version': '1', 'author': 'Christian Studer',
              'description': 'An expansion module to query variotdbs.pl',
              'module-type': ['expansion', 'hover']}
moduleconfig = ['API_key']
variotdbs_url = 'https://www.variotdbs.pl/api'


class VariotMapping(VulnerabilityMapping):
    __exploit_mapping = {
        'credits': 'credit',
        'description': 'description',
        'exploit': 'exploit',
        'title': 'title'
    }
    __exploit_multiple_mapping = {
        'cve': {
            'feature': 'cve_id',
            'relation': 'cve-id'
        },
        'references': {
            'feature': 'url',
            'relation': 'reference'
        }
    }

    @classmethod
    def exploit_mapping(cls) -> dict:
        return cls.__exploit_mapping

    @classmethod
    def exploit_multiple_mapping(cls) -> dict:
        return cls.__exploit_multiple_mapping


class VariotdbsParser(VulnerabilityParser):
    def __init__(self, attribute):
        super().__init__(attribute)
        self.__mapping = VulnerabilityMapping

    @property
    def mapping(self) -> VulnerabilityMapping:
        return self.__mapping

    def parse_exploit_information(self, query_results):
        for exploit in query_results:
            exploit_object = MISPObject('exploit')
            exploit_object.add_attribute('exploitdb-id', exploit['edb_id'])
            for field, relation in self.mapping.exploit_mapping().items():
                if exploit.get(field):
                    exploit_object.add_attribute(
                        relation, exploit[field]['data']
                    )
            for field, relation in self.mapping.exploit_multiple_mapping().items():
                if exploit.get(field):
                    for value in exploit[field]['data']:
                        exploit_object.add_attribute(
                            relation['relation'], value[relation['feature']]
                        )
            exploit_object.add_reference(self.misp_attribute.uuid, 'related-to')
            self.misp_event.add_object(exploit_object)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('attribute') or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
    attribute = request['attribute']
    if attribute.get('type') != 'vulnerability':
        return {'error': 'Vulnerability id missing.'}
    headers = {'Content-Type': 'application/json'}
    if request.get('config', {}).get('API_key'):
        headers['Authorization'] = f"Token {request['config']['API_key']}"
    empty = True
    parser = VariotdbsParser(attribute)
    r = requests.get(f"{variotdbs_url}/vuln/{attribute['value']}/", headers=headers)
    if r.status_code == 200:
        vulnerability_results = r.json()
        if vulnerability_results:
            parser._parse_variot_description(vulnerability_results)
            empty = False
    else:
        if r.reason != 'Not Found':
            return {'error': 'Error while querying the variotdbs API.'}
    r = requests.get(f"{variotdbs_url}/exploits/?cve={attribute['value']}", headers=headers)
    if r.status_code == 200:
        exploit_results = r.json()
        if exploit_results:
            parser.parse_exploit_information(exploit_results['results'])
            empty = False
            if exploit_results['next'] is not None:
                while(1):
                    exploit_results = requests.get(exploit_results['next'], headers=headers)
                    if exploit_results.status_code != 200:
                        break
                    exploit_results = exploit_results.json()
                    parser.parse_exploit_information(exploit_results['results'])
                    if exploit_results['next'] is None:
                        break
    else:
        return {'error': 'Error while querying the variotdbs API.'}
    if empty:
        return {'error': 'Empty results'}
    return parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
