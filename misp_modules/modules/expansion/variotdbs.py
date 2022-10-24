import json
import requests
from . import check_input_attribute, standard_error_message
from pymisp import MISPAttribute, MISPEvent, MISPObject

misperrors = {'error': 'Error'}
mispattributes = {'input': ['vulnerability'], 'format': 'misp_standard'}
moduleinfo = {'version': '1', 'author': 'Christian Studer',
              'description': 'An expansion module to query variotdbs.pl',
              'module-type': ['expansion', 'hover']}
moduleconfig = ['API_key']
variotdbs_url = 'https://www.variotdbs.pl/api'


class VariotdbsParser:
    def __init__(self, attribute):
        misp_attribute = MISPAttribute()
        misp_attribute.from_dict(**attribute)
        misp_event = MISPEvent()
        misp_event.add_attribute(**misp_attribute)
        self.__misp_attribute = misp_attribute
        self.__misp_event = misp_event
        self.__vulnerability_data_mapping = {
            'credits': 'credit',
            'description': 'description',
            'title': 'summary'
        }
        self.__vulnerability_flat_mapping = {
            'cve': 'id', 'id': 'id'
        }

    @property
    def misp_attribute(self) -> MISPAttribute:
        return self.__misp_attribute

    @property
    def misp_event(self) -> MISPEvent:
        return self.__misp_event

    @property
    def vulnerability_data_mapping(self) -> dict:
        return self.__vulnerability_data_mapping

    @property
    def vulnerability_flat_mapping(self) -> dict:
        return self.__vulnerability_flat_mapping

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if event.get(key)}
        return {'results': results}

    def parse_vulnerability_information(self, query_results):
        vulnerability_object = MISPObject('vulnerability')
        for feature, relation in self.vulnerability_flat_mapping.items():
            if query_results.get(feature):
                vulnerability_object.add_attribute(
                    relation,
                    query_results[feature]
                )
        for feature, relation in self.vulnerability_data_mapping.items():
            if query_results.get(feature, {}).get('data'):
                vulnerability_object.add_attribute(
                    relation,
                    query_results[feature]['data']
                )
        if query_results.get('configurations', {}).get('data'):
            for configuration in query_results['configurations']['data']:
                for node in configuration['nodes']:
                    for cpe_match in node['cpe_match']:
                        if cpe_match['vulnerable']:
                            vulnerability_object.add_attribute(
                                'vulnerable-configuration',
                                cpe_match['cpe23Uri']
                            )
        if query_results.get('cvss', {}).get('data'):
            cvss = {}
            for cvss_data in query_results['cvss']['data']:
                for cvss_v3 in cvss_data['cvssV3']:
                    cvss[float(cvss_v3['trust'])] = cvss_v3
            if cvss:
                cvss = cvss[max(cvss)]
                vulnerability_object.add_attribute(
                    'cvss-score',
                    cvss['baseScore']
                )
                vulnerability_object.add_attribute(
                    'cvss-string',
                    cvss['vectorString']
                )
        if query_results.get('references', {}).get('data'):
            for reference in query_results['references']['data']:
                vulnerability_object.add_attribute(
                    'references',
                    reference['url']
                )
        if query_results.get('sources_release_date', {}).get('data'):
            for release_date in query_results['sources_release_date']['data']:
                if release_date['db'] != 'NVD':
                    continue
                if release_date['id'] == self.misp_attribute.value:
                    vulnerability_object.add_attribute(
                        'published',
                        release_date['date']
                    )
                    break
        if query_results.get('sources_update_date', {}).get('data'):
            for update_date in query_results['sources_update_date']['data']:
                if update_date['db'] != 'NVD':
                    continue
                if update_date['id'] == self.misp_attribute.value:
                    vulnerability_object.add_attribute(
                        'modified',
                        update_date['date']
                    )
                    break
        vulnerability_object.add_reference(self.misp_attribute.uuid, 'related-to')
        self.misp_event.add_object(vulnerability_object)


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
            parser.parse_vulnerability_information(vulnerability_results)
            empty = False
    else:
        if r.reason != 'Not found':
            return {'error': 'Error while querying the variotdbs API.'}
    if empty:
        return {'error': 'Empty results'}
    return parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
