import json
import requests
from . import check_input_attribute, standard_error_message
from pymisp import MISPEvent, MISPObject

misperrors = {'error': 'Error'}
mispattributes = {'input': ['cpe'], 'format': 'misp_standard'}
moduleinfo = {
    'version': '1',
    'author': 'Christian Studer',
    'description': 'An expansion module to enrich a CPE attribute with its related vulnerabilities.',
    'module-type': ['expansion', 'hover']
}
moduleconfig = ["custom_API_URL", "limit"]
cveapi_url = 'https://cvepremium.circl.lu/api/cvefor/'


class VulnerabilitiesParser():
    def __init__(self, attribute, api_url):
        self.attribute = attribute
        self.api_url = api_url
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.vulnerability_mapping = {
            'id': {
                'type': 'vulnerability',
                'object_relation': 'id'
            },
            'summary': {
                'type': 'text',
                'object_relation': 'summary'
            },
            'vulnerable_configuration': {
                'type': 'cpe',
                'object_relation': 'vulnerable_configuration'
            },
            'vulnerable_configuration_cpe_2_2': {
                'type': 'cpe',
                'object_relation': 'vulnerable_configuration'
            },
            'Modified': {
                'type': 'datetime',
                'object_relation': 'modified'
            },
            'Published': {
                'type': 'datetime',
                'object_relation': 'published'
            },
            'references': {
                'type': 'link',
                'object_relation': 'references'
            },
            'cvss': {
                'type': 'float',
                'object_relation': 'cvss-score'
            }
        }

    def parse_vulnerabilities(self, vulnerabilities):
        for vulnerability in vulnerabilities:
            vulnerability_object = MISPObject('vulnerability')
            for feature in ('id', 'summary', 'Modified', 'Published', 'cvss'):
                if vulnerability.get(feature):
                    attribute = {'value': vulnerability[feature]}
                    attribute.update(self.vulnerability_mapping[feature])
                    vulnerability_object.add_attribute(**attribute)
            if vulnerability.get('Published'):
                vulnerability_object.add_attribute(**{
                    'type': 'text',
                    'object_relation': 'state',
                    'value': 'Published'
                })
            for feature in ('references', 'vulnerable_configuration', 'vulnerable_configuration_cpe_2_2'):
                if vulnerability.get(feature):
                    for value in vulnerability[feature]:
                        if isinstance(value, dict):
                            value = value['title']
                        attribute = {'value': value}
                        attribute.update(self.vulnerability_mapping[feature])
                        vulnerability_object.add_attribute(**attribute)
            vulnerability_object.add_reference(self.attribute['uuid'], 'related-to')
            self.misp_event.add_object(vulnerability_object)

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object')}
        return {'results': results}


def check_url(url):
    return url if url.endswith('/') else f"{url}/"


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('attribute') or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
    attribute = request['attribute']
    if attribute.get('type') != 'cpe':
        return {'error': 'Wrong input attribute type.'}
    api_url = check_url(request['config']['custom_API_URL']) if request['config'].get('custom_API_URL') else cveapi_url
    url = f"{api_url}{attribute['value']}"
    if request['config'].get('limit'):
        url = f"{url}/{request['config']['limit']}"
    response = requests.get(url)
    if response.status_code == 200:
        vulnerabilities = response.json()
        if not vulnerabilities:
            return {'error': 'No related vulnerability for this CPE.'}
    else:
        return {'error': 'API not accessible.'}
    parser = VulnerabilitiesParser(attribute, api_url)
    parser.parse_vulnerabilities(vulnerabilities)
    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
