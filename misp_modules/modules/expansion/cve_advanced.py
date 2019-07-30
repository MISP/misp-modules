from pymisp import MISPEvent, MISPObject
import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['vulnerability'], 'format': 'misp_standard'}
moduleinfo = {'version': '1', 'author': 'Christian Studer',
              'description': 'An expansion module to enrich a CVE attribute with the vulnerability information.',
              'module-type': ['expansion', 'hover']}
moduleconfig = []
cveapi_url = 'https://cve.circl.lu/api/cve/'


class VulnerabilityParser():
    def __init__(self, vulnerability):
        self.vulnerability = vulnerability
        self.misp_event = MISPEvent()
        self.vulnerability_mapping = {
            'id': ('text', 'id'), 'summary': ('text', 'summary'),
            'vulnerable_configuration_cpe_2_2': ('text', 'vulnerable_configuration'),
            'Modified': ('datetime', 'modified'), 'Published': ('datetime', 'published'),
            'references': ('link', 'references'), 'cvss': ('float', 'cvss-score')}

    def get_result(self):
        event = json.loads(self.misp_event.to_json())['Event']
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}

    def parse_vulnerability_information(self):
        vulnerability_object = MISPObject('vulnerability')
        for feature in ('id', 'summary', 'Modified', 'cvss'):
            value = self.vulnerability.get(feature)
            if value:
                attribute_type, relation = self.vulnerability_mapping[feature]
                vulnerability_object.add_attribute(relation, **{'type': attribute_type, 'value': value})
        if 'Published' in self.vulnerability:
            vulnerability_object.add_attribute('published', **{'type': 'datetime', 'value': self.vulnerability['Published']})
            vulnerability_object.add_attribute('state', **{'type': 'text', 'value': 'Published'})
        for feature in ('references', 'vulnerable_configuration_cpe_2_2'):
            if feature in self.vulnerability:
                attribute_type, relation = self.vulnerability_mapping[feature]
                for value in self.vulnerability[feature]:
                    vulnerability_object.add_attribute(relation, **{'type': attribute_type, 'value': value})
        self.misp_event.add_object(**vulnerability_object)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    attribute = request.get('attribute')
    if attribute.get('type') != 'vulnerability':
        misperrors['error'] = 'Vulnerability id missing.'
        return misperrors
    r = requests.get("{}{}".format(cveapi_url, attribute['value']))
    if r.status_code == 200:
        vulnerability = r.json()
        if not vulnerability:
            misperrors['error'] = 'Non existing CVE'
            return misperrors['error']
    else:
        misperrors['error'] = 'cve.circl.lu API not accessible'
        return misperrors['error']
    parser = VulnerabilityParser(vulnerability)
    parser.parse_vulnerability_information()
    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
