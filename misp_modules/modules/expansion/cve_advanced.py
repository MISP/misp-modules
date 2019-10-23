from collections import defaultdict
from pymisp import MISPEvent, MISPObject
import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['vulnerability'], 'format': 'misp_standard'}
moduleinfo = {'version': '1', 'author': 'Christian Studer',
              'description': 'An expansion module to enrich a CVE attribute with the vulnerability information.',
              'module-type': ['expansion', 'hover']}
moduleconfig = ["custom_API"]
cveapi_url = 'https://cve.circl.lu/api/cve/'


class VulnerabilityParser():
    def __init__(self, attribute, vulnerability, api_url):
        self.attribute = attribute
        self.vulnerability = vulnerability
        self.api_url = api_url
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.references = defaultdict(list)
        self.capec_features = ('id', 'name', 'summary', 'prerequisites', 'solutions')
        self.vulnerability_mapping = {
            'id': ('text', 'id'), 'summary': ('text', 'summary'),
            'vulnerable_configuration': ('text', 'vulnerable_configuration'),
            'vulnerable_configuration_cpe_2_2': ('text', 'vulnerable_configuration'),
            'Modified': ('datetime', 'modified'), 'Published': ('datetime', 'published'),
            'references': ('link', 'references'), 'cvss': ('float', 'cvss-score')}
        self.weakness_mapping = {'name': 'name', 'description_summary': 'description',
                                 'status': 'status', 'weaknessabs': 'weakness-abs'}

    def get_result(self):
        if self.references:
            self.__build_references()
        event = json.loads(self.misp_event.to_json())
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
        for feature in ('references', 'vulnerable_configuration', 'vulnerable_configuration_cpe_2_2'):
            if feature in self.vulnerability:
                attribute_type, relation = self.vulnerability_mapping[feature]
                for value in self.vulnerability[feature]:
                    if isinstance(value, dict):
                        value = value['title']
                    vulnerability_object.add_attribute(relation, **{'type': attribute_type, 'value': value})
        vulnerability_object.add_reference(self.attribute['uuid'], 'related-to')
        self.misp_event.add_object(**vulnerability_object)
        if 'cwe' in self.vulnerability and self.vulnerability['cwe'] not in ('Unknown', 'NVD-CWE-noinfo'):
            self.__parse_weakness(vulnerability_object.uuid)
        if 'capec' in self.vulnerability:
            self.__parse_capec(vulnerability_object.uuid)

    def __build_references(self):
        for object_uuid, references in self.references.items():
            for misp_object in self.misp_event.objects:
                if misp_object.uuid == object_uuid:
                    for reference in references:
                        misp_object.add_reference(**reference)
                    break

    def __parse_capec(self, vulnerability_uuid):
        attribute_type = 'text'
        for capec in self.vulnerability['capec']:
            capec_object = MISPObject('attack-pattern')
            for feature in self.capec_features:
                capec_object.add_attribute(feature, **dict(type=attribute_type, value=capec[feature]))
            for related_weakness in capec['related_weakness']:
                attribute = dict(type='weakness', value="CWE-{}".format(related_weakness))
                capec_object.add_attribute('related-weakness', **attribute)
            self.misp_event.add_object(**capec_object)
            self.references[vulnerability_uuid].append(dict(referenced_uuid=capec_object.uuid,
                                                            relationship_type='targeted-by'))

    def __parse_weakness(self, vulnerability_uuid):
        attribute_type = 'text'
        cwe_string, cwe_id = self.vulnerability['cwe'].split('-')
        cwes = requests.get(self.api_url.replace('/cve/', '/cwe'))
        if cwes.status_code == 200:
            for cwe in cwes.json():
                if cwe['id'] == cwe_id:
                    weakness_object = MISPObject('weakness')
                    weakness_object.add_attribute('id', **dict(type=attribute_type, value='-'.join([cwe_string, cwe_id])))
                    for feature, relation in self.weakness_mapping.items():
                        if cwe.get(feature):
                            weakness_object.add_attribute(relation, **dict(type=attribute_type, value=cwe[feature]))
                    self.misp_event.add_object(**weakness_object)
                    self.references[vulnerability_uuid].append(dict(referenced_uuid=weakness_object.uuid,
                                                                    relationship_type='weakened-by'))
                    break


def check_url(url):
    return "{}/".format(url) if not url.endswith('/') else url


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    attribute = request.get('attribute')
    if attribute.get('type') != 'vulnerability':
        misperrors['error'] = 'Vulnerability id missing.'
        return misperrors
    api_url = check_url(request['config']['custom_API']) if request['config'].get('custom_API') else cveapi_url
    r = requests.get("{}{}".format(api_url, attribute['value']))
    if r.status_code == 200:
        vulnerability = r.json()
        if not vulnerability:
            misperrors['error'] = 'Non existing CVE'
            return misperrors['error']
    else:
        misperrors['error'] = 'API not accessible'
        return misperrors['error']
    parser = VulnerabilityParser(attribute, vulnerability, api_url)
    parser.parse_vulnerability_information()
    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
