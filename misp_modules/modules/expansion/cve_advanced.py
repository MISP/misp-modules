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
        self.references = defaultdict(list)
        self.capec_features = ('id', 'name', 'summary', 'prerequisites', 'solutions')
        self.vulnerability_mapping = {
            'id': ('text', 'id'), 'summary': ('text', 'summary'),
            'vulnerable_configuration_cpe_2_2': ('text', 'vulnerable_configuration'),
            'Modified': ('datetime', 'modified'), 'Published': ('datetime', 'published'),
            'references': ('link', 'references'), 'cvss': ('float', 'cvss-score')}
        self.weakness_mapping = {'name': 'name', 'description_summary': 'description',
                                 'status': 'status', 'weaknessabs': 'weakness-abs'}

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
        if 'cwe' in self.vulnerability:
            self.__parse_weakness(vulnerability_object.uuid)
        if 'capec' in self.vulnerability:
            self.__parse_capec(vulnerability_object.uuid)

    def __parse_capec(self, vulnerability_uuid):
        attribute_type = 'text'
        for capec in self.vulnerability['capec']:
            capec_object = MISPObject('capec')
            for feature in self.capec_features:
                capec_object.add_attribute(feature, **dict(type=attribute_type, value=capec[feature]))
            for related_weakness in capec['related_weakness']:
                attribute = dict(type='weakness', value="CWE-{}".format(related_weakness))
                capec_object.add_attribute('related-weakness', **attribute)
            self.misp_event.add_object(**capec_object)

    def __parse_weakness(self, vulnerability_uuid):
        attribute_type = 'text'
        cwe_string, cwe_id  = self.vulnerability['cwe'].split('-')
        cwes = requests.get(cveapi_url.replace('/cve/', '/cwe'))
        if cwes.status_code == 200:
            for cwe in cwes.json():
                if cwe['id'] == cwe_id:
                    weakness_object = MISPObject('weakness')
                    weakness_object.add_attribute('id', **dict(type=attribute_type, value='-'.join([cwe_string, cwe_id])))
                    for feature, relation in self.weakness_mapping.items():
                        if cwe.get(feature):
                            weakness_object.add_attribute(relation, **dict(type=attribute_type, value=cwe[feature]))
                    self.misp_event.add_object(**weakness_object)
                    break


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
