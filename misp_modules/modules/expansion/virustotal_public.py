from pymisp import MISPAttribute, MISPEvent, MISPObject
import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', "ip-src", "ip-dst", "md5", "sha1", "sha256", "url"],
                  'format': 'misp_standard'}
moduleinfo = {'version': '1', 'author': 'Christian Studer',
              'description': 'Get information from VirusTotal public API v2.',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['apikey']


class VirusTotalParser():
    def __init__(self):
        super(VirusTotalParser, self).__init__()
        self.misp_event = MISPEvent()

    def declare_variables(self, apikey, attribute):
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.apikey = apikey

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}

    def parse_urls(self, query_result):
        for feature in ('detected_urls', 'undetected_urls'):
            if feature in query_result:
                for url in query_result[feature]:
                    value = url['url'] if isinstance(url, dict) else url[0]
                    self.misp_event.add_attribute('url', value)

    def parse_resolutions(self, resolutions, subdomains=None, uuids=None):
        domain_ip_object = MISPObject('domain-ip')
        if self.attribute.type == 'domain':
            domain_ip_object.add_attribute('domain', type='domain', value=self.attribute.value)
            attribute_type, relation, key = ('ip-dst', 'ip', 'ip_address')
        else:
            domain_ip_object.add_attribute('ip', type='ip-dst', value=self.attribute.value)
            attribute_type, relation, key = ('domain', 'domain', 'hostname')
        for resolution in resolutions:
            domain_ip_object.add_attribute(relation, type=attribute_type, value=resolution[key])
        if subdomains:
            for subdomain in subdomains:
                attribute = MISPAttribute()
                attribute.from_dict(**dict(type='domain', value=subdomain))
                self.misp_event.add_attribute(**attribute)
                domain_ip_object.add_reference(attribute.uuid, 'subdomain')
        if uuids:
            for uuid in uuids:
                domain_ip_object.add_reference(uuid, 'sibling-of')
        self.misp_event.add_object(**domain_ip_object)

    def parse_vt_object(self, query_result):
        if query_result['response_code'] == 1:
            vt_object = MISPObject('virustotal-report')
            vt_object.add_attribute('permalink', type='link', value=query_result['permalink'])
            detection_ratio = '{}/{}'.format(query_result['positives'], query_result['total'])
            vt_object.add_attribute('detection-ratio', type='text', value=detection_ratio)
            self.misp_event.add_object(**vt_object)

    def get_query_result(self, query_type):
        params = {query_type: self.attribute.value, 'apikey': self.apikey}
        return requests.get(self.base_url, params=params)


class DomainQuery(VirusTotalParser):
    def __init__(self, apikey, attribute):
        super(DomainQuery, self).__init__()
        self.base_url = "https://www.virustotal.com/vtapi/v2/domain/report"
        self.declare_variables(apikey, attribute)

    def parse_report(self, query_result):
        hash_type = 'sha256'
        whois = 'whois'
        for feature_type in ('referrer', 'downloaded', 'communicating'):
            for feature in ('undetected_{}_samples', 'detected_{}_samples'):
                for sample in query_result.get(feature.format(feature_type), []):
                    self.misp_event.add_attribute(hash_type, sample[hash_type])
        if query_result.get(whois):
            whois_object = MISPObject(whois)
            whois_object.add_attribute('text', type='text', value=query_result[whois])
            self.misp_event.add_object(**whois_object)
        if 'domain_siblings' in query_result:
            siblings = (self.parse_siblings(domain) for domain in query_result['domain_siblings'])
            if 'subdomains' in query_result:
                self.parse_resolutions(query_result['resolutions'], query_result['subdomains'], siblings)
        self.parse_urls(query_result)

    def parse_siblings(self, domain):
        attribute = MISPAttribute()
        attribute.from_dict(**dict(type='domain', value=domain))
        self.misp_event.add_attribute(**attribute)
        return attribute.uuid


class HashQuery(VirusTotalParser):
    def __init__(self, apikey, attribute):
        super(HashQuery, self).__init__()
        self.base_url = "https://www.virustotal.com/vtapi/v2/file/report"
        self.declare_variables(apikey, attribute)

    def parse_report(self, query_result):
        file_attributes = []
        for hash_type in ('md5', 'sha1', 'sha256'):
            if query_result.get(hash_type):
                file_attributes.append({'type': hash_type, 'object_relation': hash_type,
                                        'value': query_result[hash_type]})
        if file_attributes:
            file_object = MISPObject('file')
            for attribute in file_attributes:
                file_object.add_attribute(**attribute)
            self.misp_event.add_object(**file_object)
        self.parse_vt_object(query_result)


class IpQuery(VirusTotalParser):
    def __init__(self, apikey, attribute):
        super(IpQuery, self).__init__()
        self.base_url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        self.declare_variables(apikey, attribute)

    def parse_report(self, query_result):
        if query_result.get('asn'):
            asn_mapping = {'network': ('ip-src', 'subnet-announced'),
                           'country': ('text', 'country')}
            asn_object = MISPObject('asn')
            asn_object.add_attribute('asn', type='AS', value=query_result['asn'])
            for key, value in asn_mapping.items():
                if query_result.get(key):
                    attribute_type, relation = value
                    asn_object.add_attribute(relation, type=attribute_type, value=query_result[key])
            self.misp_event.add_object(**asn_object)
        self.parse_urls(query_result)
        if query_result.get('resolutions'):
            self.parse_resolutions(query_result['resolutions'])


class UrlQuery(VirusTotalParser):
    def __init__(self, apikey, attribute):
        super(UrlQuery, self).__init__()
        self.base_url = "https://www.virustotal.com/vtapi/v2/url/report"
        self.declare_variables(apikey, attribute)

    def parse_report(self, query_result):
        self.parse_vt_object(query_result)


domain = ('domain', DomainQuery)
ip = ('ip', IpQuery)
file = ('resource', HashQuery)
misp_type_mapping = {'domain': domain, 'hostname': domain, 'ip-src': ip,
                     'ip-dst': ip, 'md5': file, 'sha1': file, 'sha256': file,
                     'url': ('resource', UrlQuery)}


def parse_error(status_code):
    status_mapping = {204: 'VirusTotal request rate limit exceeded.',
                      400: 'Incorrect request, please check the arguments.',
                      403: 'You don\'t have enough privileges to make the request.'}
    if status_code in status_mapping:
        return status_mapping[status_code]
    return "VirusTotal may not be accessible."


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = "A VirusTotal api key is required for this module."
        return misperrors
    attribute = request['attribute']
    query_type, to_call = misp_type_mapping[attribute['type']]
    parser = to_call(request['config']['apikey'], attribute)
    query_result = parser.get_query_result(query_type)
    status_code = query_result.status_code
    if status_code == 200:
        parser.parse_report(query_result.json())
    else:
        misperrors['error'] = parse_error(status_code)
        return misperrors
    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
