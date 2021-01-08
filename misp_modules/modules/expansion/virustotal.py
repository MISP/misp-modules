from pymisp import MISPAttribute, MISPEvent, MISPObject
import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', "ip-src", "ip-dst", "md5", "sha1", "sha256", "url"],
                  'format': 'misp_standard'}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '4', 'author': 'Hannah Ward',
              'description': 'Get information from VirusTotal',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "event_limit"]


class VirusTotalParser(object):
    def __init__(self, apikey, limit):
        self.apikey = apikey
        self.limit = limit
        self.base_url = "https://www.virustotal.com/vtapi/v2/{}/report"
        self.misp_event = MISPEvent()
        self.parsed_objects = {}
        self.input_types_mapping = {'ip-src': self.parse_ip, 'ip-dst': self.parse_ip,
                                    'domain': self.parse_domain, 'hostname': self.parse_domain,
                                    'md5': self.parse_hash, 'sha1': self.parse_hash,
                                    'sha256': self.parse_hash, 'url': self.parse_url}

    def query_api(self, attribute):
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        return self.input_types_mapping[self.attribute.type](self.attribute.value, recurse=True)

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}

    ################################################################################
    ####                         Main parsing functions                         #### # noqa
    ################################################################################

    def parse_domain(self, domain, recurse=False):
        req = requests.get(self.base_url.format('domain'), params={'apikey': self.apikey, 'domain': domain})
        if req.status_code != 200:
            return req.status_code
        req = req.json()
        hash_type = 'sha256'
        whois = 'whois'
        feature_types = {'communicating': 'communicates-with',
                         'downloaded': 'downloaded-from',
                         'referrer': 'referring'}
        siblings = (self.parse_siblings(domain) for domain in req['domain_siblings'])
        uuid = self.parse_resolutions(req['resolutions'], req['subdomains'], siblings)
        for feature_type, relationship in feature_types.items():
            for feature in ('undetected_{}_samples', 'detected_{}_samples'):
                for sample in req.get(feature.format(feature_type), [])[:self.limit]:
                    status_code = self.parse_hash(sample[hash_type], False, uuid, relationship)
                    if status_code != 200:
                        return status_code
        if req.get(whois):
            whois_object = MISPObject(whois)
            whois_object.add_attribute('text', type='text', value=req[whois])
            self.misp_event.add_object(**whois_object)
        return self.parse_related_urls(req, recurse, uuid)

    def parse_hash(self, sample, recurse=False, uuid=None, relationship=None):
        req = requests.get(self.base_url.format('file'), params={'apikey': self.apikey, 'resource': sample})
        status_code = req.status_code
        if req.status_code == 200:
            req = req.json()
            vt_uuid = self.parse_vt_object(req)
            file_attributes = []
            for hash_type in ('md5', 'sha1', 'sha256'):
                if req.get(hash_type):
                    file_attributes.append({'type': hash_type, 'object_relation': hash_type,
                                            'value': req[hash_type]})
            if file_attributes:
                file_object = MISPObject('file')
                for attribute in file_attributes:
                    file_object.add_attribute(**attribute)
                file_object.add_reference(vt_uuid, 'analyzed-with')
                if uuid and relationship:
                    file_object.add_reference(uuid, relationship)
                self.misp_event.add_object(**file_object)
        return status_code

    def parse_ip(self, ip, recurse=False):
        req = requests.get(self.base_url.format('ip-address'), params={'apikey': self.apikey, 'ip': ip})
        if req.status_code != 200:
            return req.status_code
        req = req.json()
        if req.get('asn'):
            asn_mapping = {'network': ('ip-src', 'subnet-announced'),
                           'country': ('text', 'country')}
            asn_object = MISPObject('asn')
            asn_object.add_attribute('asn', type='AS', value=req['asn'])
            for key, value in asn_mapping.items():
                if req.get(key):
                    attribute_type, relation = value
                    asn_object.add_attribute(relation, type=attribute_type, value=req[key])
            self.misp_event.add_object(**asn_object)
        uuid = self.parse_resolutions(req['resolutions']) if req.get('resolutions') else None
        return self.parse_related_urls(req, recurse, uuid)

    def parse_url(self, url, recurse=False, uuid=None):
        req = requests.get(self.base_url.format('url'), params={'apikey': self.apikey, 'resource': url})
        status_code = req.status_code
        if req.status_code == 200:
            req = req.json()
            vt_uuid = self.parse_vt_object(req)
            if not recurse:
                feature = 'url'
                url_object = MISPObject(feature)
                url_object.add_attribute(feature, type=feature, value=url)
                url_object.add_reference(vt_uuid, 'analyzed-with')
                if uuid:
                    url_object.add_reference(uuid, 'hosted-in')
                self.misp_event.add_object(**url_object)
        return status_code

    ################################################################################
    ####                      Additional parsing functions                      #### # noqa
    ################################################################################

    def parse_related_urls(self, query_result, recurse, uuid=None):
        if recurse:
            for feature in ('detected_urls', 'undetected_urls'):
                if feature in query_result:
                    for url in query_result[feature]:
                        value = url['url'] if isinstance(url, dict) else url[0]
                        status_code = self.parse_url(value, False, uuid)
                        if status_code != 200:
                            return status_code
        else:
            for feature in ('detected_urls', 'undetected_urls'):
                if feature in query_result:
                    for url in query_result[feature]:
                        value = url['url'] if isinstance(url, dict) else url[0]
                        self.misp_event.add_attribute('url', value)
        return 200

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
        return domain_ip_object.uuid

    def parse_siblings(self, domain):
        attribute = MISPAttribute()
        attribute.from_dict(**dict(type='domain', value=domain))
        self.misp_event.add_attribute(**attribute)
        return attribute.uuid

    def parse_vt_object(self, query_result):
        if query_result['response_code'] == 1:
            vt_object = MISPObject('virustotal-report')
            vt_object.add_attribute('permalink', type='link', value=query_result['permalink'])
            detection_ratio = '{}/{}'.format(query_result['positives'], query_result['total'])
            vt_object.add_attribute('detection-ratio', type='text', value=detection_ratio)
            self.misp_event.add_object(**vt_object)
            return vt_object.uuid


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
    event_limit = request['config'].get('event_limit')
    if not isinstance(event_limit, int):
        event_limit = 5
    parser = VirusTotalParser(request['config']['apikey'], event_limit)
    attribute = request['attribute']
    status = parser.query_api(attribute)
    if status != 200:
        misperrors['error'] = parse_error(status)
        return misperrors
    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
