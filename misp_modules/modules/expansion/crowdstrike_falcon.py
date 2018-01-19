import json
import requests

moduleinfo = {'version': '0.1',
              'author': 'Christophe Vandeplas',
              'description': 'Module to query CrowdStrike Falcon.',
              'module-type': ['expansion']}
moduleconfig = ['api_id', 'apikey']
misperrors = {'error': 'Error'}
misp_types_in = ['domain', 'email-attachment', 'email-dst', 'email-reply-to', 'email-src', 'email-subject',
                 'filename', 'hostname', 'ip', 'ip-src', 'ip-dst', 'md5', 'mutex', 'regkey', 'sha1', 'sha256', 'uri', 'url',
                 'user-agent', 'whois-registrant-email', 'x509-fingerprint-md5']
mapping_out = {  # mapping between the MISP attributes types and the compatible CrowdStrike indicator types.
    'domain': {'types': 'hostname', 'to_ids': True},
    'email_address': {'types': 'email-src', 'to_ids': True},
    'email_subject': {'types': 'email-subject', 'to_ids': True},
    'file_name': {'types': 'filename', 'to_ids': True},
    'hash_md5': {'types': 'md5', 'to_ids': True},
    'hash_sha1': {'types': 'sha1', 'to_ids': True},
    'hash_sha256': {'types': 'sha256', 'to_ids': True},
    'ip_address': {'types': 'ip-dst', 'to_ids': True},
    'ip_address_block': {'types': 'ip-dst', 'to_ids': True},
    'mutex_name': {'types': 'mutex', 'to_ids': True},
    'registry': {'types': 'regkey', 'to_ids': True},
    'url': {'types': 'url', 'to_ids': True},
    'user_agent': {'types': 'user-agent', 'to_ids': True},
    'x509_serial': {'types': 'x509-fingerprint-md5', 'to_ids': True},

    'actors': {'types': 'threat-actor'},
    'malware_families': {'types': 'text', 'categories': 'Attribution'}
}
misp_types_out = [item['types'] for item in mapping_out.values()]
mispattributes = {'input': misp_types_in, 'output': misp_types_out}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if (request.get('config')):
        if (request['config'].get('apikey') is None):
            misperrors['error'] = 'CrowdStrike apikey is missing'
            return misperrors
        if (request['config'].get('api_id') is None):
            misperrors['error'] = 'CrowdStrike api_id is missing'
            return misperrors
    client = CSIntelAPI(request['config']['api_id'], request['config']['apikey'])

    r = {"results": []}

    valid_type = False
    for k in misp_types_in:
        if request.get(k):
            # map the MISP typ to the CrowdStrike type
            for item in lookup_indicator(client, request[k]):
                r['results'].append(item)
            valid_type = True

    if not valid_type:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    return r


def lookup_indicator(client, item):
    result = client.search_indicator(item)
    for item in result:
        for relation in item['relations']:
            if mapping_out.get(relation['type']):
                r = mapping_out[relation['type']].copy()
                r['values'] = relation['indicator']
                yield(r)
        for actor in item['actors']:
            r = mapping_out['actors'].copy()
            r['values'] = actor
            yield(r)
        for malware_family in item['malware_families']:
            r = mapping_out['malware_families'].copy()
            r['values'] = malware_family
            yield(r)


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


class CSIntelAPI():
    def __init__(self, custid=None, custkey=None, perpage=100, page=1, baseurl="https://intelapi.crowdstrike.com/indicator/v2/search/"):
        # customer id and key should be passed when obj is created
        self.custid = custid
        self.custkey = custkey

        self.baseurl = baseurl
        self.perpage = perpage
        self.page = page

    def request(self, query):
        headers = {'X-CSIX-CUSTID': self.custid,
                   'X-CSIX-CUSTKEY': self.custkey,
                   'Content-Type': 'application/json'}

        full_query = self.baseurl + query

        r = requests.get(full_query, headers=headers)
        # 400 - bad request
        if r.status_code == 400:
            raise Exception('HTTP Error 400 - Bad request.')

        # 404 - oh shit
        if r.status_code == 404:
            raise Exception('HTTP Error 404 - awww snap.')

        # catch all?
        if r.status_code != 200:
            raise Exception('HTTP Error: ' + str(r.status_code))

        if r.text:
            return r

    def search_indicator(self, item):
        query = 'indicator?match=' + item
        r = self.request(query)
        return json.loads(r.text)
