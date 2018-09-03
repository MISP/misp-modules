import json
import requests
from requests import HTTPError
import base64
from collections import defaultdict

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', "ip-src", "ip-dst", "md5", "sha1", "sha256", "sha512"],
                  'output': ['domain', "ip-src", "ip-dst", "text", "md5", "sha1", "sha256", "sha512", "ssdeep",
                             "authentihash", "filename"]}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '3', 'author': 'Hannah Ward',
              'description': 'Get information from virustotal',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "event_limit"]
comment = '{}: Enriched via VirusTotal'
hash_types = ["md5", "sha1", "sha256", "sha512"]

class VirusTotalRequest(object):
    def __init__(self, config):
        self.apikey = config['apikey']
        self.limit = int(config.get('event_limit', 5))
        self.base_url = "https://www.virustotal.com/vtapi/v2/{}/report"
        self.results = defaultdict(set)
        self.to_return = []
        self.input_types_mapping = {'ip-src': self.get_ip, 'ip-dst': self.get_ip,
                                    'domain': self.get_domain, 'hostname': self.get_domain,
                                    'md5': self.get_hash, 'sha1': self.get_hash,
                                    'sha256': self.get_hash, 'sha512': self.get_hash}
        self.output_types_mapping = {'submission_names': 'filename', 'ssdeep': 'ssdeep',
                                     'authentihash': 'authentihash', 'ITW_urls': 'url'}

    def parse_request(self, q):
        req_values = set()
        for attribute_type, attribute_value in q.items():
            req_values.add(attribute_value)
            try:
                error = self.input_types_mapping[attribute_type](attribute_value)
            except KeyError:
                continue
            if error is not None:
                return error
        for key, values in self.results.items():
            values = values.difference(req_values)
            if values:
                if isinstance(key, tuple):
                    types, comment = key
                    self.to_return.append({'types': list(types), 'values': list(values), 'comment': comment})
                else:
                    self.to_return.append({'types': key, 'values': list(values)})
        return self.to_return

    def get_domain(self, domain, do_not_recurse=False):
        req = requests.get(self.base_url.format('domain'), params={'domain': domain, 'apikey': self.apikey})
        try:
            req.raise_for_status()
            req = req.json()
        except HTTPError as e:
            return str(e)
        if req["response_code"] == 0:
            # Nothing found
            return []
        if "resolutions" in req:
            for res in req["resolutions"][:self.limit]:
                ip_address = res["ip_address"]
                self.results[(("ip-dst", "ip-src"), comment.format(domain))].add(ip_address)
                # Pivot from here to find all domain info
                if not do_not_recurse:
                    error = self.get_ip(ip_address, True)
                    if error is not None:
                        return error
        self.get_more_info(req)

    def get_hash(self, _hash):
        req = requests.get(self.base_url.format('file'), params={'resource': _hash, 'apikey': self.apikey, 'allinfo': 1})
        try:
            req.raise_for_status()
            req = req.json()
        except HTTPError as e:
            return str(e)
        if req["response_code"] == 0:
            # Nothing found
            return []
        self.get_more_info(req)

    def get_ip(self, ip, do_not_recurse=False):
        req = requests.get(self.base_url.format('ip-address'), params={'ip': ip, 'apikey': self.apikey})
        try:
            req.raise_for_status()
            req = req.json()
        except HTTPError as e:
            return str(e)
        if req["response_code"] == 0:
            # Nothing found
            return []
        if "resolutions" in req:
            for res in req["resolutions"][:self.limit]:
                hostname = res["hostname"]
                self.results[(("domain",), comment.format(ip))].add(hostname)
                # Pivot from here to find all domain info
                if not do_not_recurse:
                    error = self.get_domain(hostname, True)
                    if error is not None:
                        return error
        self.get_more_info(req)

    def find_all(self, data):
        hashes = []
        if isinstance(data, dict):
            for key, value in data.items():
                if key in hash_types:
                    self.results[key].add(value)
                    hashes.append(value)
                else:
                    if isinstance(value, (dict, list)):
                        hashes.extend(self.find_all(value))
        elif isinstance(data, list):
            for d in data:
                hashes.extend(self.find_all(d))
        return hashes

    def get_more_info(self, req):
        # Get all hashes first
        hashes = self.find_all(req)
        for h in hashes[:self.limit]:
            # Search VT for some juicy info
            try:
            data = requests.get(self.base_url.format('file'), params={'resource': h, 'apikey': self.apikey, 'allinfo': 1}).json()
            except Exception:
                continue
            # Go through euch key and check if it exists
            for VT_type, MISP_type in self.output_types_mapping.items():
                if VT_type in data:
                    self.results[((MISP_type,), comment.format(h))].add(data[VT_type])
            # Get the malware sample
            sample = requests.get(self.base_url[:-6].format('file/download'), params={'hash': h, 'apikey': self.apikey})
            malsample = sample.content
            # It is possible for VT to not give us any submission names
            if "submission_names" in data:
                self.to_return.append({"types": ["malware-sample"], "categories": ["Payload delivery"],
                                       "values": data["submimssion_names"], "data": str(base64.b64encore(malsample), 'utf-8')})

def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    if not q.get('config') or not q['config'].get('apikey'):
        misperrors['error']: "A VirusTotal api key is required for this module."
        return misperrors
    del q['module']
    query = VirusTotalRequest(q.pop('config'))
    r = query.parse_request(q)
    if isinstance(r, str):
        misperrors['error'] = r
        return misperrors
    return {'results': r}

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
