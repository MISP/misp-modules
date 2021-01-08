import json
import requests
from collections import defaultdict

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', 'ip-src', 'ip-dst', 'md5', 'sha1', 'sha256', 'sha512'],
                  'output': ['domain', 'ip-src', 'ip-dst', 'text', 'md5', 'sha1', 'sha256', 'sha512', 'ssdeep',
                             'authentihash', 'filename', 'whois-registrant-email', 'url', 'link']
                  }

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'KX499',
              'description': 'Get information from ThreatMiner',
              'module-type': ['expansion']}


class ThreatMiner():
    def __init__(self):
        self.results = defaultdict(set)
        self.comment = '{}: Threatminer - {}'
        self.types_mapping = {'domain': '_get_domain', 'hostname': '_get_domain',
                              'ip-dst': '_get_ip', 'ip-src': '_get_ip',
                              'md5': '_get_hash', 'sha1': '_get_hash',
                              'sha256': '_get_hash', 'sha512': '_get_hash'}

    @property
    def parsed_results(self):
        to_return = []
        for key, values in self.results.items():
            if values:
                input_value, comment = key[:2]
                types = [k for k in key[2:]]
                to_return.append({'types': types, 'values': list(values),
                                  'comment': self.comment.format(input_value, comment)})
        return to_return

    def parse_query(self, request):
        for input_type, to_call in self.types_mapping.items():
            if request.get(input_type):
                getattr(self, to_call)(request[input_type])

    def _get_domain(self, q):
        queries_mapping = {1: ('_add_whois', 'whois'), 2: ('_add_ip', 'pdns'),
                           3: ('_add_uri', 'uri'), 4: ('_add_hash', 'samples'),
                           5: ('_add_domain', 'subdomain'), 6: ('_add_link', 'report')}
        for flag, mapped in queries_mapping.items():
            req = requests.get('https://www.threatminer.org/domain.php', params={'q': q, 'api': 'True', 'rt': flag})
            if not req.status_code == 200:
                continue
            results = req.json().get('results')
            if not results:
                continue
            to_call, comment = mapped
            getattr(self, to_call)(results, q, comment)

    def _get_hash(self, q):
        queries_mapping = {1: ('_add_filename', 'file'), 3: ('_add_network', 'network'),
                           6: ('_add_text', 'detection'), 7: ('_add_hash', 'report')}
        for flag, mapped in queries_mapping.items():
            req = requests.get('https://www.threatminer.org/sample.php', params={'q': q, 'api': 'True', 'rt': flag})
            if not req.status_code == 200:
                continue
            results = req.json().get('results')
            if not results:
                continue
            to_call, comment = mapped
            getattr(self, to_call)(results, q, comment)

    def _get_ip(self, q):
        queries_mapping = {1: ('_add_whois', 'whois'), 2: ('_add_ip', 'pdns'),
                           3: ('_add_uri', 'uri'), 4: ('_add_hash', 'samples'),
                           5: ('_add_x509', 'ssl'), 6: ('_add_link', 'report')}
        for flag, mapped in queries_mapping.items():
            req = requests.get('https://www.threatminer.org/host.php', params={'q': q, 'api': 'True', 'rt': flag})
            if not req.status_code == 200:
                continue
            results = req.json().get('results')
            if not results:
                continue
            to_call, comment = mapped
            getattr(self, to_call)(results, q, comment)

    def _add_domain(self, results, q, comment):
        self.results[(q, comment, 'domain')].update({result for result in results if isinstance(result, str)})

    def _add_filename(self, results, q, comment):
        self.results[(q, comment, 'filename')].update({result['file_name'] for result in results if result.get('file_name')})

    def _add_hash(self, results, q, comment):
        self.results[(q, comment, 'sha256')].update({result for result in results if isinstance(result, str)})

    def _add_ip(self, results, q, comment):
        self.results[(q, comment, 'ip-src', 'ip-dst')].update({result['ip'] for result in results if result.get('ip')})

    def _add_link(self, results, q, comment):
        self.results[(q, comment, 'link')].update({result['URL'] for result in results if result.get('URL')})

    def _add_network(self, results, q, comment):
        for result in results:
            domains = result.get('domains')
            if domains:
                self.results[(q, comment, 'domain')].update({domain['domain'] for domain in domains if domain.get('domain')})
            hosts = result.get('hosts')
            if hosts:
                self.results[(q, comment, 'ip-src', 'ip-dst')].update({host for host in hosts if isinstance(host, str)})

    def _add_text(self, results, q, comment):
        for result in results:
            detections = result.get('av_detections')
            if detections:
                self.results[(q, comment, 'text')].update({d['detection'] for d in detections if d.get('detection')})

    def _add_uri(self, results, q, comment):
        self.results[(q, comment, 'url')].update({result['uri'] for result in results if result.get('uri')})

    def _add_whois(self, results, q, comment):
        for result in results:
            emails = result.get('whois', {}).get('emails')
            if emails:
                self.results[(q, comment, 'whois-registrant-email')].update({email for em_type, email in emails.items() if em_type == 'registrant' and email})

    def _add_x509(self, results, q, comment):
        self.results[(q, comment, 'x509-fingerprint-sha1')].update({result for result in results if isinstance(result, str)})


def handler(q=False):
    if q is False:
        return False

    q = json.loads(q)

    parser = ThreatMiner()
    parser.parse_query(q)
    return {'results': parser.parsed_results}


def introspection():
    return mispattributes


def version():
    return moduleinfo
