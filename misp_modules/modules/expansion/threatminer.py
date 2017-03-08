import json
import requests
from requests import HTTPError
import base64

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', 'ip-src', 'ip-dst', 'md5', 'sha1', 'sha256', 'sha512'],
                  'output': ['domain', 'ip-src', 'ip-dst', 'text', 'md5', 'sha1', 'sha256', 'sha512', 'ssdeep',
                             'authentihash', 'filename', 'whois-registrant-email', 'url', 'link']
                  }

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'KX499',
              'description': 'Get information from ThreatMiner',
              'module-type': ['expansion']}

desc = '{}: Threatminer - {}'


def handler(q=False):
    if q is False:
        return False

    q = json.loads(q)

    r = {'results': []}

    if 'ip-src' in q:
        r['results'] += get_ip(q['ip-src'])
    if 'ip-dst' in q:
        r['results'] += get_ip(q['ip-dst'])
    if 'domain' in q:
        r['results'] += get_domain(q['domain'])
    if 'hostname' in q:
        r['results'] += get_domain(q['hostname'])
    if 'md5' in q:
        r['results'] += get_hash(q['md5'])
    if 'sha1' in q:
        r['results'] += get_hash(q['sha1'])
    if 'sha256' in q:
        r['results'] += get_hash(q['sha256'])
    if 'sha512' in q:
        r['results'] += get_hash(q['sha512'])

    uniq = []
    for res in r['results']:
        if res not in uniq:
            uniq.append(res)
    r['results'] = uniq
    return r


def get_domain(q):
    ret = []
    for flag in [1, 2, 3, 4, 5, 6]:
        req = requests.get('https://www.threatminer.org/domain.php', params={'q': q, 'api': 'True', 'rt': flag})
        if not req.status_code == 200:
            continue
        results = req.json().get('results')
        if not results:
            continue

        for result in results:
            if flag == 1: #whois
                emails = result.get('whois', {}).get('emails')
                if not emails:
                    continue
                for em_type, email in emails.items():
                    ret.append({'types': ['whois-registrant-email'], 'values': [email], 'comment': desc.format(q, 'whois')})
            if flag == 2: #pdns
                ip = result.get('ip')
                if ip:
                    ret.append({'types': ['ip-src', 'ip-dst'], 'values': [ip], 'comment': desc.format(q, 'pdns')})
            if flag == 3: #uri
                uri = result.get('uri')
                if uri:
                    ret.append({'types': ['url'], 'values': [uri], 'comment': desc.format(q, 'uri')})
            if flag == 4: #samples
                if type(result) is str:
                    ret.append({'types': ['sha256'], 'values': [result], 'comment': desc.format(q, 'samples')})
            if flag == 5: #subdomains
                if type(result) is str:
                    ret.append({'types': ['domain'], 'values': [result], 'comment': desc.format(q, 'subdomain')})
            if flag == 6: #reports
                link = result.get('URL')
                if link:
                    ret.append({'types': ['url'], 'values': [link], 'comment': desc.format(q, 'report')})

    return ret


def get_ip(q):
    ret = []
    for flag in [1, 2, 3, 4, 5, 6]:
        req = requests.get('https://www.threatminer.org/host.php', params={'q': q, 'api': 'True', 'rt': flag})
        if not req.status_code == 200:
            continue
        results = req.json().get('results')
        if not results:
            continue

        for result in results:
            if flag == 1: #whois
                emails = result.get('whois', {}).get('emails')
                if not emails:
                    continue
                for em_type, email in emails.items():
                    ret.append({'types': ['whois-registrant-email'], 'values': [email], 'comment': desc.format(q, 'whois')})
            if flag == 2: #pdns
                ip = result.get('ip')
                if ip:
                    ret.append({'types': ['ip-src', 'ip-dst'], 'values': [ip], 'comment': desc.format(q, 'pdns')})
            if flag == 3: #uri
                uri = result.get('uri')
                if uri:
                    ret.append({'types': ['url'], 'values': [uri], 'comment': desc.format(q, 'uri')})
            if flag == 4: #samples
                if type(result) is str:
                    ret.append({'types': ['sha256'], 'values': [result], 'comment': desc.format(q, 'samples')})
            if flag == 5: #ssl
                if type(result) is str:
                    ret.append({'types': ['x509-fingerprint-sha1'], 'values': [result], 'comment': desc.format(q, 'ssl')})
            if flag == 6: #reports
                link = result.get('URL')
                if link:
                    ret.append({'types': ['url'], 'values': [link], 'comment': desc.format(q, 'report')})

    return ret


def get_hash(q):
    ret = []
    for flag in [1, 3, 6, 7]:
        req = requests.get('https://www.threatminer.org/sample.php', params={'q': q, 'api': 'True', 'rt': flag})
        if not req.status_code == 200:
            continue
        results = req.json().get('results')
        if not results:
            continue

        for result in results:
            if flag == 1: #meta (filename)
                name = result.get('file_name')
                if name:
                    ret.append({'types': ['filename'], 'values': [name], 'comment': desc.format(q, 'file')})
            if flag == 3: #network
                domains = result.get('domains')
                for dom in domains:
                    if dom.get('domain'):
                        ret.append({'types': ['domain'], 'values': [dom['domain']], 'comment': desc.format(q, 'network')})

                hosts = result.get('hosts')
                for h in hosts:
                    if type(h) is str:
                        ret.append({'types': ['ip-src', 'ip-dst'], 'values': [h], 'comment': desc.format(q, 'network')})
            if flag == 6: #detections
                detections = result.get('av_detections')
                for d in detections:
                    if d.get('detection'):
                        ret.append({'types': ['text'], 'values': [d['detection']], 'comment': desc.format(q, 'detection')})
            if flag == 7: #report
                if type(result) is str:
                    ret.append({'types': ['sha256'], 'values': [result], 'comment': desc.format(q, 'report')})

    return ret


def introspection():
    return mispattributes


def version():
    return moduleinfo
