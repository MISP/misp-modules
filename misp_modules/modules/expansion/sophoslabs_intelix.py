from pymisp import MISPEvent, MISPObject
import json
import requests
import base64
from urllib.parse import quote

moduleinfo = {'version': '1.0',
              'author': 'Ben Verschaeren',
              'description': 'SOPHOSLabs Intelix Integration',
              'module-type': ['expansion']}

moduleconfig = ['client_id', 'client_secret']

misperrors = {'error': 'Error'}

misp_types_in = ['sha256', 'ip', 'ip-src', 'ip-dst', 'uri', 'url', 'domain', 'hostname']

mispattributes = {'input': misp_types_in,
                  'format': 'misp_standard'}


class SophosLabsApi():
    def __init__(self, client_id, client_secret):
        self.misp_event = MISPEvent()
        self.client_id = client_id
        self.client_secret = client_secret
        self.authToken = f"{self.client_id}:{self.client_secret}"
        self.baseurl = 'de.api.labs.sophos.com'
        d = {'grant_type': 'client_credentials'}
        h = {'Authorization': f"Basic {base64.b64encode(self.authToken.encode('UTF-8')).decode('ascii')}",
             'Content-Type': 'application/x-www-form-urlencoded'}
        r = requests.post('https://api.labs.sophos.com/oauth2/token', headers=h, data=d)
        if r.status_code == 200:
            j = json.loads(r.text)
            self.accessToken = j['access_token']

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}

    def hash_lookup(self, filehash):
        sophos_object = MISPObject('SOPHOSLabs Intelix SHA256 Report')
        h = {"Authorization": f"{self.accessToken}"}
        r = requests.get(f"https://{self.baseurl}/lookup/files/v1/{filehash}", headers=h)
        if r.status_code == 200:
            j = json.loads(r.text)
            if 'reputationScore' in j:
                sophos_object.add_attribute('Reputation Score', type='text', value=j['reputationScore'])
                if 0 <= j['reputationScore'] <= 19:
                    sophos_object.add_attribute('Decision', type='text', value='This file is malicious')
                if 20 <= j['reputationScore'] <= 29:
                    sophos_object.add_attribute('Decision', type='text', value='This file is potentially unwanted')
                if 30 <= j['reputationScore'] <= 69:
                    sophos_object.add_attribute('Decision', type='text', value='This file is unknown and suspicious')
                if 70 <= j['reputationScore'] <= 100:
                    sophos_object.add_attribute('Decision', type='text', value='This file is known good')
            if 'detectionName' in j:
                sophos_object.add_attribute('Detection Name', type='text', value=j['detectionName'])
            else:
                sophos_object.add_attribute('Detection Name', type='text', value='No name associated with this IoC')
        self.misp_event.add_object(**sophos_object)

    def ip_lookup(self, ip):
        sophos_object = MISPObject('SOPHOSLabs Intelix IP Category Lookup')
        h = {"Authorization": f"{self.accessToken}"}
        r = requests.get(f"https://{self.baseurl}/lookup/ips/v1/{ip}", headers=h)
        if r.status_code == 200:
            j = json.loads(r.text)
            if 'category' in j:
                for c in j['category']:
                    sophos_object.add_attribute('IP Address Categorisation', type='text', value=c)
            else:
                sophos_object.add_attribute('IP Address Categorisation', type='text', value='No category assocaited with IoC')
        self.misp_event.add_object(**sophos_object)

    def url_lookup(self, url):
        sophos_object = MISPObject('SOPHOSLabs Intelix URL Lookup')
        h = {"Authorization": f"{self.accessToken}"}
        r = requests.get(f"https://{self.baseurl}/lookup/urls/v1/{quote(url, safe='')}", headers=h)
        if r.status_code == 200:
            j = json.loads(r.text)
            if 'productivityCategory' in j:
                sophos_object.add_attribute('URL Categorisation', type='text', value=j['productivityCategory'])
            else:
                sophos_object.add_attribute('URL Categorisation', type='text', value='No category assocaited with IoC')

            if 'riskLevel' in j:
                sophos_object.add_attribute('URL Risk Level', type='text', value=j['riskLevel'])
            else:
                sophos_object.add_attribute('URL Risk Level', type='text', value='No risk level associated with IoC')

            if 'securityCategory' in j:
                sophos_object.add_attribute('URL Security Category', type='text', value=j['securityCategory'])
            else:
                sophos_object.add_attribute('URL Security Category', type='text', value='No Security Category associated with IoC')
        self.misp_event.add_object(**sophos_object)


def handler(q=False):
    if q is False:
        return False
    j = json.loads(q)
    if not j.get('config') or not j['config'].get('client_id') or not j['config'].get('client_secret'):
        misperrors['error'] = "Missing client_id or client_secret value for SOPHOSLabs Intelix. \
            It's free to sign up here https://aws.amazon.com/marketplace/pp/B07SLZPMCS."
        return misperrors
    client = SophosLabsApi(j['config']['client_id'], j['config']['client_secret'])
    if j['attribute']['type'] == "sha256":
        client.hash_lookup(j['attribute']['value1'])
    if j['attribute']['type'] in ['ip-dst', 'ip-src', 'ip']:
        client.ip_lookup(j["attribute"]["value1"])
    if j['attribute']['type'] in ['uri', 'url', 'domain', 'hostname']:
        client.url_lookup(j["attribute"]["value1"])
    return client.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
