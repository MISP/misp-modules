import json

try:
    import pyeti
except ImportError:
    print("pyeti module not installed.")

from pymisp import MISPEvent, MISPObject

misperrors = {'error': 'Error'}

mispattributes = {'input': ['ip-src', 'ip-dst', 'hostname', 'domain'],
                  'format': 'misp_standard'
                  }
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Sebastien Larinier @sebdraven',
              'description': 'Query on yeti',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['apikey', 'url']


class Yeti():

    def __init__(self, url, key,attribute):
        self.misp_mapping = {'Ip': 'ip-dst', 'Domain': 'domain', 'Hostname': 'hostname', 'Url': 'url'}
        self.yeti_client = pyeti.YetiApi(url=url, api_key=key)
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)

    def search(self, value):
        obs = self.yeti_client.observable_search(value=value)
        if obs:
            return obs[0]

    def get_neighboors(self, obs_id):
        neighboors = self.yeti_client.neighbors_observables(obs_id)
        if neighboors and 'objs' in neighboors:
            for n in neighboors['objs']:
                yield n

    def get_tags(self, value):
        obs = self.search(value)
        if obs:
            for t in obs['tags']:
                yield t

    def get_entity(self, obs_id):
        companies = self.yeti_client.observable_to_company(obs_id)
        actors = self.yeti_client.observable_to_actor(obs_id)
        campaigns = self.yeti_client.observable_to_campaign(obs_id)
        exploit_kit = self.yeti_client.observable_to_exploitkit(obs_id)
        exploit = self.yeti_client.observable_to_exploit(obs_id)
        ind = self.yeti_client.observable_to_indicator(obs_id)

        res = []
        res.extend(companies)
        res.extend(actors)
        res.extend(campaigns)
        res.extend(exploit)
        res.extend(exploit_kit)
        res.extend(ind)

        for r in res:
            yield r['name']

    def parse_yeti_result(self):
        obs = self.search(self.attribute['value'])
        values = []
        types = []
        self.misp_event.add_attribute(**self.attribute)
        for obs_to_add in self.get_neighboors(obs['id']):
            object_misp = self.get_object(obs_to_add)
            self.misp_event.add_object(object_misp)
            print(self.misp_event)

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object')}
        return results

    def get_object(self, obj_to_add):
        if (obj_to_add['type'] == 'Ip' and self.attribute in ['hostname','domain']) or\
                (obj_to_add['type'] in ('Hostname', 'Domain') and self.attribute['type'] in ('ip-src', 'ip-dst')):
            domain_ip_object = MISPObject('domain-ip')
            domain_ip_object.add_attribute(**self.__get_attribute(obj_to_add))
            domain_ip_object.add_reference(self.attribute['uuid'], 'related_to')
            domain_ip_object.add_attribute(**self.attribute)
            return domain_ip_object

    def __get_attribute(self, obj_yeti):
        typ_attribute = self.misp_mapping[obj_yeti['type']]
        attr_misp = {'type':typ_attribute, 'value': obj_yeti['value']}
        if typ_attribute == 'ip-src' or typ_attribute == 'ip-dst':
            attr_misp['object_relation'] = 'ip'
        elif 'domain' == typ_attribute:
            attr_misp['object_relation'] = 'domain'
        else:
            attr_misp['object_relation'] = None
        return attr_misp

def handler(q=False):
    if q is False:
        return False

    apikey = None
    yeti_url = None
    yeti_client = None

    request = json.loads(q)
    attribute = request['attribute']
    if attribute['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attributes type'}

    if 'config' in request and 'url' in request['config']:
        yeti_url = request['config']['url']
    if 'config' in request and 'apikey' in request['config']:
        apikey = request['config']['apikey']
    if apikey and yeti_url:
        yeti_client = Yeti(yeti_url, apikey, attribute)

    if yeti_client:
        yeti_client.parse_yeti_result()
        return yeti_client.get_result()
    else:
        misperrors['error'] = 'Yeti Config Error'
        return misperrors



def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

def introspection():
    return mispattributes