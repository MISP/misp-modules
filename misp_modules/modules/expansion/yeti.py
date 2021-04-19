import json
import logging

try:
    import pyeti
except ImportError:
    print("pyeti module not installed.")

from pymisp import MISPEvent, MISPObject, MISPAttribute

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
        self.misp_mapping = {'Ip': 'ip-dst', 'Domain': 'domain', 'Hostname': 'hostname', 'Url': 'url',
                             'AutonomousSystem': 'AS'}
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
        for obs_to_add in self.get_neighboors(obs['id']):
            object_misp_domain_ip = self.__get_object_domain_ip(obs_to_add)
            if object_misp_domain_ip:
                self.misp_event.add_object(object_misp_domain_ip)
            object_misp_url = self.__get_object_url(obs_to_add)
            if object_misp_url:
                self.misp_event.add_object(object_misp_url)
            if not object_misp_url and not object_misp_url:
                self.__get_attribute(obs_to_add)
                       
    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object')}
        return results

    def __get_attribute(self, obs_to_add):

        try:
            type_attr = self.misp_mapping[obs_to_add['type']]
            attr = self.misp_event.add_attribute(value=obs_to_add['value'], type=type_attr)
        except KeyError:
            logging.error('type not found %s' % obs_to_add['type'])
            return

        for t in obs_to_add['tags']:
            self.misp_event.add_attribute_tag(t['name'], attr['uuid'])

    def __get_object_domain_ip(self, obj_to_add):
        if (obj_to_add['type'] == 'Ip' and self.attribute['type'] in ['hostname','domain']) or\
                (obj_to_add['type'] in ('Hostname', 'Domain') and self.attribute['type'] in ('ip-src', 'ip-dst')):
            domain_ip_object = MISPObject('domain-ip')
            domain_ip_object.add_attribute(self.__get_relation(obj_to_add),
                                           obj_to_add['value'])
            domain_ip_object.add_attribute(self.__get_relation(self.attribute, is_yeti_object=False),
                                           self.attribute['value'])
            domain_ip_object.add_reference(self.attribute['uuid'], 'related_to')

            return domain_ip_object

    def __get_object_url(self, obj_to_add):
        if (obj_to_add['type'] == 'Url' and self.attribute['type'] in ['hostname', 'domain', 'ip-src', 'ip-dst']) or (
            obj_to_add['type'] in ('Hostname', 'Domain', 'Ip') and self.attribute['type'] == 'url'
        ):
            url_object = MISPObject('url')
            obj_relation = self.__get_relation(obj_to_add)
            if obj_relation:
                url_object.add_attribute(obj_relation, obj_to_add['value'])
            obj_relation = self.__get_relation(self.attribute, is_yeti_object=False)
            if obj_relation:
                url_object.add_attribute(obj_relation,
                                         self.attribute['value'])
            url_object.add_reference(self.attribute['uuid'], 'related_to')

            return url_object

    def __get_relation(self, obj, is_yeti_object=True):
        if is_yeti_object:
            type_attribute = self.misp_mapping[obj['type']]
        else:
            type_attribute = obj['type']
        if type_attribute == 'ip-src' or type_attribute == 'ip-dst':
            return 'ip'
        elif 'domain' == type_attribute:
            return 'domain'
        elif 'hostname' == type_attribute:
            return 'domain'
        elif type_attribute == 'url':
            return type_attribute


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
        return {'results': yeti_client.get_result()}
    else:
        misperrors['error'] = 'Yeti Config Error'
        return misperrors



def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

def introspection():
    return mispattributes