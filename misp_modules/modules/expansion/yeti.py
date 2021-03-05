import json

try:
    import pyeti
except ImportError:
    print("pyeti module not installed.")

misperrors = {'error': 'Error'}

mispattributes = {'input': ['ip-src', 'ip-dst', 'hostname', 'domain'],
                  'output': ['hostname', 'domain', 'ip-src', 'ip-dst', 'url']}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Sebastien Larinier @sebdraven',
              'description': 'Query on yeti',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['apikey', 'url']


class Yeti(pyeti.YetiApi):

    def __init__(self, url, key):
        super(Yeti, self).__init__(url, key)
        self.dict = {'Ip': 'ip-src', 'Domain': 'domain', 'Hostname': 'hostname'}

    def search(self, value):
        obs = self.observable_search(value=value)
        if obs:
            return obs[0]

    def get_neighboors(self, obs_id):
        neighboors = self.neighbors_observables(obs_id)
        if neighboors and 'objs' in neighboors:
            for n in neighboors:
                yield n

    def get_tags(self, value):
        obs = self.search(value)
        if obs:
            for t in obs['tags']:
                yield t

    def get_entity(self, obs_id):
        companies = self.observable_to_company(obs_id)
        actors = self.observable_to_actor(obs_id)
        campaigns = self.observable_to_campaign(obs_id)
        exploit_kit = self.observable_to_exploitkit(obs_id)
        exploit = self.observable_to_exploit(obs_id)
        ind = self.observable_to_indicator(obs_id)

        res = []
        res.extend(companies)
        res.extend(actors)
        res.extend(campaigns)
        res.extend(exploit)
        res.extend(exploit_kit)
        res.extend(ind)

        for r in res:
            yield r['name']

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    attribute = request['attribute']
    print(attribute)


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

def introspection():
    return mispattributes