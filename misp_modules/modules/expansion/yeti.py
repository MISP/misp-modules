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


class Yeti():

    def __init__(self, url, key):
        self.dict = {'Ip': 'ip-dst', 'Domain': 'domain', 'Hostname': 'hostname', 'Url': 'url'}
        self.yeti_client = pyeti.YetiApi(url=url, api_key=key)

    def search(self, value):
        obs = self.yeti_client.observable_search(value=value)
        if obs:
            return obs[0]

    def get_neighboors(self, obs_id):
        neighboors = self.yeti_client.neighbors_observables(obs_id)
        if neighboors and 'objs' in neighboors:
            for n in neighboors:
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

def handler(q=False):
    if q is False:
        return False


    apikey = None
    yeti_url = None
    yeti_client = None

    request = json.loads(q)
    print(request)

    if 'config' in request and 'url' in request['config']:
        yeti_url = request['config']['url']
    if 'config' in request and 'apikey' in request['config']:
        apikey = request['config']['apikey']
    if apikey and yeti_url:
        yeti_client = Yeti(yeti_url,apikey)
    if request.get('ip-dst'):
        obs_value = request['ip-dst']

    if yeti_client:
        obs = yeti_client.search(obs_value)
        print(obs)
        values = []
        types = []
        to_push = {"results": []}
        for obs_to_add in yeti_client.get_neighboors(obs['id']):
            print(obs_to_add)
            values.append(obs_to_add['value'])
            types.append(yeti_client.dict[obs_to_add['type']])
        to_push['results'].append(
            {'types': types,
             'values': values,
             'categories': ['Network Activities']
            }
        )
        return to_push
    else:
        misperrors['error'] = 'Yeti Config Error'
        return misperrors



def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

def introspection():
    return mispattributes