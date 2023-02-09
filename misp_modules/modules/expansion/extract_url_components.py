import json
from pymisp import MISPEvent, MISPObject
from . import check_input_attribute, standard_error_message
from pyfaup.faup import Faup

misperrors = {'error': 'Error'}
mispattributes = {'input': ['url'], 'format': 'misp_standard'}
moduleinfo = {'version': '1', 'author': 'MISP Team',
              'description': "Extract URL components",
              'module-type': ['expansion', 'hover']}
moduleconfig = []


def createObjectFromURL(url):
    f = Faup()
    f.decode(url)
    parsed = f.get()
    obj = MISPObject('url')
    obj.add_attribute('url', type='url', value=url)
    if parsed['tld'] is not None:
        obj.add_attribute('tld', type='text', value=parsed['tld'])
    if parsed['subdomain'] is not None:
        obj.add_attribute('subdomain', type='text', value=parsed['subdomain'])
    obj.add_attribute('scheme', type='text', value=parsed['scheme'])
    obj.add_attribute('resource_path', type='text', value=parsed['resource_path'])
    obj.add_attribute('query_string', type='text', value=parsed['query_string'])
    obj.add_attribute('port', type='port', value=parsed['port'])
    obj.add_attribute('host', type='hostname', value=parsed['host'])
    if parsed['fragment'] is not None:
        obj.add_attribute('fragment', type='text', value=parsed['fragment'])
    obj.add_attribute('domain_without_tld', type='text', value=parsed['domain_without_tld'])
    obj.add_attribute('domain', type='domain', value=parsed['domain'])
    return obj


def createEvent(urlObject, attributeUUID, urlAttribute):
    mispEvent = MISPEvent()
    mispEvent.add_attribute(**urlAttribute)
    urlObject.add_reference(attributeUUID, 'generated-from')
    mispEvent.add_object(urlObject)
    return mispEvent

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('attribute') or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
    attribute = request['attribute']
    
    if attribute['type'] not in mispattributes['input']:
        return {'error': 'Bad attribute type'} 

    url = attribute['value'] 
    urlObject = createObjectFromURL(url)

    event = createEvent(urlObject, attribute['uuid'], attribute)
    event = json.loads(event.to_json())
    
    result = {'results': {'Object': event['Object']}}
    return result


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
