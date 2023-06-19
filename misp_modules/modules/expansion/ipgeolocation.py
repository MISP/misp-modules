import json

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

mispattributes = {
    'input': ['ip-dst', 'ip-src'],
    'format': 'misp_standard'
}
moduleinfo = {
    'version': '1', 'author': 'IpGeolocation',
    'description': 'Querry Using IpGeolocation.io',
    'module-type': ['expansion', 'hover']
}
moduleconfig = ['apiKey']


def handler(q=False):
    # Input checks
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config'):
        return {'error' : 'IpGeolocation Configuration is missing'}
    if not request['config'].get('apiKey'):
        return {'error' : 'IpGeolocation apiKey is missing'}
    
    if request['attribute']['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attribute type.'}
            
    ip = request['attribute']['value']
    apiKey = request['config']['apiKey']
    # Correct
    response = handle_ip(apiKey, ip)
    return {'error': 'Going to the handleIP method'}
    
    
def handle_ip(apiKey, ip):

    try:
        results = query_ipgeolocation(apiKey, ip)
    except Exception:
        return {'error' : 'Error during querying IPGeolocation API.'}


    # Check if the IP address is not reserved for special use
    try:
        if results.get('message'):
            if 'bogon' in results['message']:
                return {'error': 'The IP address(bogon IP) is reserved for special use'}
            else:
                return {'error': 'Error Occurred during IP data Extraction from Message'}
    except Exception:
        return {'error': 'line 54'}
    try:
        misp_event = MISPEvent()
    except Exception:
        return {'error': 'line 58'}
    # input_attribute = MISPAttribute()
    # misp_event.add_attribute(**input_attribute)


    ipObject = MISPObject('ip-api-address')
    return {'error': 'line 64'}
    # mapping = get_mapping().json()
    # try:
        # for field, relation in mapping.items():
            # ipObject.add_attribute(relation, results[field])
    # except Exception:
        # return {'error': 'Error while Adding attributes'}
    # misp_event.add_object(ipObject)
# 
    # Return the results in MISP format
    # event = json.loads(misp_event.to_json())
    # return {
        # 'results': {key: event[key] for key in ('Attribute', 'Object')}
    # }


def query_ipgeolocation(apiKey, ip):
    query = requests.get(
        f"https://api.ipgeolocation.io/ipgeo?apiKey={apiKey}&ip={ip}"
    )
    if query.status_code != 200:
        return {'error': f'Error while querying ipGeolocation.io - {query.status_code}: {query.reason}'}
    return query.json()

def get_mapping():
    return {
        'isp':'ISP',
        'asn':'asn',
        'city':'city',
        'country_name':'country',
        'country_code2':'country-code',
        'latitude':'latitude',
        'longitude':'longitude',
        'organization':'organization',
        'continent_name':'region',
        'continent_code':'region-code',
        'state_prov':'state',
        'zipcode':'zipcode',
        'ip':'ip-src'
    }

def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
