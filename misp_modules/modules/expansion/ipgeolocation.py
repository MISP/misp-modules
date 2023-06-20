import json
import traceback

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
            
    attribute = request['attribute']
    ip = request['attribute']['value']
    apiKey = request['config']['apiKey']
    # Correct
    response = handle_ip(apiKey, ip, attribute)
    return {'error' : f'Completed Response - {response}'}
    
def handle_ip(apiKey, ip, attribute):

    try:
        results = query_ipgeolocation(apiKey, ip)
    except Exception:
        return {'error' : 'Error during querying IPGeolocation API.'}


    # Check if the IP address is not reserved for special use
    if results.get('message'):
        if 'bogon' in results['message']:
            return {'error': 'The IP address(bogon IP) is reserved for special use'}
        else:
            return {'error': 'Error Occurred during IP data Extraction from Message'}
    try:
        misp_event = MISPEvent()
        input_attribute = MISPAttribute()
        # input_attribute.from_dict(**attribute)
        misp_event.add_attribute(**input_attribute)
    except Exception:
        return {'error': f'Error on line 58 - {traceback.print_exc()}'}

    ipObject = MISPObject('ip-api-address')
    # Correct
    try:
        mapping = get_mapping()
    except Exception:
        return {'error': f'Error on line 66 - {traceback.print_exc()}'}
    try:
        for field, relation in mapping.items():
            ipObject.add_attribute(relation, results[field])
    except Exception:
        return {'error': f'Error on line 71 - {traceback.print_exc()}'}
    try:
        misp_event.add_object(ipObject)
    except Exception:
        return {'error': f'Error on line 75 - {traceback.print_exc()}'}
    # Return the results in MISP format
    try:
        event = json.loads(misp_event.to_json())
        return {
            'results': {key: event[key] for key in ('Attribute', 'Object')}
        }
    except Exception:
        return {'error': f'Error on line 83 - {traceback.print_exc()}'}


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

def main():
    attribute = {
        'type' : 'ip-src',
        'value' : '20.20.12.154'
    }
    handle_ip('efe037a76a17432fad2dbdca8299d559','21.02.15.123', attribute)    
    
if __name__ == '__main__':
    main()


