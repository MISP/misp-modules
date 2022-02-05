import json
import logging
import requests
import urllib.parse
from . import check_input_attribute, standard_error_message
from pymisp import MISPAttribute, MISPEvent, MISPTag,  MISPObject, Distribution

logger = logging.getLogger('ipqualityscore')
logger.setLevel(logging.DEBUG)

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', 'url', 'uri', 'ip-src', 'ip-dst', 'email', 'email-src', 'email-dst', 'target-email', 'whois-registrant-email', 'phone-number','whois-registrant-phone'], 'output': ['text'], 'format': 'misp_standard'}
moduleinfo = {'version': '0.1', 'author': 'David Mackler', 'description': 'Query IPQualityScore for IP reputation, Email Validation, Phone Number Validation and Malicious Domain/URL Scanner.',
              'module-type': ['hover', 'expansion']}
moduleconfig = ['apikey']

BASE_URL = 'https://ipqualityscore.com/api/json'
DEFAULT_DISTRIBUTION_SETTING = Distribution.your_organisation_only.value

IP_API_ATTRIBUTE_TYPES = ['ip-src', 'ip-dst']
URL_API_ATTRIBUTE_TYPES = ['hostname', 'domain', 'url', 'uri']
EMAIL_API_ATTRIBUTE_TYPES = ['email', 'email-src', 'email-dst', 'target-email', 'whois-registrant-email']
PHONE_API_ATTRIBUTE_TYPES = ['phone-number','whois-registrant-phone']

def _format_result(attribute, result, enrichment_type):

    event = MISPEvent()

    orig_attr = MISPAttribute()
    orig_attr.from_dict(**attribute)

    event = _make_enriched_attr(event, result, orig_attr)

    return event
    
def _make_enriched_attr(event, result, orig_attr):

    enriched_object = MISPObject('IPQualityScore Enrichment')
    enriched_object.add_reference(orig_attr.uuid, 'related-to')

    enriched_attr = MISPAttribute()
    enriched_attr.from_dict(**{
        'value': orig_attr.value,
        'type': orig_attr.type,
        'distribution': 0,
        'object_relation': 'enriched-attr',
        'to_ids': orig_attr.to_ids
    })

    # enriched_attr = _make_tags(enriched_attr, result)
    # enriched_object.add_attribute(**enriched_attr)
    
    
    fraud_score_attr = MISPAttribute()
    fraud_score_attr.from_dict(**{
        'value': result.get('fraud_score'),
        'type': 'text',
        'object_relation': 'fraud_score',
        'distribution': 0
    })
    enriched_object.add_attribute(**fraud_score_attr)

    latitude = MISPAttribute()
    latitude.from_dict(**{
        'value': result.get('latitude'),
        'type': 'text',
        'object_relation': 'latitude',
        'distribution': 0
    })
    enriched_object.add_attribute(**latitude)

    event.add_attribute(**orig_attr)
    event.add_object(**enriched_object)
    
    longitude = MISPAttribute()
    longitude.from_dict(**{
        'value': result.get('longitude'),
        'type': 'text',
        'object_relation': 'longitude',
        'distribution': 0
    })
    enriched_object.add_attribute(**longitude)

    return event
              
def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    
    # check if the apikey is pprovided
    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = 'IPQualityScore apikey is missing'
        return misperrors
    apikey = request['config'].get('apikey')    
    # check attribute is added to the event   
    if not request.get('attribute') or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
        
    input_attribute = request['attribute']
    input_attribute_type = input_attribute['type']
    input_attribute_value = attribute['value']
    # check if the attribute type is supported by IPQualityScore
    if input_attribute_type not in mispattributes['input']:
        return {'error': 'Unsupported attributes type for IPqualityScore Enrichment'}
      
    if input_attribute_type in IP_API_ATTRIBUTE_TYPES:
        url = f"{BASE_URL}/ip/{input_attribute_value}"
        headers = {"IPQS-KEY": apikey}
        response = self.get(url, headers)
        data = response.data
        if str(data.get('success')) == "True":
            event = _format_result(input_attribute, data, "ip")
            event = json.loads(event.to_json())
            ret_result = {key: event[key] for key in ('Attribute', 'Object') if key
                  in event}
            return {'results': ret_result}
        else:
            return {'error', str(data.get('message'))           
        
def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
    