import requests
import json
from pymisp import MISPObject
from . import check_input_attribute, checking_error, standard_error_message
import dns.resolver

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', 'domain|ip'], 'output': ['boolean', 'counter'], 'format': 'misp_standard'}
moduleinfo = {'version': '0.1', 'author': 'Stephanie S',
              'description': 'AbuseIPDB MISP expansion module',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['api_key', 'max_age_in_days']

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if "config" not in request or "api_key" not in request["config"]:
        return {"error": "AbuseIPDB API key is missing"}
    if "max_age_in_days" not in request["config"]:
        return {"error": "AbuseIPDB max age in days is missing"}
    if not request.get('attribute') or not check_input_attribute(request['attribute'], requirements=('type', 'value')):
        return {'error': f'{standard_error_message}, {checking_error}.'}
    if request['attribute']['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attribute type.'}

    # Need to get the ip from the domain
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    try:
        ip = resolver.query(request["attribute"]["value"], 'A')
    except dns.resolver.NXDOMAIN:
        misperrors['error'] = "NXDOMAIN"
        return misperrors
    except dns.exception.Timeout:
        misperrors['error'] = "Timeout"
        return misperrors
    except Exception:
        misperrors['error'] = "DNS resolving error"
        return misperrors
  
    api_key = request["config"]["api_key"]   
    max_age_in_days = request["config"]["max_age_in_days"]
    api_endpoint = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip[0],
        'maxAgeInDays': max_age_in_days
    }
    headers = {
        'Accept': 'application/json',
        'key': api_key
    }
    r = {"results": []} 

    response = requests.request(method='GET', url=api_endpoint, headers=headers, params=querystring)
    response_json = json.loads(response.text)

    is_whitelisted = response_json['data']['isWhitelisted'] 
    is_tor = response_json['data']['isTor']
    is_public = response_json['data']['isPublic']
    abuse_confidence_score = response_json['data']['abuseConfidenceScore']

    if (is_whitelisted == False):
        is_whitelisted = 0
    if (is_tor == False):
        is_tor = 0
    if (is_public == False):
        is_public = 0
    if (abuse_confidence_score == None):
        abuse_confidence_score = 0

    if (response_json.get("errors")):
        return {'error': 'AbuseIPDB error, check logs'}
    else:
        obj = MISPObject('abuseipdb')
        obj.add_attribute('is-whitelisted', **{'type': 'boolean', 'value': is_whitelisted})
        obj.add_attribute('is-tor', **{'type': 'boolean', 'value': is_tor})
        obj.add_attribute('is-public', **{'type': 'boolean', 'value': is_public})
        obj.add_attribute('abuse-confidence-score', **{'type': 'counter', 'value': abuse_confidence_score})

    r['results'] = {'Object': [json.loads(obj.to_json())]}
    return r

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
