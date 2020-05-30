import json
from pymisp import MISPAttribute, MISPEvent, MISPObject
from trustar import TruStar

misperrors = {'error': "Error"}
mispattributes = {'input': ["btc", "domain","email-src", "filename", "hostname", "ip-src", "ip-dst", "malware-type", "md5", "sha1", "sha256", "url"], 'format': 'misp_standard'}

moduleinfo = {'version': "0.1", 'author': "Jesse Hedden",
              'description': "Enrich data with TruSTAR",
              'module-type': ["hover", "expansion"]}

moduleconfig = ["api_key", "api_secret", "enclave_ids"]


def get_results(misp_event):
    event = json.loads(misp_event.to_json())
    results = {key: event[key] for key in ('Attribute', 'Object')}
    return {'results': results}

def parse_indicator_summary(attribute, summary):
    misp_event = MISPEvent()
    misp_attribute = MISPAttribute().from_dict(**attribute)
    misp_event.add_attribute(**misp_attribute)

    mapping = {'value': 'text', 'reportId': 'text', 'enclaveId': 'text', 'description': 'text'}

    for item in summary.get('items'):
        trustar_obj = MISPObject(attribute.value)
        for key, attribute_type in mapping.items():
            trustar_obj.add_attribute(key, attribute_type=attribute_type, value=item[key])
        trustar_obj.add_reference(misp_attribute.uuid, 'associated-to')
        misp_event.add_object(**trustar_obj)

    return misp_event


def handler(q=False):

    if q is False:
        return False

    request = json.loads(q)
    config = request.get('config', {})
    if not config.get('api_key') or not config.get('api_secret'):
        misperrors['error'] = "Your TruSTAR API key and secret are required for indicator enrichment."
        return misperrors

    enclave_ids = [enclave_id for enclave_id in config.get('enclave_ids', "").split(',')]
    ts_client = TruStar(config={'user_api_key': config.get('api_key'), 'user_api_secret': config.get('api_secret'), 'enclave_ids': enclave_ids})
    attribute = request.get('attribute')

    summary = ts_client.get_indicator_summaries(attribute)

    misp_event = parse_indicator_summary(attribute, summary)
    return get_results(misp_event)

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

