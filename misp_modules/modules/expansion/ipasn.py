# -*- coding: utf-8 -*-

import json
from . import check_input_attribute, standard_error_message
from pyipasnhistory import IPASNHistory
from pymisp import MISPAttribute, MISPEvent, MISPObject

misperrors = {'error': 'Error'}
mispattributes = {'input': ['ip-src', 'ip-dst'], 'format': 'misp_standard'}
moduleinfo = {'version': '0.2', 'author': 'Raphaël Vinot',
              'description': 'Query an IP ASN history service (https://github.com/CIRCL/IP-ASN-history.git)',
              'module-type': ['expansion', 'hover']}


def parse_result(attribute, values):
    event = MISPEvent()
    initial_attribute = MISPAttribute()
    initial_attribute.from_dict(**attribute)
    event.add_attribute(**initial_attribute)
    mapping = {'asn': ('AS', 'asn'), 'prefix': ('ip-src', 'subnet-announced')}
    print(values)
    for last_seen, response in values['response'].items():
        asn = MISPObject('asn')
        asn.add_attribute('last-seen', **{'type': 'datetime', 'value': last_seen})
        for feature, attribute_fields in mapping.items():
            attribute_type, object_relation = attribute_fields
            asn.add_attribute(object_relation, **{'type': attribute_type, 'value': response[feature]})
        asn.add_reference(initial_attribute.uuid, 'related-to')
        event.add_object(**asn)
    event = json.loads(event.to_json())
    return {key: event[key] for key in ('Attribute', 'Object')}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('attribute') or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
    if request['attribute']['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attribute type.'}
    toquery = request['attribute']['value']

    ipasn = IPASNHistory()
    values = ipasn.query(toquery)

    if not values:
        misperrors['error'] = 'Unable to find the history of this IP'
        return misperrors
    return {'results': parse_result(request['attribute'], values)}


def introspection():
    return mispattributes


def version():
    return moduleinfo
