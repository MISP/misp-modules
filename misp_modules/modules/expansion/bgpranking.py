# -*- coding: utf-8 -*-

import json
from . import check_input_attribute, standard_error_message
from datetime import date, datetime, timedelta
from pybgpranking import BGPRanking
from pymisp import MISPAttribute, MISPEvent, MISPObject

misperrors = {'error': 'Error'}
mispattributes = {'input': ['AS'], 'format': 'misp_standard'}
moduleinfo = {
    'version': '0.1',
    'author': 'Raphaël Vinot',
    'description': 'Query BGP Ranking to get the ranking of an Autonomous System number.',
    'module-type': ['expansion', 'hover'],
    'name': 'BGP Ranking',
    'logo': '',
    'requirements': ['pybgpranking python library'],
    'features': 'The module takes an AS number attribute as input and displays its description as well as its ranking position in BGP Ranking for a given day.',
    'references': ['https://github.com/D4-project/BGP-Ranking/'],
    'input': 'Autonomous system number.',
    'output': 'An asn object with its related bgp-ranking object.',
}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('attribute') or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
    toquery = request['attribute']
    if toquery['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attribute type.'}

    bgpranking = BGPRanking()
    value_toquery = int(toquery['value'][2:]) if toquery['value'].startswith('AS') else int(toquery['value'])
    values = bgpranking.query(value_toquery, date=(date.today() - timedelta(1)).isoformat())

    if not values['response'] or not values['response']['asn_description']:
        misperrors['error'] = 'There is no result about this ASN in BGP Ranking'
        return misperrors

    event = MISPEvent()
    attribute = MISPAttribute()
    attribute.from_dict(**toquery)
    event.add_attribute(**attribute)

    asn_object = MISPObject('asn')
    asn_object.add_attribute(**{
        'type': 'AS',
        'object_relation': 'asn',
        'value': values['meta']['asn']
    })
    description, country = values['response']['asn_description'].split(', ')
    for relation, value in zip(('description', 'country'), (description, country)):
        asn_object.add_attribute(**{
            'type': 'text',
            'object_relation': relation,
            'value': value
        })

    mapping = {
        'address_family': {'type': 'text', 'object_relation': 'address-family'},
        'date': {'type': 'datetime', 'object_relation': 'date'},
        'position': {'type': 'float', 'object_relation': 'position'},
        'rank': {'type': 'float', 'object_relation': 'ranking'}
    }
    bgp_object = MISPObject('bgp-ranking')
    for feature in ('rank', 'position'):
        bgp_attribute = {'value': values['response']['ranking'][feature]}
        bgp_attribute.update(mapping[feature])
        bgp_object.add_attribute(**bgp_attribute)
    date_attribute = {'value': datetime.strptime(values['meta']['date'], '%Y-%m-%d')}
    date_attribute.update(mapping['date'])
    bgp_object.add_attribute(**date_attribute)
    address_attribute = {'value': values['meta']['address_family']}
    address_attribute.update(mapping['address_family'])
    bgp_object.add_attribute(**address_attribute)

    asn_object.add_reference(attribute.uuid, 'describes')
    asn_object.add_reference(bgp_object.uuid, 'ranked-with')
    event.add_object(asn_object)
    event.add_object(bgp_object)

    event = json.loads(event.to_json())
    results = {key: event[key] for key in ('Attribute', 'Object')}
    return {'results': results}


def introspection():
    return mispattributes


def version():
    return moduleinfo
