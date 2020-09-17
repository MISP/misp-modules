
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import os
import re
import sys
import requests
import argparse
import string
import json
import pymisp
import time
import logging
from pymisp import MISPObject
from pymisp import PyMISP
from pymisp import MISPEvent
from . import check_input_attribute, checking_error, standard_error_message
import platform
import os
from urllib.parse import quote, urlparse


moduleinfo = {
    'version': '0.0.1',
    'author': 'HAWK.IO (Tim Shelton)',
    'description': 'Module to calculate overall score using source confidence along side time-related degradation.',
    'module-type': ['expansion', 'hover']
}

moduleconfig = [ 'degrade_hours', 'degrade_delta', 'confidence_json', 'misp_url', 'misp_authkey' ]

misperrors = {'error': 'Error'}

ATTRIBUTES = [ 'ip', 'ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'url', 'uri', 'domain', 'domain|ip', 'hostname', 'hostname|ip', 'email-dst', 'email-src', 'sha1', 'md5', 'sha256', 'filename|sha1', 'filename|md5', 'filename|sha256', 'regkey|value', 'regkey' ]

mispattributes = {
    'input': ATTRIBUTES,
    'output': ATTRIBUTES + ['email-src', 'text'],
    'format': 'misp_standard'
}

LOGGER = logging.getLogger('source_confidence')
LOGGER.setLevel(logging.INFO)



def init(misp_url, misp_key, misp_verifycert, proxies):
    return PyMISP(misp_url, misp_key, ssl=misp_verifycert, debug=False, proxies=proxies)


def get_timestamp_from_attribute(attribute):
    current_timestamp = attribute['last_seen']
    if not current_timestamp:
        current_timestamp = attribute['first_seen']
    if not current_timestamp:
        current_timestamp = attribute['timestamp']

    return int(current_timestamp)

def riskscore_color(risk_score: int) -> str:
    """Returns appropriate hex-colors according to risk score."""
    risk_score = int(risk_score)
    if risk_score < 25:
        return '#CCCCCC'
    elif risk_score < 65:
        return '#FFCE00'
    else:
        return '#CF0A2C'


def handler(q=False):
    """Handle enrichment."""
    if q is False:
        return False
    request = json.loads(q)

    # print(request)

    if not request.get('attribute') or not check_input_attribute(request['attribute'], requirements=('type', 'value')):
        return {'error': f'{standard_error_message}, {checking_error}.'}
    if request['attribute']['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attribute type.'}

    input_attribute = request.get('attribute')
    # print("Attribute: ", input_attribute)

    config = request.get('config')

    if config and config.get('misp_url'):
        misp_url = config.get('misp_url')
    else:
        misperrors['error'] = 'Missing base MISP URL.'
        return misperrors

    if config and config.get('misp_authkey'):
        misp_key = config.get('misp_authkey')
    else:
        misperrors['error'] = 'Missing MISP admin authkey.'
        return misperrors

    # doesnt verify ssl and no proxy support for now
    misp = init(misp_url, misp_key, False, { } )

    if config and config.get('confidence_json'):
        weights_file = config.get('confidence_json')
    else:
        weights_file = '/var/tmp/misp-source-confidence.json'

    weights = { }
    if not os.path.isfile(weights_file):
        misperrors['error'] = 'Missing confidence json file, has the background job completed yet?'
        return misperrors

    with open(weights_file, 'r') as f:
        try:
            weights = json.loads( f.read() )
        except Exception as e:
            misperrors['error'] = 'Failed to load  confidence json file, file is not json.'
            return misperrors


    # other values are 1.0, 2.0 and 4.0
    if config and config.get('degrade_hours'):
        degrading_hours = float(config.get('degrade_hours'))
    else:
        degrading_hours = 30 * 24 # 30 days by default.

    if config and config.get('degrade_delta'):
        degrading_line = float(config.get('degrade_delta'))
    else:
        degrading_line = 0.5


    # look up all organizations that match this attribute

    # results = misp.search(quick_filter=input_attribute['value'])
    results = misp.search(value=input_attribute['value'])

    total_score = 0.0
    confidence = 0.0

    r = {"results": []}

    current_time = time.time()

    # print("%r total events match this attribute." % len(results))
    for event in results:
        # get orgc id
        org = event['Event']['orgc_id']

        if not org in weights:
            misperrors['error'] = "Missing org id in confidence table: %s." % org
            print(misperrors)
            return misperrors

        table = weights[org]
        # find our attribute
        attribute = None
        for a in event['Event']['Attribute']:
            if a['value'] == input_attribute['value']:
                attribute = a
                break

        if not attribute:
            misperrors['error'] = "No attribute found to match, must be a mistake?"
            print(misperrors)
            print(json.dumps(event['Event']))
            # return misperrors
            continue

        # calculate score using source score #1

        # broke it out into smaller steps for easier understanding
        time_delta = current_time - get_timestamp_from_attribute(attribute)
        time_delta = time_delta / ( degrading_hours * 3600 )
        time_delta = time_delta ** ( 1 / degrading_line )

        score = table['scs'] * max(0, 1.0 - time_delta )
        # print("Score: ", score)

        total_score += score
        confidence += table['scs']

    if confidence > 0:
        final_score = ( total_score / confidence) * 100.0 # make it a pct
        # print("Final score: %.2f" % final_score)

        r = {'results': [{'types': mispattributes['output'],
                      'values':["Final score: %.2f%%" % final_score]}]}

    else:
        misperrors['error'] = "Unable to find value in MISP"
        print(misperrors)
        print(json.dumps(results))
        return misperrors

    return r

def introspection():
    """Returns a dict of the supported attributes."""
    return mispattributes


def version():
    """Returns a dict with the version and the associated meta-data
    including potential configurations required of the module."""
    moduleinfo['config'] = moduleconfig
    return moduleinfo

