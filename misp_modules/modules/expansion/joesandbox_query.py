# -*- coding: utf-8 -*-
import jbxapi
import json
from joe_parser import JoeParser

misperrors = {'error': 'Error'}
mispattributes = {'input': ['link'], 'format': 'misp_standard'}

moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'Query Joe Sandbox API with a report URL to get the parsed data.',
              'module-type': ['expansion']}
moduleconfig = ['apiurl', 'apikey', 'accept-tac']


class _ParseError(Exception):
    pass


def _parse_bool(value, name="bool"):
    if value is None or value == "":
        return None
    if value in ("true", "True"):
        return True
    if value in ("false", "False"):
        return False
    raise _ParseError("Cannot parse {}. Must be 'true' or 'false'".format(name))


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    apiurl = request['config'].get('apiurl') or 'https://jbxcloud.joesecurity.org/api'
    apikey = request['config'].get('apikey')
    if not apikey:
        return {'error': 'No API key provided'}
    try:
        accept_tac = _parse_bool(request['config'].get('accept-tac'), 'accept-tac')
    except _ParseError as e:
        return {'error': str(e)}
    attribute = request['attribute']
    joe = jbxapi.JoeSandbox(apiurl=apiurl, apikey=apikey, user_agent='MISP joesandbox_analysis', accept_tac=accept_tac)
    joe_info = joe.submission_info(attribute['value'].split('/')[-1])
    joe_parser = JoeParser()
    most_relevant = joe_info['most_relevant_analysis']['webid']
    for analyse in joe_info['analyses']:
        if analyse['webid'] == most_relevant:
            joe_data = json.loads(joe.analysis_download(most_relevant, 'jsonfixed')[1])
            joe_parser.parse_data(joe_data['analysis'])
            break
    joe_parser.finalize_results()
    return {'results': joe_parser.results}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
