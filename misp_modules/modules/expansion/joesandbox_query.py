# -*- coding: utf-8 -*-
import jbxapi
import json
from joe_parser import JoeParser

misperrors = {'error': 'Error'}

inputSource = ['link']

moduleinfo = {'version': '0.2', 'author': 'Christian Studer',
              'description': 'Query Joe Sandbox API with a report URL to get the parsed data.',
              'module-type': ['expansion']}
moduleconfig = ['apiurl', 'apikey', 'import_pe', 'import_mitre_attack']


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    apiurl = request['config'].get('apiurl') or 'https://jbxcloud.joesecurity.org/api'
    apikey = request['config'].get('apikey')
    parser_config = {
        "import_pe": request["config"].get('import_pe', "false") == "true",
        "mitre_attack": request["config"].get('import_mitre_attack', "false") == "true",
    }

    if not apikey:
        return {'error': 'No API key provided'}

    url = request['attribute']['value']
    if "/submissions/" not in url:
        return {'error': "The URL does not point to a Joe Sandbox analysis."}

    submission_id = url.split('/')[-1]  # The URL has the format https://example.net/submissions/12345
    joe = jbxapi.JoeSandbox(apiurl=apiurl, apikey=apikey, user_agent='MISP joesandbox_query')

    try:
        joe_info = joe.submission_info(submission_id)
    except jbxapi.ApiError as e:
        return {'error': str(e)}

    if joe_info["status"] != "finished":
        return {'error': "The analysis has not finished yet."}

    if joe_info['most_relevant_analysis'] is None:
        return {'error': "No analysis belongs to this submission."}

    analysis_webid = joe_info['most_relevant_analysis']['webid']

    joe_parser = JoeParser(parser_config)
    joe_data = json.loads(joe.analysis_download(analysis_webid, 'jsonfixed')[1])
    joe_parser.parse_data(joe_data['analysis'])
    joe_parser.finalize_results()

    return {'results': joe_parser.results}


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup['input'] = inputSource
    except NameError:
        pass
    modulesetup['format'] = 'misp_standard'
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
