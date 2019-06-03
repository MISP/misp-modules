# -*- coding: utf-8 -*-
import base64
import json
import os
import sys
sys.path.append('{}/lib'.format('/'.join((os.path.realpath(__file__)).split('/')[:-3])))
from joe_parser import JoeParser

misperrors = {'error': 'Error'}
userConfig = {}
inputSource = ['file']

moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'Import for Joe Sandbox JSON reports',
              'module-type': ['import']}

moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    data = base64.b64decode(q.get('data')).decode('utf-8')
    if not data:
        return json.dumps({'success': 0})
    joe_parser = JoeParser()
    joe_parser.parse_data(json.loads(data)['analysis'])
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
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    modulesetup['format'] = 'misp_standard'
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
