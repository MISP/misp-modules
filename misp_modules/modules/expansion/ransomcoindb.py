import json
from ._ransomcoindb import ransomcoindb
from pymisp import MISPObject

copyright = """
  Copyright 2019 (C) by Aaron Kaplan <aaron@lo-res.org>, all rights reserved.
  This file is part of the ransomwarecoindDB project and licensed under the AGPL 3.0 license
"""

__version__ = 0.1


debug = False

misperrors = {'error': 'Error'}
# mispattributes = {'input': ['sha1', 'sha256', 'md5', 'btc', 'xmr', 'dash' ], 'output': ['btc', 'sha1', 'sha256', 'md5', 'freetext']}
mispattributes = {'input': ['sha1', 'sha256', 'md5', 'btc'], 'output': ['btc', 'sha1', 'sha256', 'md5', 'freetext'], 'format': 'misp_standard'}
moduleinfo = {'version': __version__, 'author': 'Aaron Kaplan', 'description': 'Module to access the ransomcoinDB (see https://ransomcoindb.concinnity-risks.com)', 'module-type': ['expansion', 'hover']}
moduleconfig = ['api-key']


def handler(q=False):
    """ the main handler function which gets a JSON dict as input and returns a results dict """

    if q is False:
        return False

    q = json.loads(q)
    if "config" not in q or "api-key" not in q["config"]:
        return {"error": "Ransomcoindb API key is missing"}
    api_key = q["config"]["api-key"]
    r = {"results": []}

    """ the "q" query coming in should look something like this:
        {'config': {'api-key': '<api key here>'},
         'md5': 'md5 or sha1 or sha256 or btc',
         'module': 'ransomcoindb',
         'persistent': 1}
    """
    attribute = q['attribute']
    answer = ransomcoindb.get_data_by('BTC', attribute['type'], attribute['value'], api_key)
    """ The results data type should be:
      r =  { 'results': [ {'types': 'md5', 'values': [ a list of all md5s or all binaries related to this btc address ]  } ] }
    """
    if attribute['type'] in ['md5', 'sha1', 'sha256']:
        r['results'].append({'types': 'btc', 'values': [a['btc'] for a in answer]})
    elif attribute['type'] == 'btc':
        # better: create a MISP object
        files = []
        for a in answer:
            obj = MISPObject('file')
            obj.add_attribute('md5', a['md5'])
            obj.add_attribute('sha1', a['sha1'])
            obj.add_attribute('sha256', a['sha256'])
            files.append(obj)
        r['results'] = {'Object': [json.loads(f.to_json()) for f in files]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
