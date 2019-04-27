import json
from pyintel471 import PyIntel471

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', 'url', 'ip-src', 'ip-dst', 'email-src',
                            'email-dst', 'target-email', 'whois-registrant-email',
                            'whois-registrant-name', 'md5', 'sha1', 'sha256'], 'output': ['freetext']}
moduleinfo = {'version': '0.1', 'author': 'Raphaël Vinot', 'description': 'Module to access Intel 471',
              'module-type': ['hover', 'expansion']}
moduleconfig = ['email', 'authkey']


def cleanup(response):
    '''The entries have uids that will be recognised as hashes when they shouldn't'''
    j = response.json()
    if j['iocTotalCount'] == 0:
        return 'Nothing has been found.'
    for ioc in j['iocs']:
        ioc.pop('uid')
        if ioc['links']['actorTotalCount'] > 0:
            for actor in ioc['links']['actors']:
                actor.pop('uid')
        if ioc['links']['reportTotalCount'] > 0:
            for report in ioc['links']['reports']:
                report.pop('uid')
    return json.dumps(j, indent=2)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    for input_type in mispattributes['input']:
        if input_type in request:
            to_query = request[input_type]
            break
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    if (request.get('config')):
        if (request['config'].get('email') is None) or (request['config'].get('authkey') is None):
            misperrors['error'] = 'Intel 471 authentication is missing'
            return misperrors

    intel471 = PyIntel471(email=request['config'].get('email'), authkey=request['config'].get('authkey'))
    ioc_filters = intel471.iocs_filters(ioc=to_query)
    res = intel471.iocs(filters=ioc_filters)
    to_return = cleanup(res)

    r = {'results': [{'types': mispattributes['output'], 'values': to_return}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
