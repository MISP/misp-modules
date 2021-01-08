# -*- coding: utf-8 -*-

import json
try:
    from onyphe import Onyphe
except ImportError:
    print("pyonyphe module not installed.")

misperrors = {'error': 'Error'}

mispattributes = {'input': ['ip-src', 'ip-dst', 'hostname', 'domain'],
                  'output': ['hostname', 'domain', 'ip-src', 'ip-dst', 'url']}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Sebastien Larinier @sebdraven',
              'description': 'Query on Onyphe',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ['apikey']


def handler(q=False):
    if q:

        request = json.loads(q)

        if not request.get('config') or not request['config'].get('apikey'):
            misperrors['error'] = 'Onyphe authentication is missing'
            return misperrors

        api = Onyphe(request['config'].get('apikey'))

        if not api:
            misperrors['error'] = 'Onyphe Error instance api'

        ip = ''
        if request.get('ip-src'):
            ip = request['ip-src']
        elif request.get('ip-dst'):
            ip = request['ip-dst']
        else:
            misperrors['error'] = "Unsupported attributes type"
            return misperrors

        return handle_expansion(api, ip, misperrors)
    else:
        return False


def handle_expansion(api, ip, misperrors):
    result = api.ip(ip)

    if result['status'] == 'nok':
        misperrors['error'] = result['message']
        return misperrors

    # categories = list(set([item['@category'] for item in result['results']]))

    result_filtered = {"results": []}
    urls_pasties = []
    asn_list = []
    os_list = []
    domains_resolver = []
    domains_forward = []

    for r in result['results']:
        if r['@category'] == 'pastries':
            if r['source'] == 'pastebin':
                urls_pasties.append('https://pastebin.com/raw/%s' % r['key'])
        elif r['@category'] == 'synscan':
            asn_list.append(r['asn'])
            os_target = r['os']
            if os_target != 'Unknown':
                os_list.append(r['os'])
        elif r['@category'] == 'resolver' and r['type'] == 'reverse':
            domains_resolver.append(r['reverse'])
        elif r['@category'] == 'resolver' and r['type'] == 'forward':
            domains_forward.append(r['forward'])

    result_filtered['results'].append({'types': ['url'], 'values': urls_pasties,
                                       'categories': ['External analysis']})

    result_filtered['results'].append({'types': ['AS'], 'values': list(set(asn_list)),
                                       'categories': ['Network activity']})

    result_filtered['results'].append({'types': ['target-machine'],
                                       'values': list(set(os_list)),
                                       'categories': ['Targeting data']})

    result_filtered['results'].append({'types': ['domain'],
                                       'values': list(set(domains_resolver)),
                                       'categories': ['Network activity'],
                                       'comment': 'resolver to %s' % ip})

    result_filtered['results'].append({'types': ['domain'],
                                       'values': list(set(domains_forward)),
                                       'categories': ['Network activity'],
                                       'comment': 'forward to %s' % ip})
    return result_filtered


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
