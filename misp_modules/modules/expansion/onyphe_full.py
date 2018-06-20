import json
# -*- coding: utf-8 -*-

import json
try:
    from onyphe import Onyphe
except ImportError:
    print("pyonyphe module not installed.")

misperrors = {'error': 'Error'}

mispattributes = {'input': ['ip-src', 'ip-dst', 'hostname', 'domain'], 'output': ['hostname', 'domain', 'ip-src', 'ip-dst','url']}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Sebastien Larinier @sebdraven',
              'description': 'Query on Onyphe',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ['apikey']


def handler(q=False):
    if q:

        request = json.loads(q)

        if not request.get('config') and not (request['config'].get('apikey')):
            misperrors['error'] = 'Onyphe authentication is missing'
            return misperrors

        api = Onyphe(request['config'].get('apikey'))

        if not api:
            misperrors['error'] = 'Onyphe Error instance api'

        ip = ''
        if request.get('ip-src'):
            ip = request['ip-src']
            return handle_ip(api ,ip, misperrors)
        elif request.get('ip-dst'):
            ip = request['ip-dst']
            return handle_ip(api,ip,misperrors)
        elif request.get('domain'):
            domain = request['domain']
        elif request.get('hostname'):
            hostname = request['hostname']
        else:
            misperrors['error'] = "Unsupported attributes type"
            return misperrors


    else:
        return False


def handle_domain(api, domain, misperrors):
    pass


def handle_ip(api, ip, misperrors):
    result_filtered = {"results": []}

    r, status_ok = expand_syscan(api, ip, misperrors)

    if status_ok:
         result_filtered['results'].append(r)
    else:
         misperrors['error'] = "Error syscan result"

    r, status_ok = expand_pastries(api,misperrors,ip=ip)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = 'Error pastries result'
        return misperrors

    # r, status_ok = expand_datascan(api, misperrors, ip=ip)
    #
    # if status_ok:
    #     result_filtered['results'].append(r)
    # else:
    #     return r
    #
    # r, status_ok = expand_forward(api, ip, misperrors)
    #
    # if status_ok:
    #     result_filtered['results'].append(r)
    # else:
    #     return r
    #
    # r, status_ok = expand_reverse(api, ip, misperrors)
    #
    # if status_ok:
    #     result_filtered['results'].append(r)
    # else:
    #     return r
    print(result_filtered)
    return result_filtered


def expand_syscan(api, ip, misperror):
    status_ok = False
    r = []
    asn_list = []
    os_list = []
    geoloc = []
    orgs = []
    results = api.synscan(ip)

    if results['status'] == 'ok':
        status_ok = True
        for elem in results['results']:
            asn_list.append(elem['asn'])
            os_target = elem['os']
            geoloc.append(elem['location'])
            orgs.append(elem['organization'])
            if os_target != 'Unknown':
                os_list.append(elem['os'])

            r.append({'types': ['target-machine'],
                    'values': list(set(os_list)),
                    'categories': ['Targeting data']})

            r.append({'types': ['target-location'],
                      'values': list(set(geoloc)),
                      'categories': ['Targeting data']})

            r.append({'types': ['target-org'],
                      'values': list(set(orgs)),
                      'categories': ['Targeting data']})

            r.append({'types': ['AS'], 'values': list(set(asn_list)),
                      'categories': ['Network activity']})

    return r, status_ok


def expand_datascan(api, misperror,**kwargs):
    status_ok = False
    r = None

    return r,status_ok


def expand_reverse(api, ip, misperror):
    status_ok = False
    r = None

    return r, status_ok


def expand_forward(api, ip, misperror):
    status_ok = False
    r = None

    return r, status_ok


def expand_pastries(api, misperror, **kwargs):
    status_ok = False
    r = []
    ip = None
    domain = None
    result = None
    urls_pasties = []
    domains = []
    ips = []
    if 'ip' in kwargs:
        ip = kwargs.get('ip')
        result = api.pastries(ip)

    if 'domain' in kwargs:
        domain = kwargs.get('domain')
        result = api.pastries(domain)

    if result['status'] =='ok':
        status_ok = True
        for item in result['results']:
            if item['@category'] == 'pastries':
                if item['@type'] == 'pastebin':
                    urls_pasties.append('https://pastebin.com/raw/%s' % item['key'])

                    if 'domain' in item:
                        domains.extend(item['domain'])
                    if 'ip' in item:
                        ips.extend(item['ip'])
                    if 'hostname' in item:
                        domains.extend(item['hostname'])

        r.append({'types': ['url'], 'values': urls_pasties,
                                           'categories': ['External analysis']})
        r.append({'types': ['domain'], 'values': list(set(domains)),
                                           'categories': ['Network activity']})

        r.append({'types': ['ip-dst'], 'values': list(set(ips)),
                  'categories': ['Network activity']})

    return r, status_ok


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo