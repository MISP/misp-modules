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

    r,status_ok = expand_syscan(api,ip,misperrors)

    if status_ok:
        result_filtered['results'].append(r)
    else:
        return r

    r, status_ok = expand_datascan(api,misperrors, ip=ip)

    if status_ok:
        result_filtered['results'].append(r)
    else:
        return r

    r, status_ok = expand_forward(api, ip,misperrors)

    if status_ok:
        result_filtered['results'].append(r)
    else:
        return r

    r, status_ok = expand_reverse(api, ip,misperrors)

    if status_ok:
        result_filtered['results'].append(r)
    else:
        return r

    return result_filtered


def expand_syscan(api, ip, misperror):
    status_ok = False
    r = None

    return r,status_ok


def expand_datascan(api, misperror,**kwargs):
    status_ok = False
    r = None

    return r,status_ok


def expand_reverse(api, ip, misperror):
    status_ok = False
    r = None

    return r,status_ok


def expand_forward(api, ip, misperror):
    status_ok = False
    r = None

    return r,status_ok

def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo