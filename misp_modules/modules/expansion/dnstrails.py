import json
import logging
import sys
from dnstrails import DnsTrails

log = logging.getLogger('dnstrails')
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {'error': 'Error'}
mispattributes = {
    'input': ['hostname', 'domain', 'ip-src', 'ip-dst'],
    'output': ['hostname', 'domain', 'ip-src', 'ip-dst', 'dns-soa-email']
}

moduleinfo = {'version': '1', 'author': 'Sebastien Larinier @sebdraven',
              'description': 'Query on securitytrails.com',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ['apikey']


def handler(q=False):
    if q:

        request = json.loads(q)

        if not request.get('config') and not (request['config'].get('apikey')):
            misperrors['error'] = 'DNS authentication is missing'
            return misperrors

        api = DnsTrails(request['config'].get('apikey'))

        if not api:
            misperrors['error'] = 'Onyphe Error instance api'

        ip = ""
        dns_name = ""

        ip = ''
        if request.get('ip-src'):
            ip = request['ip-src']
            return handle_ip(api, ip, misperrors)
        elif request.get('ip-dst'):
            ip = request['ip-dst']
            return handle_ip(api, ip, misperrors)
        elif request.get('domain'):
            domain = request['domain']
            return handle_domain(api, domain, misperrors)
        elif request.get('hostname'):
            hostname = request['hostname']
            return handle_domain(api, hostname, misperrors)
        else:
            misperrors['error'] = "Unsupported attributes type"
            return misperrors
    else:
        return False


def handle_domain(api, domain, misperrors):
    result_filtered = {"results": []}

    r, status_ok = expand_domain_info(api, misperrors, domain)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = 'Error pastries result'
        return misperrors

    return result_filtered

def handle_ip(api, ip, misperrors):
    pass


def expand_domain_info(api, misperror,domain):
    r = []
    status_ok = False
    ns_servers = []
    list_ipv4 = []
    list_ipv6 = []
    servers_mx = []
    soa_hostnames = []

    results = api.domain(domain)

    if results:
        if 'current_dns' in results:
            if 'values' in results['current_dns']['ns']:
                ns_servers = [ns_entry['nameserver'] for ns_entry in
                              results['current_dns']['ns']['values']
                              if 'nameserver' in ns_entry]
            if 'values' in results['current_dns']['a']:
                list_ipv4 = [a_entry['ip'] for a_entry in
                             results['current_dns']['a']['values'] if
                             'ip' in a_entry]

            if 'values' in results['current_dns']['aaaa']:
                list_ipv6 = [ipv6_entry['ipv6'] for ipv6_entry in
                             results['current_ns']['aaaa']['values'] if
                             'ipv6' in ipv6_entry]

            if 'values' in results['current_dns']['mx']:
                servers_mx = [mx_entry['hostname'] for mx_entry in
                           results['current_dns']['mx']['values'] if
                           'hostname' in mx_entry]
            if 'values' in results['current_dns']['soa']:
                soa_hostnames = [soa_entry['email'] for soa_entry in
                               results['current_dns']['soa']['values'] if
                               'email' in soa_entry]

        if ns_servers:
            r.append({'type': ['domain'],
                      'values': ns_servers,
                      'Category': ['Network Activity'],
                      'comment': 'List of name servers  of %s first seen %s ' %
                                 (domain, results['current_dns']['ns']['first_seen'])
        })

        if list_ipv4:
            r.append({'type': ['domain|ip'],
                      'values': ['%s|%s' % (domain, ipv4) for ipv4 in list_ipv4],
                      'Category': ['Network Activity'],
                      'comment': ' List ipv4 of %s first seen %s' %
                                 (domain,
                                  results['current_dns']['a']['first_seen'])

            })
        if list_ipv6:
            r.append({'type': ['domain|ip'],
                      'values': ['%s|%s' % (domain, ipv6) for ipv6 in
                                 list_ipv6],
                      'Category': ['Network Activity'],
                      'comment': ' List ipv6 of %s first seen %s' %
                                 (domain,
                                  results['current_dns']['aaaa']['first_seen'])

                      })

        if servers_mx:
            r.append({'type': ['domain'],
                      'values': servers_mx,
                      'Category': ['Network Activity'],
                      'comment': ' List mx of %s first seen %s' %
                                 (domain,
                                  results['current_dns']['mx']['first_seen'])

                      })
        if soa_hostnames:
            r.append({'type': ['domain'],
                      'values': soa_hostnames,
                      'Category': ['Network Activity'],
                      'comment': ' List soa of %s first seen %s' %
                                 (domain,
                                  results['current_dns']['soa']['first_seen'])
                      })


    return r, status_ok

def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo