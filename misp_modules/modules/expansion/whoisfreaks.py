import json
import logging

import requests

from . import check_input_attribute, standard_error_message

misperrors = {'error': 'Error'}
mispattributes = {
    'input': ['domain'],
    'output': ['domain', 'dns-soa-email',
               'whois-registrant-email', 'whois-registrant-phone',
               'whois-registrant-name',
               'whois-registrar', 'whois-creation-date', 'domain']
}
moduleinfo = {'version': '1', 'author': 'WhoisFreaks',
              'description': 'Query on whoisfreaks.com',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ['apikey']


def handler(q=False):
    if q:

        request = json.loads(q)

        if 'config' not in request or (not (request['config'].get('apikey') or ('apiKey' in request['config']))):
            misperrors['error'] = 'WhoisFreaks authentication is missing' + request
            return misperrors

        apiKey = request['config'].get('apikey')

        if request.get('domain'):
            domain = request['domain']
            return handle_domain(apiKey, domain, misperrors)
        else:
            misperrors['error'] = "Unsupported attributes types"
            return misperrors
    else:
        return False


def handle_domain(apiKey, domain, errors):
    result_filtered = {"results": []}
    r, status_ok = expand_whois(apiKey, domain)
    if status_ok:
        if r:
            result_filtered['results'].extend(r)

    r, status_ok = expand_dns(apiKey, domain)
    if status_ok:
        if r:
            result_filtered['results'].extend(r)
            
    return result_filtered


def expand_whois(apiKey, domain):
    r = []
    ns_servers = []
    status_ok = False

    try:
        results = get_whois_response(domain, apiKey)

        if results:
            status_ok = True

            if 'create_date' in results:
                r.append(
                    {
                        'types': ['whois-creation-date'],
                        'values': [results['create_date']],
                        'categories': ['Attribution'],
                        'comment': 'Creation Date for %s by whoisFreaks'
                                   % domain

                    }
                )

            if 'domain_registrar' in results:
                if 'registrar_name' in results['domain_registrar']:
                    r.append(
                        {
                            'types': ['whois-registrant-name'],
                            'values': [results['domain_registrar']['registrar_name']],
                            'categories': ['Attribution'],
                            'comment': 'Whois information of %s by whoisFreaks'
                                       % domain
                        }
                    )
                if 'email_address' in results['domain_registrar']:
                    r.append(
                        {
                            'types': ['whois-registrant-email'],
                            'values': [results['domain_registrar']['email_address']],
                            'categories': ['Attribution'],
                            'comment': 'Whois information of %s by whoisFreaks'
                                       % domain
                        }
                    )

                if 'phone_number' in results['domain_registrar']:
                    r.append(
                        {
                            'types': ['whois-registrant-email'],
                            'values': [results['domain_registrar']['phone_number']],
                            'categories': ['Attribution'],
                            'comment': 'Whois information of %s by whoisFreaks'
                                       % domain
                        }
                    )

            if 'name_servers' in results:
                ns_servers = results['name_servers']
                r.append(
                    {
                        'types': ['domain'],
                        'values': ns_servers,
                        'categories': ['Attribution'],
                        'comment': 'list of name server for %s by whoisFreaks'
                                   % domain

                    }
                )

    except Exception:
        misperrors['error'] = "Error while processing Whois Data"
        return [], False

    return r, status_ok


def expand_dns(apiKey, domain):
    r = []
    status_ok = False
    list_ipv4 = []
    list_ipv6 = []
    servers_mx = []
    soa_hostnames = []

    try:
        results = get_dns_response(domain, apiKey)

        if results:
            status_ok = True

            if 'dnsRecords' in results:
                dns_records = results['dnsRecords']

            for record in dns_records:
                if record['dnsType'] == 'A':
                    list_ipv4.append(record['address'])
                elif record['dnsType'] == 'AAAA':
                    list_ipv6.append(record['address'])
                elif record['dnsType'] == 'MX':
                    servers_mx.append(record['target'])
                elif record['dnsType'] == 'SOA':
                    soa_hostnames.append(record['host'])
                    
            if list_ipv4:
                r.append({'types': ['domain|ip'],
                          'values': ['%s|%s' % (domain, ipv4) for ipv4 in
                                    list_ipv4],
                          'categories': ['Network activity'],
                                  'comment': ' List ipv4 of %s ' %
                                    domain
                                  })
            if list_ipv6:
                r.append({'types': ['domain|ip'],
                          'values': ['%s|%s' % (domain, ipv6) for ipv6 in
                                    list_ipv6],
                          'categories': ['Network activity'],
                          'comment': ' List ipv6 of %s' %
                                    domain
                          })

            if servers_mx:
                r.append({'types': ['domain'],
                          'values': servers_mx,
                          'categories': ['Network activity'],
                          'comment': ' List mx of %s' %
                                    domain
                          })
            if soa_hostnames:
                r.append({'types': ['domain'],
                          'values': soa_hostnames,
                          'categories': ['Network activity'],
                          'comment': ' List soa of %s' %
                                    domain
                          })


    except Exception:
        misperrors['error'] = "Error while processing Whois Data"
        return [], False

    return r, status_ok


def get_whois_response(domain, apiKey):
    query = requests.get(
        f"https://api.whoisfreaks.com/v1.0/whois?apiKey={apiKey}&whois=live&domainName={domain}"
    )
    if query.status_code != 200 and query.status_code != 206:
        return {'error': f'Error while querying whoisfreaks.com - {query.status_code}: {query.reason}'}
    return query.json()


def get_dns_response(domain, apiKey):
    query = requests.get(
        f"https://api.whoisfreaks.com/v1.0/dns/live?apiKey={apiKey}&domainName={domain}&type=SOA,AAAA,A,MX"
    )
    if query.status_code != 200 and query.status_code != 206:
        return {'error': f'Error while querying whoisfreaks.com - {query.status_code}: {query.reason}'}
    return query.json()

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


# def main():

        
#     apiKey = 'b7d971e9fe0f43d097d130e245b0f687'
#     domain = 'google.com'
#     return handle_domain(apiKey, domain, misperrors)
        

# if __name__ == '__main__':
#     main()
 