import json
import logging
import sys

from domaintools import API


log = logging.getLogger('domaintools')
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {'error': 'Error'}
mispattributes = {
    'input': ['domain'],
    'output': ['whois-registrant-email', 'whois-registrant-phone', 'whois-registrant-name',
               'whois-registrar', 'whois-creation-date', 'freetext']
}

moduleinfo = {
    'version': '0.1',
    'author': 'Raphaël Vinot',
    'description': 'DomainTools MISP expansion module.',
    'module-type': ['expansion', 'hover']
}

moduleconfig = ['username', 'api_key']


class DomainTools(object):

    def __init__(self):
        self.reg_mail = set()
        self.reg_phone = set()
        self.reg_name = set()
        self.registrar = set()
        self.creation_date = set()
        self.freetext = ''

    def dump(self):
        to_return = []
        if self.reg_mail:
            to_return.append({'type': ['whois-registrant-email'], 'values': list(self.reg_mail)})
        if self.reg_phone:
            to_return.append({'type': ['whois-registrant-phone'], 'values': list(self.reg_phone)})
        if self.reg_name:
            to_return.append({'type': ['whois-registrant-name'], 'values': list(self.reg_name)})
        if self.registrar:
            to_return.append({'type': ['whois-registrar'], 'values': list(self.registrar)})
        if self.creation_date:
            to_return.append({'type': ['whois-creation-date'], 'values': list(self.creation_date)})
        if self.freetext:
            to_return.append({'type': ['freetext'], 'values': [self.freetext]})
        return to_return


def handler(q=False):
    if not q:
        return q

    request = json.loads(q)
    to_query = None
    for t in mispattributes['input']:
        to_query = request.get(t)
        if to_query:
            break
    if not to_query:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    if request.get('config'):
        if (request['config'].get('username') is None) or (request['config'].get('api_key') is None):
            misperrors['error'] = 'DomainTools authentication is incomplete'
            return misperrors
        else:
            domtools = API(request['config'].get('username'), request['config'].get('api_key'))
    else:
        misperrors['error'] = 'DomainTools authentication is missing'
        return misperrors

    whois_entry = domtools.parsed_whois(to_query)
    values = DomainTools()

    if whois_entry.has_key('error'):
        misperrors['error'] = whois_entry['error']['message']
        return misperrors

    if whois_entry.has_key('registrant'):
        values.reg_name.add(whois_entry['registrant'])

    if whois_entry.has_key('registration'):
        values.creation_date.add(whois_entry['registration']['created'])

    if whois_entry.has_key('whois'):
        values.freetext = whois_entry['whois']['record']
    if whois_entry.emails():
        # NOTE: not sure we want to do that (contains registrar emails)
        values.reg_mail |= whois_entry.emails()
    if whois_entry.has_key('parsed_whois'):
        if whois_entry['parsed_whois']['created_date']:
            values.creation_date.add(whois_entry['parsed_whois']['created_date'])
        if whois_entry['parsed_whois']['registrar']['name']:
            values.registrar.add(whois_entry['parsed_whois']['registrar']['name'])
        for key, entry in whois_entry['parsed_whois']['contacts'].items():
            # TODO: pass key as comment
            if entry['email']:
                values.reg_mail.add(entry['email'])
            if entry['phone']:
                values.reg_phone.add(entry['phone'])
            if entry['name']:
                values.reg_name.add(entry['name'])
    return json.dumps({'results': values.dump()})


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
