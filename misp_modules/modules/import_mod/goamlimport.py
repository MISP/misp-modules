import json, datetime
import xml.etree.ElementTree as ET
from collections import defaultdict
from pymisp import MISPEvent

misperrors = {'error': 'Error'}
moduleinfo = {'version': 1, 'author': 'Christian Studer',
              'description': 'Import from GoAML',
              'module-type': ['import']}
moduleconfig = []
mispattributes = {'input': ['xml file'], 'output': ['MISPEvent']}

t_from_objects = {'nodes': ['from_person', 'from_account', 'from_entity'],
          'leaves': ['from_funds_code', 'from_country']}
t_to_objects = {'nodes': ['to_person', 'to_account', 'to_entity'],
        'leaves': ['to_funds_code', 'to_country']}
t_person_objects = {'nodes': ['addresses'],
            'leaves': ['first_name', 'middle_name', 'last_name', 'gender', 'title', 'mothers_name', 'birthdate',
                       'passport_number', 'passport_country', 'id_number', 'birth_place', 'alias', 'nationality1']}
t_account_objects = {'nodes': ['signatory'],
             'leaves': ['institution_name', 'institution_code', 'swift', 'branch', 'non_banking_insitution',
                        'account', 'currency_code', 'account_name', 'iban', 'client_number', 'opened', 'closed',
                        'personal_account_type', 'balance', 'date_balance', 'status_code', 'beneficiary',
                        'beneficiary_comment', 'comments']}
entity_objects = {'nodes': ['addresses'],
          'leaves': ['name', 'commercial_name', 'incorporation_legal_form', 'incorporation_number', 'business', 'phone']}

goAMLobjects = {'report': {'nodes': ['reporting_person', 'location'],
                           'leaves': ['rentity_id', 'submission_code', 'report_code', 'submission_date', 'currency_code_local']},
                'reporting_person': {'nodes': ['addresses'], 'leaves': ['first_name', 'middle_name', 'last_name', 'title']},
                'location': {'nodes': [], 'leaves': ['address_type', 'address', 'city', 'zip', 'country_code', 'state']},
                'transaction': {'nodes': ['t_from', 't_from_my_client', 't_to', 't_to_my_client'],
                                'leaves': ['transactionnumber', 'transaction_location', 'date_transaction',
                                           'transmode_code', 'amount_local']},
                't_from': t_from_objects, 't_from_my_client': t_from_objects,
                't_to': t_to_objects, 't_to_my_client': t_to_objects,
                'addresses': {'nodes': ['address'], 'leaves': []},
                'address': {'nodes': [], 'leaves': ['address_type', 'address', 'city', 'zip', 'country_code', 'state']},
                'from_person': t_person_objects, 'to_person': t_person_objects, 't_person': t_person_objects,
                'from_account': t_account_objects, 'to_account': t_account_objects,
                'signatory': {'nodes': ['t_person'], 'leaves': []},
                'from_entity': entity_objects, 'to_entity': entity_objects,
                }

t_account_mapping = {'t_account': 'bank-account', 'institution_name': 'institution-name', 'institution_code': 'institution-code',
                     'iban': 'iban', 'swift': 'swift', 'branch': 'branch', 'non_banking_institution': 'non-bank-institution',
                     'account': 'account', 'currency_code': 'currency-code', 'account_name': 'account-name',
                     'client_number': 'client-number', 'personal_account_type': 'personal-account-type', 'opened': 'opened',
                     'closed': 'closed', 'balance': 'balance', 'status_code': 'status-code', 'beneficiary': 'beneficiary',
                     'beneficiary_comment': 'beneficiary-comment', 'comments': 'comments'}

t_person_mapping = {'t_person': 'person', 'comments': 'text', 'first_name': 'first-name', 'middle_name': 'middle-name',
                    'last_name': 'last-name', 'title': 'title', 'mothers_name': 'mothers-name', 'alias': 'alias',
                    'birthdate': 'date-of-birth', 'birth_place': 'place-of-birth', 'gender': 'gender','nationality1': 'nationality',
                    'passport_number': 'passport-number', 'passport_country': 'passport-country', 'ssn': 'social-security-number',
                    'id_number': 'identity-card-number'}

location_mapping = {'location': 'geolocation', 'city': 'city', 'state': 'region', 'country-code': 'country', 'address': 'address',
                   'zip': 'zipcode'}

t_entity_mapping = {'entity': 'legal-entity', 'name': 'name', 'business': 'business', 'commercial_name': 'commercial-name',
                    'phone': 'phone-number', 'incorporation_legal_form': 'legal-form', 'incorporation_number': 'registration-number'}

goAMLmapping = {'from_account': t_account_mapping, 'to_account': t_account_mapping,
                'from_person': t_person_mapping, 'to_person': t_person_mapping, 'reporting_person': t_person_mapping,
                'from_entity': t_entity_mapping, 'to_entity': t_entity_mapping,
                'location': location_mapping, 'address': location_mapping,
                'transaction': {'transaction': 'transaction', 'transactionnumber': 'transaction-number', 'date_transaction': 'date',
                                'transaction_location': 'location', 'transmode_code': 'transmode-code', 'amount_local': 'amount',
                                'transmode_comment': 'transmode-comment', 'date_posting': 'date-posting', 'teller': 'teller',
                                'authorized': 'authorized', 'transaction_description': 'text'}}

nodes_to_ignore = ['addresses', 'signatory']

class GoAmlParser():
    def __init__(self):
        self.dict = {}
        self.misp_event = MISPEvent()

    def readFile(self, filename):
        self.tree = ET.parse(filename).getroot()

    def parse_xml(self):
        self.dict = self.itterate(self.tree, 'report')
        self.dict['transaction'] = []
        for t in self.tree.findall('transaction'):
            self.dict['transaction'].append(self.itterate(t, 'transaction'))
        self.misp_event.timestamp = self.dict.get('submission_date')

    def itterate(self, tree, aml_type):
        element_dict = {}
        for element in tree:
            tag = element.tag
            mapping = goAMLobjects.get(aml_type)
            if tag in mapping.get('nodes'):
                if aml_type == 'transaction':
                    self.fill_transaction(element, element_dict, tag)
                element_dict[tag] = self.itterate(element, tag)
            elif tag in mapping.get('leaves'):
                try:
                    element_dict[goAMLmapping[aml_type][tag]] = element.text
                except KeyError:
                    pass
        return element_dict

    @staticmethod
    def fill_transaction(element, element_dict, tag):
        if 't_from' in tag:
            element_dict['from-funds-code'] = element.find('from_funds_code').text
            element_dict['from-country'] = element.find('from_country').text
        if 't_to' in tag:
            element_dict['to-funds-code'] = element.find('to_funds_code').text
            element_dict['to-country'] = element.find('to_country').text

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('file'):
        filename = request['file']
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    aml_parser = GoAmlParser()
    try:
        aml_parser.readFile(filename)
    except:
        misperrors['error'] = "Impossible to read the file"
        return misperrors
    aml_parser.parse_xml()
    return aml_parser.dict

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
