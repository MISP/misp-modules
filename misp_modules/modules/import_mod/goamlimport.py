import json, datetime
import xml.etree.ElementTree as ET
from collections import defaultdict

misperrors = {'error': 'Error'}
moduleinfo = {'version': 1, 'author': 'Christian Studer',
              'description': 'Import from GoAML',
              'module-type': ['import']}
moduleconfig = []
mispattributes = {'input': ['xml file'], 'output': ['MISPEvent']}

t_from = {'nodes': ['from_person', 'from_account', 'from_entity'],
          'leaves': ['from_funds_code', 'from_country']}
t_to = {'nodes': ['to_person', 'to_account', 'to_entity'],
        'leaves': ['to_funds_code', 'to_country']}
t_person = {'nodes': ['addresses'],
            'leaves': ['first_name', 'middle_name', 'last_name', 'gender', 'title', 'mothers_name', 'birthdate',
                       'passport_number', 'passport_country', 'id_number', 'birth_place', 'alias', 'nationality1']}
t_account = {'nodes': ['signatory'],
             'leaves': ['institution_name', 'institution_code', 'swift', 'branch', 'non_banking_insitution',
                        'account', 'currency_code', 'account_name', 'iban', 'client_number', 'opened', 'closed',
                        'personal_account_type', 'balance', 'date_balance', 'status_code', 'beneficiary',
                        'beneficiary_comment', 'comments']}
entity = {'nodes': ['addresses'],
          'leaves': ['name', 'commercial_name', 'incorporation_legal_form', 'incorporation_number', 'business', 'phone']}

goAMLobjects = {'report': {'nodes': ['reporting_person', 'location'],
                           'leaves': ['rentity_id', 'submission_code', 'report_code', 'submission_date',
                                      'currency_code_local']},
                'reporting_person': {'nodes': ['addresses'],
                                     'leaves': ['first_name', 'middle_name', 'last_name', 'title']},
                'location': {'nodes': [],
                             'leaves': ['address_type', 'address', 'city', 'zip', 'country_code', 'state']},
                'transaction': {'nodes': ['t_from', 't_from_my_client', 't_to', 't_to_my_client'],
                                'leaves': ['transactionnumber', 'transaction_location', 'date_transaction',
                                           'transmode_code', 'amount_local']},
                't_from': t_from,
                't_from_my_client': t_from,
                't_to': t_to,
                't_to_my_client': t_to,
                'addresses': {'nodes': ['address'], 'leaves': []},
                'address': {'nodes': [],
                            'leaves': ['address_type', 'address', 'city', 'zip', 'country_code', 'state']},
                'from_person': t_person,
                'to_person': t_person,
                't_person': t_person,
                'from_account': t_account,
                'to_account': t_account,
                'signatory': {'nodes': ['t_person'], 'leaves': []},
                'from_entity': entity,
                'to_entity': entity,
                }

class GoAmlParser():
    def __init__(self):
        self.dict = {}

    def readFile(self, filename):
        self.tree = ET.parse(filename).getroot()

    def parse_xml(self):
        self.dict = self.itterate(self.tree, 'report')
        self.dict['transaction'] = []
        for t in self.tree.findall('transaction'):
            self.dict['transaction'].append(self.itterate(t, 'transaction'))

    def itterate(self, tree, aml_type):
        elementDict = {}
        for element in tree:
            tag = element.tag
            mapping = goAMLobjects.get(aml_type)
            if tag in mapping.get('nodes'):
                elementDict[tag] = self.itterate(element, tag)
            elif tag in mapping.get('leaves'):
                elementDict[tag] = element.text
        return elementDict

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
