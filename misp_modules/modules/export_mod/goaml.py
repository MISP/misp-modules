import json
from pymisp import MISPEvent
import base64

misperrors = {'error': 'Error'}
moduleinfo = {'version': '1', 'author': 'Christian Studer',
              'description': '',
              'module-type': ['export']}
moduleconfig = []
mispattributes = {}
outputFileExtension = "xml"
responseType = "application/xml"

objects_to_parse = ['bank-account', 'person']

goAMLmapping = {'bank-account': 't_account', 'text': 'institution_name', 'institution-code': 'institution_code',
                'swift': 'swift', 'branch': 'branch', 'non-banking-institution': 'non_bank_institution',
                'account': 'account', 'currency-code': 'currency_code', 'account-name': 'account_name',
                'iban': 'iban', 'client-number': 'client_number', 'personal-account-type': 'personal_account_type',
                'opened': 'opened', 'closed': 'closed', 'balance': 'balance', 'status-code': 'status_code',
                'beneficiary': 'beneficiary', 'beneficiary-comment': 'beneficiary_comment', 'comments': 'comments',
                'person': 't_person', 'text': 'comments', 'first-name': 'first_name', 'middle-name': 'middle_name',
                'last-name': 'last_name', 'mothers-name': 'mothers_name', 'title': 'title', 'alias': 'alias',
                'date-of-birth': 'birthdate', 'place-of-birth': 'birth_place', 'gender': 'gender',
                'passport-number': 'passport_number', 'passport-country': 'passport_country',
                'social-security-number': 'ssn', 'nationality': 'nationality1'}

class GoAmlGeneration():
    def __init__(self):
        self.document = {}

    def from_event(self, event):
        self.misp_event = MISPEvent()
        self.misp_event.load(event)

    def parse_objects(self):
        for obj in self.misp_event.objects:
            if obj.name in objects_to_parse:
                obj_dict = {}
                for attribute in obj.attributes:
                    obj_dict[attribute.object_relation] = attribute.value
                self.document[obj.name] = obj_dict

    def build_xml(self):
        self.xml = "<report>"
        if 'bank-account' in self.document:
            if 'report-code' in self.document['bank-account']:
                self.xml += "<report_code>{}</report_code>".format(self.document['bank-account'].pop('report-code').split(' ')[0])
            for a in ('personal-account-type', 'status-code'):
                if a in self.document['bank-account']:
                    self.document['bank-account'][a] = self.document['bank-account'][a].split(' - ')[0]
        self.itterate()
        self.xml += "</report>"

    def itterate(self):
        for t in self.document:
            self.xml += "<{}>".format(goAMLmapping[t])
            for k in self.document[t]:
                try:
                    self.xml += "<{0}>{1}</{0}>".format(goAMLmapping[k], self.document[t][k])
                except KeyError:
                    pass
            self.xml += "</{}>".format(goAMLmapping[t])

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if 'data' not in request:
        return False
    exp_doc = GoAmlGeneration()
    exp_doc.from_event(request['data'][0])
    exp_doc.parse_objects()
    exp_doc.build_xml()
    return {'response': {}, 'data': exp_doc.xml}
    #return {'response': [], 'data': str(base64.b64encode(bytes(exp_doc.document, 'utf-8')), 'utf-8')}

def introspection():
    modulesetup = {}
    try:
        responseType
        modulesetup['responseType'] = responseType
    except NameError:
        pass
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        outputFileExtension
        modulesetup['outputFileExtension'] = outputFileExtension
    except NameError:
        pass
    try:
        inputSource
        mmoduleSetup['inputSource'] = inputSource
    except NameError:
        pass
    return modulesetup

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
