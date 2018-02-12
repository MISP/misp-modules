import json
from pymisp import MISPEvent
from collections import defaultdict
import base64

misperrors = {'error': 'Error'}
moduleinfo = {'version': '1', 'author': 'Christian Studer',
              'description': '',
              'module-type': ['export']}
moduleconfig = []
mispattributes = {}
outputFileExtension = "xml"
responseType = "application/xml"

objects_to_parse = ['transaction', 'bank-account', 'person', 'entity', 'geolocation']

goAMLmapping = {'bank-account': 't_account', 'institution-code': 'institution_code', 'iban': 'iban',
                'swift': 'swift', 'branch': 'branch', 'non-banking-institution': 'non_bank_institution',
                'account': 'account', 'currency-code': 'currency_code', 'account-name': 'account_name',
                'client-number': 'client_number', 'personal-account-type': 'personal_account_type',
                'opened': 'opened', 'closed': 'closed', 'balance': 'balance', 'status-code': 'status_code',
                'beneficiary': 'beneficiary', 'beneficiary-comment': 'beneficiary_comment', 'comments': 'comments',
                'person': 't_person', 'text': 'comments', 'first-name': 'first_name', 'middle-name': 'middle_name',
                'last-name': 'last_name', 'mothers-name': 'mothers_name', 'title': 'title', 'alias': 'alias',
                'date-of-birth': 'birthdate', 'place-of-birth': 'birth_place', 'gender': 'gender',
                'passport-number': 'passport_number', 'passport-country': 'passport_country',
                'social-security-number': 'ssn', 'nationality': 'nationality1', 'identity-card-number': 'id_number',
                'geolocation': 'location', 'city': 'city', 'region': 'state', 'country': 'country-code',
                'address': 'address', 'zipcode': 'zip',
                'transaction': 'transaction', 'transaction-number': 'transactionnumber', 'date': 'date_transaction',
                'location': 'transaction_location', 'transmode-code': 'transmode_code', 'amount': 'amount_local',
                'transmode-comment': 'transmode_comment', 'date-posting': 'date_posting',
                'entity': 'entity', 'name': 'name', 'commercial-name': 'commercial_name', 'business': 'business',
                'legal-form': 'incorporation_legal_form', 'registration-number': 'incorporation_number',
                'phone-number': 'phone'}

class GoAmlGeneration(object):
    def __init__(self, config):
        self.config = config

    def from_event(self, event):
        self.misp_event = MISPEvent()
        self.misp_event.load(event)

    def parse_objects(self):
        uuids = defaultdict(list)
        report_code = []
        currency_code = []
        for obj in self.misp_event.objects:
            obj_type = obj.name
            uuids[obj_type].append(obj.uuid)
            if obj_type == 'bank-account':
                try:
                    report_code.append(obj.get_attributes_by_relation('report-code'))
                    currency_code.append(obj.get_attributes_by_relation('currency-code'))
                except:
                    print('non')
        self.uuids, self.report_code, self.currency_code = uuids, report_code, currency_code

    def build_xml(self):
        self.xml = "<report><rentity_id>{}</rentity_id>".format(self.config)
        for trans_uuid in self.uuids.get('transaction'):
            self.itterate('transaction', 'transaction', trans_uuid)
        self.xml += "</report>"

    def itterate(self, object_type, aml_type, uuid):
        self.xml += "<{}>".format(aml_type)
        obj = self.misp_event.get_object_by_uuid(uuid)
        self.fill_xml(obj)
        if obj.ObjectReference:
            for ref in obj.ObjectReference:
                uuid = ref.referenced_uuid
                next_object_type = ref.Object.get('name')
                relationship_type = ref.relationship_type
                self.parse_references(object_type, next_object_type, uuid, relationship_type)
        self.xml += "</{}>".format(aml_type)

    def fill_xml(self, obj):
        for attribute in obj.attributes:
            if obj.name == 'bank-account' and attribute.type in ('personal-account-type', 'status-code'):
                attribute_value = attribute.value.split(' - ')[0]
            else:
                attribute_value = attribute.value
            try:
                self.xml += "<{0}>{1}</{0}>".format(goAMLmapping[attribute.object_relation], attribute_value)
            except KeyError:
                pass

    def parse_references(self, object_type, next_object_type, uuid, relationship_type):
        if next_object_type == 'bank-account':
            self.xml += "<t_{}>".format(relationship_type)
            next_aml_type = "{}_account".format(relationship_type.split('_')[0])
            self.itterate(next_object_type, next_aml_type, uuid)
            self.xml += "</t_{}>".format(relationship_type)
        elif next_object_type == 'person':
            if object_type == 'transaction':
                self.xml += "<t_{}>".format(relationship_type)
                next_aml_type = "{}_person".format(relationship_type.split('_')[0])
                self.itterate(next_object_type, next_aml_type, uuid)
                self.xml += "</t_{}>".format(relationship_type)
            elif object_type == 'bank-account':
                self.xml += "<signatory>"
                next_aml_type = goAMLmapping[next_object_type]
                self.itterate(next_object_type, next_aml_type, uuid)
                self.xml += "</signatory>"
        elif next_object_type == 'legal-entity':
            if object_type == 'transaction':
                self.xml += "<t_{}>".format(relationship_type)
                next_aml_type = "{}_entity".format(relationship_type.split('_')[0])
                self.itterate(next_object_type, next_aml_type, uuid)
                self.xml += "</t_{}>".format(relationship_type)
            elif object_type == 'bank-account':
                next_aml_type = goAMLmapping[next_object_type]
                self.itterate(next_object_type, next_aml_type, uuid)

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if 'data' not in request:
        return False
    if not request.get('config') and not request['config'].get('rentity_id'):
        misperrors['error'] = "Configuration error."
        return misperrors
    config = request['config'].get('rentity_id')
    exp_doc = GoAmlGeneration(config)
    exp_doc.from_event(request['data'][0])
    exp_doc.parse_objects()
    exp_doc.build_xml()
    return {'response': [], 'data': str(base64.b64encode(bytes(exp_doc.xml, 'utf-8')), 'utf-8')}

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
