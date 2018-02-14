import json, datetime, base64
from pymisp import MISPEvent
from collections import defaultdict, Counter

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
                'transmode-comment': 'transmode_comment', 'date-posting': 'date_posting', 'teller': 'teller',
                'authorized': 'authorized',
                'legal-entity': 'entity', 'name': 'name', 'commercial-name': 'commercial_name', 'business': 'business',
                'legal-form': 'incorporation_legal_form', 'registration-number': 'incorporation_number',
                'phone-number': 'phone'}

referencesMapping = {'bank-account': {'aml_type': '{}_account', 'bracket': 't_{}'},
                     'person': {'transaction': {'aml_type': '{}_person', 'bracket': 't_{}'}, 'bank-account': {'aml_type': 't_person', 'bracket': 'signatory'}},
                     'legal-entity': {'transaction': {'aml_type': '{}_entity', 'bracket': 't_{}'}, 'bank-account': {'aml_type': 'entity'}},
                     'geolocation': {'aml_type': 'address', 'bracket': 'addresses'}}

class GoAmlGeneration(object):
    def __init__(self, config):
        self.config = config
        self.parsed_uuids = defaultdict(list)

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
                    report_code.append(obj.get_attributes_by_relation('report-code')[0].value.split(' ')[0])
                    currency_code.append(obj.get_attributes_by_relation('currency-code')[0].value)
                except:
                    print('report_code or currency_code error')
        self.uuids, self.report_codes, self.currency_codes = uuids, report_code, currency_code

    def build_xml(self):
        self.xml = {'header': "<report><rentity_id>{}</rentity_id><submission_code>E</submission_code>".format(self.config),
                    'data': ""}
        if "STR" in self.report_codes:
            report_code = "STR"
        else:
            report_code = Counter(self.report_codes).most_common(1)[0][0]
        self.xml['header'] += "<report_code>{}</report_code>".format(report_code)
        submission_date = str(self.misp_event.timestamp).replace(' ', 'T')
        self.xml['header'] += "<submission_date>{}</submission_date>".format(submission_date)
        self.xml['header'] += "<currency_code_local>{}</currency_code_local>".format(Counter(self.currency_codes).most_common(1)[0][0])
        for trans_uuid in self.uuids.get('transaction'):
            self.itterate('transaction', 'transaction', trans_uuid, 'data')
        person_to_parse = [person_uuid for person_uuid in self.uuids.get('person') if person_uuid not in self.parsed_uuids.get('person')]
        if len(person_to_parse) == 1:
            self.itterate('person', 'reporting_person', person_to_parse[0], 'header')
        location_to_parse = [location_uuid for location_uuid in self.uuids.get('geolocation') if location_uuid not in self.parsed_uuids.get('geolocation')]
        if len(location_to_parse) == 1:
            self.itterate('geolocation', 'location', location_to_parse[0], 'header')
        self.xml['data'] += "</report>"

    def itterate(self, object_type, aml_type, uuid, xml_part):
        self.xml[xml_part] += "<{}>".format(aml_type)
        obj = self.misp_event.get_object_by_uuid(uuid)
        self.fill_xml(obj, xml_part)
        self.parsed_uuids[object_type].append(uuid)
        if obj.ObjectReference:
            for ref in obj.ObjectReference:
                uuid = ref.referenced_uuid
                next_object_type = ref.Object.get('name')
                relationship_type = ref.relationship_type
                self.parse_references(object_type, next_object_type, uuid, relationship_type, xml_part)
        self.xml[xml_part] += "</{}>".format(aml_type)

    def fill_xml(self, obj, xml_part):
        for attribute in obj.attributes:
            if obj.name == 'bank-account' and attribute.object_relation in ('personal-account-type', 'status-code'):
                attribute_value = attribute.value.split(' - ')[0]
            else:
                attribute_value = attribute.value
            if obj.name == 'transaction' and attribute.object_relation == 'date-posting':
                self.xml[xml_part] += "<late_deposit>True</late_deposit>"
            try:
                self.xml[xml_part] += "<{0}>{1}</{0}>".format(goAMLmapping[attribute.object_relation], attribute_value)
            except KeyError:
                pass

    def parse_references(self, object_type, next_object_type, uuid, relationship_type, xml_part):
        reference = referencesMapping[next_object_type]
        try:
            next_aml_type = reference[object_type].get('aml_type').format(relationship_type.split('_')[0])
            try:
                bracket = reference[object_type].get('bracket').format(relationship_type)
                self.xml[xml_part] += "<{}>".format(bracket)
                self.itterate(next_object_type, next_aml_type, uuid, xml_part)
                self.xml[xml_part] += "</{}>".format(bracket)
            except KeyError:
                self.itterate(next_object_type, next_aml_type, uuid, xml_part)
        except KeyError:
            next_aml_type = reference.get('aml_type').format(relationship_type.split('_')[0])
            bracket = reference.get('bracket').format(relationship_type)
            self.xml[xml_part] += "<{}>".format(bracket)
            self.itterate(next_object_type, next_aml_type, uuid, xml_part)
            self.xml[xml_part] += "</{}>".format(bracket)

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
    export_doc = GoAmlGeneration(config)
    export_doc.from_event(request['data'][0])
    export_doc.parse_objects()
    export_doc.build_xml()
    exp_doc = "{}{}".format(export_doc.xml.get('header'), export_doc.xml.get('data'))
    return {'response': [], 'data': str(base64.b64encode(bytes(exp_doc, 'utf-8')), 'utf-8')}

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
