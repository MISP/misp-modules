import base64
import json
from collections import Counter, defaultdict

from pymisp import MISPEvent

misperrors = {"error": "Error"}
moduleinfo = {
    "version": "1",
    "author": "Christian Studer",
    "description": "This module is used to export MISP events containing transaction objects into GoAML format.",
    "module-type": ["export"],
    "name": "GoAML Export",
    "require_standard_format": True,
    "logo": "goAML.jpg",
    "requirements": ["PyMISP", "MISP objects"],
    "features": (
        "The module works as long as there is at least one transaction object in the Event.\n\nThen in order to have a"
        " valid GoAML document, please follow these guidelines:\n- For each transaction object, use either a"
        " bank-account, person, or legal-entity object to describe the origin of the transaction, and again one of them"
        " to describe the target of the transaction.\n- Create an object reference for both origin and target objects"
        " of the transaction.\n- A bank-account object needs a signatory, which is a person object, put as object"
        " reference of the bank-account.\n- A person can have an address, which is a geolocation object, put as object"
        " reference of the person.\n\nSupported relation types for object references that are recommended for each"
        " object are the folowing:\n- transaction:\n\t- 'from', 'from_my_client': Origin of the transaction - at least"
        " one of them is required.\n\t- 'to', 'to_my_client': Target of the transaction - at least one of them is"
        " required.\n\t- 'address': Location of the transaction - optional.\n- bank-account:\n\t- 'signatory':"
        " Signatory of a bank-account - the reference from bank-account to a signatory is required, but the"
        " relation-type is optional at the moment since this reference will always describe a signatory.\n\t- 'entity':"
        " Entity owning the bank account - optional.\n- person:\n\t- 'address': Address of a person - optional."
    ),
    "references": ["http://goaml.unodc.org/"],
    "input": (
        "MISP objects (transaction, bank-account, person, legal-entity, geolocation), with references, describing"
        " financial transactions and their origin and target."
    ),
    "output": (
        "GoAML format file, describing financial transactions, with their origin and target (bank accounts, persons or"
        " entities)."
    ),
}
moduleconfig = ["rentity_id"]
mispattributes = {"input": ["MISPEvent"], "output": ["xml file"]}
outputFileExtension = "xml"
responseType = "application/xml"

objects_to_parse = ["transaction", "bank-account", "person", "entity", "geolocation"]

goAMLmapping = {
    "bank-account": {
        "bank-account": "t_account",
        "institution-name": "institution_name",
        "institution-code": "institution_code",
        "iban": "iban",
        "swift": "swift",
        "branch": "branch",
        "non-banking-institution": "non_bank_institution",
        "account": "account",
        "currency-code": "currency_code",
        "account-name": "account_name",
        "client-number": "client_number",
        "personal-account-type": "personal_account_type",
        "opened": "opened",
        "closed": "closed",
        "balance": "balance",
        "status-code": "status_code",
        "beneficiary": "beneficiary",
        "beneficiary-comment": "beneficiary_comment",
        "comments": "comments",
    },
    "person": {
        "person": "t_person",
        "text": "comments",
        "first-name": "first_name",
        "middle-name": "middle_name",
        "last-name": "last_name",
        "title": "title",
        "mothers-name": "mothers_name",
        "alias": "alias",
        "date-of-birth": "birthdate",
        "place-of-birth": "birth_place",
        "gender": "gender",
        "nationality": "nationality1",
        "passport-number": "passport_number",
        "passport-country": "passport_country",
        "social-security-number": "ssn",
        "identity-card-number": "id_number",
    },
    "geolocation": {
        "geolocation": "location",
        "city": "city",
        "region": "state",
        "country": "country_code",
        "address": "address",
        "zipcode": "zip",
    },
    "transaction": {
        "transaction": "transaction",
        "transaction-number": "transactionnumber",
        "date": "date_transaction",
        "location": "transaction_location",
        "transmode-code": "transmode_code",
        "amount": "amount_local",
        "transmode-comment": "transmode_comment",
        "date-posting": "date_posting",
        "teller": "teller",
        "authorized": "authorized",
        "text": "transaction_description",
    },
    "legal-entity": {
        "legal-entity": "entity",
        "name": "name",
        "business": "business",
        "commercial-name": "commercial_name",
        "phone-number": "phone",
        "legal-form": "incorporation_legal_form",
        "registration-number": "incorporation_number",
    },
}

referencesMapping = {
    "bank-account": {"aml_type": "{}_account", "bracket": "t_{}"},
    "person": {
        "transaction": {"aml_type": "{}_person", "bracket": "t_{}"},
        "bank-account": {"aml_type": "t_person", "bracket": "signatory"},
    },
    "legal-entity": {
        "transaction": {"aml_type": "{}_entity", "bracket": "t_{}"},
        "bank-account": {"aml_type": "t_entity"},
    },
    "geolocation": {"aml_type": "address", "bracket": "addresses"},
}


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
            if obj_type == "bank-account":
                try:
                    report_code.append(obj.get_attributes_by_relation("report-code")[0].value.split(" ")[0])
                    currency_code.append(obj.get_attributes_by_relation("currency-code")[0].value)
                except IndexError:
                    print("report_code or currency_code error")
        self.uuids, self.report_codes, self.currency_codes = (
            uuids,
            report_code,
            currency_code,
        )

    def build_xml(self):
        self.xml = {
            "header": "<report><rentity_id>{}</rentity_id><submission_code>E</submission_code>".format(self.config),
            "data": "",
        }
        if "STR" in self.report_codes:
            report_code = "STR"
        else:
            report_code = Counter(self.report_codes).most_common(1)[0][0]
        self.xml["header"] += "<report_code>{}</report_code>".format(report_code)
        submission_date = str(self.misp_event.timestamp).replace(" ", "T")
        self.xml["header"] += "<submission_date>{}</submission_date>".format(submission_date)
        self.xml["header"] += "<currency_code_local>{}</currency_code_local>".format(
            Counter(self.currency_codes).most_common(1)[0][0]
        )
        for trans_uuid in self.uuids.get("transaction"):
            self.itterate("transaction", "transaction", trans_uuid, "data")
        person_to_parse = [
            person_uuid
            for person_uuid in self.uuids.get("person")
            if person_uuid not in self.parsed_uuids.get("person")
        ]
        if len(person_to_parse) == 1:
            self.itterate("person", "reporting_person", person_to_parse[0], "header")
        try:
            location_to_parse = [
                location_uuid
                for location_uuid in self.uuids.get("geolocation")
                if location_uuid not in self.parsed_uuids.get("geolocation")
            ]
            if len(location_to_parse) == 1:
                self.itterate("geolocation", "location", location_to_parse[0], "header")
        except TypeError:
            pass
        self.xml["data"] += "</report>"

    def itterate(self, object_type, aml_type, uuid, xml_part):
        obj = self.misp_event.get_object_by_uuid(uuid)
        if object_type == "transaction":
            self.xml[xml_part] += "<{}>".format(aml_type)
            self.fill_xml_transaction(object_type, obj.attributes, xml_part)
            self.parsed_uuids[object_type].append(uuid)
            if obj.ObjectReference:
                self.parseObjectReferences(object_type, xml_part, obj.ObjectReference)
            self.xml[xml_part] += "</{}>".format(aml_type)
        else:
            if "to_" in aml_type or "from_" in aml_type:
                relation_type = aml_type.split("_")[0]
                self.xml[xml_part] += "<{0}_funds_code>{1}</{0}_funds_code>".format(
                    relation_type,
                    self.from_and_to_fields[relation_type]["funds"].split(" ")[0],
                )
                self.itterate_normal_case(object_type, obj, aml_type, uuid, xml_part)
                self.xml[xml_part] += "<{0}_country>{1}</{0}_country>".format(
                    relation_type, self.from_and_to_fields[relation_type]["country"]
                )
            else:
                self.itterate_normal_case(object_type, obj, aml_type, uuid, xml_part)

    def itterate_normal_case(self, object_type, obj, aml_type, uuid, xml_part):
        self.xml[xml_part] += "<{}>".format(aml_type)
        self.fill_xml(object_type, obj, xml_part)
        self.parsed_uuids[object_type].append(uuid)
        if obj.ObjectReference:
            self.parseObjectReferences(object_type, xml_part, obj.ObjectReference)
        self.xml[xml_part] += "</{}>".format(aml_type)

    def parseObjectReferences(self, object_type, xml_part, references):
        for ref in references:
            next_uuid = ref.referenced_uuid
            next_object_type = ref.Object.get("name")
            relationship_type = ref.relationship_type
            self.parse_references(object_type, next_object_type, next_uuid, relationship_type, xml_part)

    def fill_xml_transaction(self, object_type, attributes, xml_part):
        from_and_to_fields = {"from": {}, "to": {}}
        for attribute in attributes:
            object_relation = attribute.object_relation
            attribute_value = attribute.value
            if object_relation == "date-posting":
                self.xml[xml_part] += "<late_deposit>True</late_deposit>"
            elif object_relation in ("from-funds-code", "to-funds-code"):
                relation_type, field, _ = object_relation.split("-")
                from_and_to_fields[relation_type][field] = attribute_value
                continue
            elif object_relation in ("from-country", "to-country"):
                relation_type, field = object_relation.split("-")
                from_and_to_fields[relation_type][field] = attribute_value
                continue
            try:
                self.xml[xml_part] += "<{0}>{1}</{0}>".format(
                    goAMLmapping[object_type][object_relation], attribute_value
                )
            except KeyError:
                pass
        self.from_and_to_fields = from_and_to_fields

    def fill_xml(self, object_type, obj, xml_part):
        if obj.name == "bank-account":
            for attribute in obj.attributes:
                if attribute.object_relation in (
                    "personal-account-type",
                    "status-code",
                ):
                    attribute_value = attribute.value.split(" - ")[0]
                else:
                    attribute_value = attribute.value
                try:
                    self.xml[xml_part] += "<{0}>{1}</{0}>".format(
                        goAMLmapping[object_type][attribute.object_relation],
                        attribute_value,
                    )
                except KeyError:
                    pass
        else:
            for attribute in obj.attributes:
                try:
                    self.xml[xml_part] += "<{0}>{1}</{0}>".format(
                        goAMLmapping[object_type][attribute.object_relation],
                        attribute.value,
                    )
                except KeyError:
                    pass

    def parse_references(self, object_type, next_object_type, uuid, relationship_type, xml_part):
        reference = referencesMapping[next_object_type]
        try:
            next_aml_type = reference[object_type].get("aml_type").format(relationship_type.split("_")[0])
            try:
                bracket = reference[object_type].get("bracket").format(relationship_type)
                self.xml[xml_part] += "<{}>".format(bracket)
                self.itterate(next_object_type, next_aml_type, uuid, xml_part)
                self.xml[xml_part] += "</{}>".format(bracket)
            except KeyError:
                self.itterate(next_object_type, next_aml_type, uuid, xml_part)
        except KeyError:
            next_aml_type = reference.get("aml_type").format(relationship_type.split("_")[0])
            bracket = reference.get("bracket").format(relationship_type)
            self.xml[xml_part] += "<{}>".format(bracket)
            self.itterate(next_object_type, next_aml_type, uuid, xml_part)
            self.xml[xml_part] += "</{}>".format(bracket)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if "data" not in request:
        return False
    if not request.get("config") and not request["config"].get("rentity_id"):
        misperrors["error"] = "Configuration error."
        return misperrors
    config = request["config"].get("rentity_id")
    export_doc = GoAmlGeneration(config)
    export_doc.from_event(request["data"][0])
    if not export_doc.misp_event.Object:
        misperrors["error"] = "There is no object in this event."
        return misperrors
    types = []
    for obj in export_doc.misp_event.Object:
        types.append(obj.name)
    if "transaction" not in types:
        misperrors["error"] = "There is no transaction object in this event."
        return misperrors
    export_doc.parse_objects()
    export_doc.build_xml()
    exp_doc = "{}{}".format(export_doc.xml.get("header"), export_doc.xml.get("data"))
    return {
        "response": [],
        "data": str(base64.b64encode(bytes(exp_doc, "utf-8")), "utf-8"),
    }


def introspection():
    modulesetup = {}
    try:
        responseType
        modulesetup["responseType"] = responseType
    except NameError:
        pass
    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    try:
        outputFileExtension
        modulesetup["outputFileExtension"] = outputFileExtension
    except NameError:
        pass
    try:
        inputSource
        moduleSetup["inputSource"] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
