import base64
import json
import time
import xml.etree.ElementTree as ET

from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
moduleinfo = {
    "version": 1,
    "author": "Christian Studer",
    "description": "Module to import MISP objects about financial transactions from GoAML files.",
    "module-type": ["import"],
    "name": "GoAML Import",
    "logo": "goAML.jpg",
    "requirements": ["PyMISP"],
    "features": (
        "Unlike the GoAML export module, there is here no special feature to import data from GoAML external files,"
        " since the module will import MISP Objects with their References on its own, as it is required for the export"
        " module to rebuild a valid GoAML document."
    ),
    "references": "http://goaml.unodc.org/",
    "input": (
        "GoAML format file, describing financial transactions, with their origin and target (bank accounts, persons or"
        " entities)."
    ),
    "output": (
        "MISP objects (transaction, bank-account, person, legal-entity, geolocation), with references, describing"
        " financial transactions and their origin and target."
    ),
}
moduleconfig = []
mispattributes = {
    "inputSource": ["file"],
    "output": ["MISP objects"],
    "format": "misp_standard",
}

t_from_objects = {
    "nodes": ["from_person", "from_account", "from_entity"],
    "leaves": ["from_funds_code", "from_country"],
}
t_to_objects = {
    "nodes": ["to_person", "to_account", "to_entity"],
    "leaves": ["to_funds_code", "to_country"],
}
t_person_objects = {
    "nodes": ["addresses"],
    "leaves": [
        "first_name",
        "middle_name",
        "last_name",
        "gender",
        "title",
        "mothers_name",
        "birthdate",
        "passport_number",
        "passport_country",
        "id_number",
        "birth_place",
        "alias",
        "nationality1",
    ],
}
t_account_objects = {
    "nodes": ["signatory"],
    "leaves": [
        "institution_name",
        "institution_code",
        "swift",
        "branch",
        "non_banking_insitution",
        "account",
        "currency_code",
        "account_name",
        "iban",
        "client_number",
        "opened",
        "closed",
        "personal_account_type",
        "balance",
        "date_balance",
        "status_code",
        "beneficiary",
        "beneficiary_comment",
        "comments",
    ],
}
entity_objects = {
    "nodes": ["addresses"],
    "leaves": [
        "name",
        "commercial_name",
        "incorporation_legal_form",
        "incorporation_number",
        "business",
        "phone",
    ],
}

goAMLobjects = {
    "report": {
        "nodes": ["reporting_person", "location"],
        "leaves": [
            "rentity_id",
            "submission_code",
            "report_code",
            "submission_date",
            "currency_code_local",
        ],
    },
    "reporting_person": {
        "nodes": ["addresses"],
        "leaves": ["first_name", "middle_name", "last_name", "title"],
    },
    "location": {
        "nodes": [],
        "leaves": ["address_type", "address", "city", "zip", "country_code", "state"],
    },
    "transaction": {
        "nodes": ["t_from", "t_from_my_client", "t_to", "t_to_my_client"],
        "leaves": [
            "transactionnumber",
            "transaction_location",
            "date_transaction",
            "transmode_code",
            "amount_local",
        ],
    },
    "t_from": t_from_objects,
    "t_from_my_client": t_from_objects,
    "t_to": t_to_objects,
    "t_to_my_client": t_to_objects,
    "addresses": {"nodes": ["address"], "leaves": []},
    "address": {
        "nodes": [],
        "leaves": ["address_type", "address", "city", "zip", "country_code", "state"],
    },
    "from_person": t_person_objects,
    "to_person": t_person_objects,
    "t_person": t_person_objects,
    "from_account": t_account_objects,
    "to_account": t_account_objects,
    "signatory": {"nodes": ["t_person"], "leaves": []},
    "from_entity": entity_objects,
    "to_entity": entity_objects,
}

t_account_mapping = {
    "misp_name": "bank-account",
    "institution_name": "institution-name",
    "institution_code": "institution-code",
    "iban": "iban",
    "swift": "swift",
    "branch": "branch",
    "non_banking_institution": "non-bank-institution",
    "account": "account",
    "currency_code": "currency-code",
    "account_name": "account-name",
    "client_number": "client-number",
    "personal_account_type": "personal-account-type",
    "opened": "opened",
    "closed": "closed",
    "balance": "balance",
    "status_code": "status-code",
    "beneficiary": "beneficiary",
    "beneficiary_comment": "beneficiary-comment",
    "comments": "comments",
}

t_person_mapping = {
    "misp_name": "person",
    "comments": "text",
    "first_name": "first-name",
    "middle_name": "middle-name",
    "last_name": "last-name",
    "title": "title",
    "mothers_name": "mothers-name",
    "alias": "alias",
    "birthdate": "date-of-birth",
    "birth_place": "place-of-birth",
    "gender": "gender",
    "nationality1": "nationality",
    "passport_number": "passport-number",
    "passport_country": "passport-country",
    "ssn": "social-security-number",
    "id_number": "identity-card-number",
}

location_mapping = {
    "misp_name": "geolocation",
    "city": "city",
    "state": "region",
    "country_code": "country",
    "address": "address",
    "zip": "zipcode",
}

t_entity_mapping = {
    "misp_name": "legal-entity",
    "name": "name",
    "business": "business",
    "commercial_name": "commercial-name",
    "phone": "phone-number",
    "incorporation_legal_form": "legal-form",
    "incorporation_number": "registration-number",
}

goAMLmapping = {
    "from_account": t_account_mapping,
    "to_account": t_account_mapping,
    "t_person": t_person_mapping,
    "from_person": t_person_mapping,
    "to_person": t_person_mapping,
    "reporting_person": t_person_mapping,
    "from_entity": t_entity_mapping,
    "to_entity": t_entity_mapping,
    "location": location_mapping,
    "address": location_mapping,
    "transaction": {
        "misp_name": "transaction",
        "transactionnumber": "transaction-number",
        "date_transaction": "date",
        "transaction_location": "location",
        "transmode_code": "transmode-code",
        "amount_local": "amount",
        "transmode_comment": "transmode-comment",
        "date_posting": "date-posting",
        "teller": "teller",
        "authorized": "authorized",
        "transaction_description": "text",
    },
}

nodes_to_ignore = ["addresses", "signatory"]
relationship_to_keep = [
    "signatory",
    "t_from",
    "t_from_my_client",
    "t_to",
    "t_to_my_client",
    "address",
]


class GoAmlParser:
    def __init__(self):
        self.misp_event = MISPEvent()

    def read_xml(self, data):
        self.tree = ET.fromstring(data)

    def parse_xml(self):
        self.first_itteration()
        for t in self.tree.findall("transaction"):
            self.itterate(t, "transaction")

    def first_itteration(self):
        submission_date = self.tree.find("submission_date").text.split("+")[0]
        self.misp_event.timestamp = int(time.mktime(time.strptime(submission_date, "%Y-%m-%dT%H:%M:%S")))
        for node in goAMLobjects["report"]["nodes"]:
            element = self.tree.find(node)
            if element is not None:
                self.itterate(element, element.tag)

    def itterate(self, tree, aml_type, referencing_uuid=None, relationship_type=None):
        objects = goAMLobjects[aml_type]
        referenced_uuid = referencing_uuid
        rel = relationship_type
        if aml_type not in nodes_to_ignore:
            try:
                mapping = goAMLmapping[aml_type]
                misp_object = MISPObject(name=mapping["misp_name"])
                for leaf in objects["leaves"]:
                    element = tree.find(leaf)
                    if element is not None:
                        object_relation = mapping[element.tag]
                        attribute = {
                            "object_relation": object_relation,
                            "value": element.text,
                        }
                        misp_object.add_attribute(**attribute)
                if aml_type == "transaction":
                    for node in objects["nodes"]:
                        element = tree.find(node)
                        if element is not None:
                            self.fill_transaction(element, element.tag, misp_object)
                self.misp_event.add_object(misp_object)
                last_object = self.misp_event.objects[-1]
                referenced_uuid = last_object.uuid
                if referencing_uuid and relationship_type:
                    referencing_object = self.misp_event.get_object_by_uuid(referencing_uuid)
                    referencing_object.add_reference(referenced_uuid, rel, None, **last_object)
            except KeyError:
                pass
        for node in objects["nodes"]:
            element = tree.find(node)
            if element is not None:
                tag = element.tag
                if tag in relationship_to_keep:
                    rel = tag[2:] if tag.startswith("t_") else tag
                self.itterate(
                    element,
                    element.tag,
                    referencing_uuid=referenced_uuid,
                    relationship_type=rel,
                )

    @staticmethod
    def fill_transaction(element, tag, misp_object):
        if "t_from" in tag:
            from_funds = element.find("from_funds_code").text
            from_funds_attribute = {
                "object_relation": "from-funds-code",
                "value": from_funds,
            }
            misp_object.add_attribute(**from_funds_attribute)
            from_country = element.find("from_country").text
            from_country_attribute = {
                "object_relation": "from-country",
                "value": from_country,
            }
            misp_object.add_attribute(**from_country_attribute)
        if "t_to" in tag:
            to_funds = element.find("to_funds_code").text
            to_funds_attribute = {"object_relation": "to-funds-code", "value": to_funds}
            misp_object.add_attribute(**to_funds_attribute)
            to_country = element.find("to_country").text
            to_country_attribute = {
                "object_relation": "to-country",
                "value": to_country,
            }
            misp_object.add_attribute(**to_country_attribute)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get("data"):
        data = base64.b64decode(request["data"]).decode("utf-8")
    else:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors
    aml_parser = GoAmlParser()
    try:
        aml_parser.read_xml(data)
    except Exception:
        misperrors["error"] = "Impossible to read XML data"
        return misperrors
    aml_parser.parse_xml()
    r = {"results": {"Object": [obj.to_json() for obj in aml_parser.misp_event.objects]}}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
