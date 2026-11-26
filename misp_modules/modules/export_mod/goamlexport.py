import base64
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

from pymisp import MISPEvent

misperrors = {"error": "Error"}
moduleinfo = {
    "version": "2",
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
        "\n\nReport metadata is configured with rentity_id (required FIU-assigned reporting entity ID),"
        " submission_code (default E), submission_date (default current UTC time), report_code, and"
        " currency_code_local. An explicit report_code overrides bank-account report-code attributes; otherwise"
        " STR takes precedence, then the most frequent code (first encountered on a tie). Configure"
        " currency_code_local explicitly; the legacy fallback requires exactly one distinct account currency."
        " Transaction amounts must already be in the report's local currency; no conversion is performed."
        " See documentation/export_mod/goamlexport.md for configuration examples and migration notes."
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
moduleconfig = ["rentity_id", "submission_code", "submission_date", "currency_code_local", "report_code"]
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
        if not isinstance(config, dict):
            raise ValueError("Configuration error: rentity_id is required.")
        self.config = {}
        for key in moduleconfig:
            value = config.get(key)
            if value is None or value == "":
                continue
            if key == "rentity_id" and type(value) is int:
                value = str(value)
            if not isinstance(value, str):
                raise ValueError(f"Configuration error: {key} must be a string.")
            if value.strip():
                self.config[key] = value.strip()
        rentity_id = self.config.get("rentity_id", "")
        if not re.fullmatch(r"[0-9]+", rentity_id) or not int(rentity_id):
            raise ValueError("Configuration error: rentity_id must be a positive integer assigned by the FIU.")
        for key in ("submission_code", "report_code"):
            if key in self.config and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", self.config[key]):
                raise ValueError(f"Configuration error: {key} must contain a code, without its description.")
        if "currency_code_local" in self.config:
            self.config["currency_code_local"] = self.currency_code(self.config["currency_code_local"])
        if "submission_date" in self.config:
            value = self.config["submission_date"]
            if not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-5][0-9])?",
                value,
            ):
                raise ValueError("Configuration error: submission_date must be an ISO 8601 date-time.")
            try:
                date = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if date.utcoffset() is not None and abs(date.utcoffset()) > timedelta(hours=14):
                    raise ValueError
            except ValueError:
                raise ValueError("Configuration error: submission_date must be a valid ISO 8601 date-time.") from None
            self.config["submission_date"] = date.isoformat()
        self.parsed_uuids = defaultdict(list)

    @staticmethod
    def currency_code(value):
        value = str(value).strip().upper()
        if not re.fullmatch(r"[A-Z]{3}", value):
            raise ValueError("Configuration error: currency_code_local must be a three-letter currency code.")
        return value

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
                for attribute in obj.get_attributes_by_relation("report-code"):
                    parts = str(attribute.value).split()
                    if parts:
                        report_code.append(parts[0])
                for attribute in obj.get_attributes_by_relation("currency-code"):
                    if str(attribute.value).strip():
                        currency_code.append(str(attribute.value))
        self.uuids, self.report_codes, self.currency_codes = (
            uuids,
            report_code,
            currency_code,
        )

    def build_xml(self):
        if "report_code" in self.config:
            report_code = self.config["report_code"]
        elif "STR" in self.report_codes:
            report_code = "STR"
        elif self.report_codes:
            report_code = Counter(self.report_codes).most_common(1)[0][0]
        else:
            raise ValueError("Report metadata error: configure report_code or supply a bank-account report-code.")
        currency = self.config.get("currency_code_local")
        if currency is None:
            currencies = {self.currency_code(value) for value in self.currency_codes}
            if len(currencies) != 1:
                raise ValueError(
                    "Report metadata error: configure currency_code_local; account currencies are missing or ambiguous."
                )
            currency = currencies.pop()
        header = (
            ("rentity_id", self.config["rentity_id"]),
            ("submission_code", self.config.get("submission_code", "E")),
            ("report_code", report_code),
            (
                "submission_date",
                self.config.get("submission_date") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ),
            ("currency_code_local", currency),
        )
        self.xml = {
            "header": "<report>" + "".join(f"<{key}>{escape(value)}</{key}>" for key, value in header),
            "data": "",
        }
        for trans_uuid in self.uuids.get("transaction"):
            self.itterate("transaction", "transaction", trans_uuid, "data")
        person_to_parse = [
            person_uuid
            for person_uuid in self.uuids.get("person", [])
            if person_uuid not in self.parsed_uuids.get("person", [])
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
    try:
        export_doc = GoAmlGeneration(request.get("config"))
    except ValueError as error:
        return {"error": str(error)}
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
    try:
        export_doc.build_xml()
    except ValueError as error:
        return {"error": str(error)}
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
        modulesetup["inputSource"] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
