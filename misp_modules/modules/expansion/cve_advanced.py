import json
from collections import defaultdict

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["vulnerability"], "format": "misp_standard"}
moduleinfo = {
    "version": "2",
    "author": "Christian Studer",
    "description": (
        "An expansion module to query the CIRCL CVE search API for more information about a vulnerability (CVE)."
    ),
    "module-type": ["expansion", "hover"],
    "name": "CVE Advanced Lookup",
    "logo": "cve.png",
    "requirements": [],
    "features": (
        "The module takes a vulnerability attribute as input and queries the CIRCL CVE search API to gather additional"
        " information.\n\nThe result of the query is then parsed to return additional information about the"
        " vulnerability, like its cvss score or some references, as well as the potential related weaknesses and attack"
        " patterns.\n\nThe vulnerability additional data is returned in a vulnerability MISP object, and the related"
        " additional information are put into weakness and attack-pattern MISP objects."
    ),
    "references": ["https://vulnerability.circl.lu", "https://cve/mitre.org/"],
    "input": "Vulnerability attribute.",
    "output": (
        "Additional information about the vulnerability, such as its cvss score, some references, or the related"
        " weaknesses and attack patterns."
    ),
}
moduleconfig = ["custom_API"]
cveapi_url = "https://cvepremium.circl.lu/api/"


class VulnerabilityParser:
    def __init__(self, attribute, api_url):
        misp_attribute = MISPAttribute()
        misp_attribute.from_dict(**attribute)
        misp_event = MISPEvent()
        misp_event.add_attribute(**misp_attribute)
        self.__misp_attribute = misp_attribute
        self.__misp_event = misp_event
        self.__api_url = api_url
        self.references = defaultdict(list)
        self.__capec_features = ("id", "name", "summary", "prerequisites", "solutions")
        self.__vulnerability_mapping = {
            "id": "id",
            "summary": "summary",
            "Modified": "modified",
            "cvss3": "cvss-score",
            "cvss3-vector": "cvss-string",
        }
        self.__vulnerability_multiple_mapping = {
            "vulnerable_configuration": "vulnerable-configuration",
            "vulnerable_configuration_cpe_2_2": "vulnerable-configuration",
            "references": "references",
        }
        self.__weakness_mapping = {
            "name": "name",
            "description_summary": "description",
            "status": "status",
            "weaknessabs": "weakness-abs",
        }

    @property
    def api_url(self) -> str:
        return self.__api_url

    @property
    def capec_features(self) -> tuple:
        return self.__capec_features

    @property
    def misp_attribute(self) -> MISPAttribute:
        return self.__misp_attribute

    @property
    def misp_event(self) -> MISPEvent:
        return self.__misp_event

    @property
    def vulnerability_mapping(self) -> dict:
        return self.__vulnerability_mapping

    @property
    def vulnerability_multiple_mapping(self) -> dict:
        return self.__vulnerability_multiple_mapping

    @property
    def weakness_mapping(self) -> dict:
        return self.__weakness_mapping

    def get_result(self):
        if self.references:
            self.__build_references()
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": results}

    def parse_vulnerability_information(self, vulnerability):
        vulnerability_object = MISPObject("vulnerability")
        for feature, relation in self.vulnerability_mapping.items():
            if vulnerability.get(feature):
                vulnerability_object.add_attribute(relation, vulnerability[feature])
        if "Published" in vulnerability:
            vulnerability_object.add_attribute("published", vulnerability["Published"])
            vulnerability_object.add_attribute("state", "Published")
        for feature, relation in self.vulnerability_multiple_mapping.items():
            if feature in vulnerability:
                for value in vulnerability[feature]:
                    if isinstance(value, dict):
                        value = value["title"]
                    vulnerability_object.add_attribute(relation, value)
        vulnerability_object.add_reference(self.misp_attribute.uuid, "related-to")
        self.misp_event.add_object(vulnerability_object)
        if "cwe" in vulnerability and vulnerability["cwe"] not in (
            "Unknown",
            "NVD-CWE-noinfo",
        ):
            self.__parse_weakness(vulnerability["cwe"], vulnerability_object.uuid)
        if "capec" in vulnerability:
            self.__parse_capec(vulnerability["capec"], vulnerability_object.uuid)

    def __build_references(self):
        for object_uuid, references in self.references.items():
            for misp_object in self.misp_event.objects:
                if misp_object.uuid == object_uuid:
                    for reference in references:
                        misp_object.add_reference(**reference)
                    break

    def __parse_capec(self, capec_values, vulnerability_uuid):
        for capec in capec_values:
            capec_object = MISPObject("attack-pattern")
            for feature in self.capec_features:
                capec_object.add_attribute(feature, capec[feature])
            for related_weakness in capec["related_weakness"]:
                capec_object.add_attribute("related-weakness", f"CWE-{related_weakness}")
            self.misp_event.add_object(capec_object)
            self.references[vulnerability_uuid].append(
                {
                    "referenced_uuid": capec_object.uuid,
                    "relationship_type": "targeted-by",
                }
            )

    def __parse_weakness(self, cwe_value, vulnerability_uuid):
        cwe_string, cwe_id = cwe_value.split("-")[:2]
        cwe = requests.get(f"{self.api_url}cwe/{cwe_id}")
        if cwe.status_code == 200:
            cwe = cwe.json()
            weakness_object = MISPObject("weakness")
            weakness_object.add_attribute("id", f"{cwe_string}-{cwe_id}")
            for feature, relation in self.weakness_mapping.items():
                if cwe.get(feature):
                    weakness_object.add_attribute(relation, cwe[feature])
            self.misp_event.add_object(weakness_object)
            self.references[vulnerability_uuid].append(
                {
                    "referenced_uuid": weakness_object.uuid,
                    "relationship_type": "weakened-by",
                }
            )


def check_url(url):
    return f"{url}/" if not url.endswith("/") else url


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute.get("type") != "vulnerability":
        misperrors["error"] = "Vulnerability id missing."
        return misperrors
    api_url = check_url(request["config"]["custom_API"]) if request.get("config", {}).get("custom_API") else cveapi_url
    r = requests.get(f"{api_url}cve/{attribute['value']}")
    if r.status_code == 200:
        vulnerability = r.json()
        if not vulnerability:
            misperrors["error"] = "Non existing CVE"
            return misperrors["error"]
    else:
        misperrors["error"] = "API not accessible"
        return misperrors["error"]
    parser = VulnerabilityParser(attribute, api_url)
    parser.parse_vulnerability_information(vulnerability)
    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
