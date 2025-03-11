import json

import requests
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["cpe"], "format": "misp_standard"}
moduleinfo = {
    "version": "2",
    "author": "Christian Studer",
    "description": (
        "An expansion module to query the CVE search API with a cpe code to get its related vulnerabilities."
    ),
    "module-type": ["expansion", "hover"],
    "name": "CPE Lookup",
    "logo": "cve.png",
    "requirements": [],
    "features": (
        "The module takes a cpe attribute as input and queries the CVE search API to get its related vulnerabilities. "
        " \nThe list of vulnerabilities is then parsed and returned as vulnerability objects.\n\nUsers can use their"
        " own CVE search API url by defining a value to the custom_API_URL parameter. If no custom API url is given,"
        " the default vulnerability.circl.lu api url is used.\n\nIn order to limit the amount of data returned by CVE"
        " serach, users can also the limit parameter. With the limit set, the API returns only the requested number of"
        " vulnerabilities, sorted from the highest cvss score to the lowest one."
    ),
    "references": ["https://vulnerability.circl.lu/api/"],
    "input": "CPE attribute.",
    "output": "The vulnerabilities related to the CPE.",
}
moduleconfig = ["custom_API_URL", "limit"]
cveapi_url = "https://cvepremium.circl.lu/api/query"
DEFAULT_LIMIT = 10


class VulnerabilitiesParser:
    def __init__(self, attribute):
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.vulnerability_mapping = {
            "id": {"type": "vulnerability", "object_relation": "id"},
            "summary": {"type": "text", "object_relation": "summary"},
            "vulnerable_configuration": {
                "type": "cpe",
                "object_relation": "vulnerable-configuration",
            },
            "vulnerable_configuration_cpe_2_2": {
                "type": "cpe",
                "object_relation": "vulnerable-configuration",
            },
            "Modified": {"type": "datetime", "object_relation": "modified"},
            "Published": {"type": "datetime", "object_relation": "published"},
            "references": {"type": "link", "object_relation": "references"},
            "cvss": {"type": "float", "object_relation": "cvss-score"},
        }

    def parse_vulnerabilities(self, vulnerabilities):
        for vulnerability in vulnerabilities:
            vulnerability_object = MISPObject("vulnerability")
            for feature in ("id", "summary", "Modified", "Published", "cvss"):
                if vulnerability.get(feature):
                    attribute = {"value": vulnerability[feature]}
                    attribute.update(self.vulnerability_mapping[feature])
                    vulnerability_object.add_attribute(**attribute)
            if vulnerability.get("Published"):
                vulnerability_object.add_attribute(**{"type": "text", "object_relation": "state", "value": "Published"})
            for feature in (
                "references",
                "vulnerable_configuration",
                "vulnerable_configuration_cpe_2_2",
            ):
                if vulnerability.get(feature):
                    for value in vulnerability[feature]:
                        if isinstance(value, dict):
                            value = value["title"]
                        attribute = {"value": value}
                        attribute.update(self.vulnerability_mapping[feature])
                        vulnerability_object.add_attribute(**attribute)
            vulnerability_object.add_reference(self.attribute["uuid"], "related-to")
            self.misp_event.add_object(vulnerability_object)

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object")}
        return {"results": results}


def check_url(url):
    return url if url.endswith("/") else f"{url}/"


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute.get("type") != "cpe":
        return {"error": "Wrong input attribute type."}
    config = request["config"]
    url = check_url(config["custom_API_URL"]) if config.get("custom_API_URL") else cveapi_url
    limit = int(config["limit"]) if config.get("limit") else DEFAULT_LIMIT
    params = {
        "retrieve": "cves",
        "dict_filter": {"vulnerable_configuration": attribute["value"]},
        "limit": limit,
        "sort": "cvss",
        "sort_dir": "DESC",
    }
    response = requests.post(url, json=params)
    if response.status_code == 200:
        vulnerabilities = response.json()["data"]
        if not vulnerabilities:
            return {"error": "No related vulnerability for this CPE."}
    else:
        return {"error": "API not accessible."}
    parser = VulnerabilitiesParser(attribute)
    parser.parse_vulnerabilities(vulnerabilities)
    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
