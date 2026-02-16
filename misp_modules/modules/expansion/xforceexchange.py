import json
import sys
from collections import defaultdict

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject
from requests.auth import HTTPBasicAuth

from . import check_input_attribute, standard_error_message

sys.path.append("./")

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "ip-src",
        "ip-dst",
        "vulnerability",
        "md5",
        "sha1",
        "sha256",
        "domain",
        "hostname",
        "url",
    ],
    "output": ["ip-src", "ip-dst", "text", "domain"],
    "format": "misp_standard",
}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "2",
    "author": "Joerg Stephan (@johest)",
    "description": "An expansion module for IBM X-Force Exchange.",
    "module-type": ["expansion", "hover"],
    "name": "IBM X-Force Exchange Lookup",
    "logo": "xforce.png",
    "requirements": ["An access to the X-Force API (apikey)"],
    "features": (
        "This module takes a MISP attribute as input to query the X-Force API. The API returns then additional"
        " information known in their threats data, that is mapped into MISP attributes."
    ),
    "references": ["https://exchange.xforce.ibmcloud.com/"],
    "input": (
        "A MISP attribute included in the following list:\n- ip-src\n- ip-dst\n- vulnerability\n- md5\n- sha1\n- sha256"
    ),
    "output": "MISP attributes mapped from the result of the query on X-Force Exchange.",
}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "apipassword"]


class XforceExchange:
    def __init__(self, attribute, apikey, apipassword):
        self.base_url = "https://api.xforce.ibmcloud.com"
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self._apikey = apikey
        self._apipassword = apipassword
        self.result = {}
        self.objects = defaultdict(dict)
        self.status_mapping = {
            403: (
                "Access denied, please check if your authentication is valid and if you did not reach the limit of"
                " queries."
            ),
            404: "No result found for your query.",
        }

    def parse(self):
        mapping = {"url": "_parse_url", "vulnerability": "_parse_vulnerability"}
        mapping.update(dict.fromkeys(("md5", "sha1", "sha256"), "_parse_hash"))
        mapping.update(dict.fromkeys(("domain", "hostname"), "_parse_dns"))
        mapping.update(dict.fromkeys(("ip-src", "ip-dst"), "_parse_ip"))
        to_call = mapping[self.attribute.type]
        getattr(self, to_call)(self.attribute.value)

    def get_result(self):
        if not self.misp_event.objects:
            if "error" not in self.result:
                self.result["error"] = "No additional data found on Xforce Exchange."
            return self.result
        self.misp_event.add_attribute(**self.attribute)
        event = json.loads(self.misp_event.to_json())
        result = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": result}

    def _api_call(self, url):
        try:
            result = requests.get(url, auth=HTTPBasicAuth(self._apikey, self._apipassword))
        except Exception as e:
            self.result["error"] = e
            return
        status_code = result.status_code
        if status_code != 200:
            try:
                self.result["error"] = self.status_mapping[status_code]
            except KeyError:
                self.result["error"] = "An error with the API has occurred."
            return
        return result.json()

    def _create_file(self, malware, relationship):
        file_object = MISPObject("file")
        for key, relation in zip(("filepath", "md5"), ("filename", "md5")):
            file_object.add_attribute(relation, malware[key])
        file_object.add_reference(self.attribute.uuid, relationship)
        return file_object

    def _create_url(self, malware):
        url_object = MISPObject("url")
        for key, relation in zip(("uri", "domain"), ("url", "domain")):
            url_object.add_attribute(relation, malware[key])
        attributes = tuple(f"{attribute.object_relation}_{attribute.value}" for attribute in url_object.attributes)
        if attributes in self.objects["url"]:
            del url_object
            return self.objects["url"][attributes]
        url_uuid = url_object.uuid
        self.misp_event.add_object(**url_object)
        self.objects["url"][attributes] = url_uuid
        return url_uuid

    def _fetch_types(self, value):
        if self.attribute.type in ("ip-src", "ip-dst"):
            return "ip", "domain", self.attribute.value
        return "domain", "ip", value

    def _handle_file(self, malware, relationship):
        file_object = self._create_file(malware, relationship)
        attributes = tuple(f"{attribute.object_relation}_{attribute.value}" for attribute in file_object.attributes)
        if attributes in self.objects["file"]:
            self.objects["file"][attributes].add_reference(self._create_url(malware), "dropped-by")
            del file_object
            return
        file_object.add_reference(self._create_url(malware), "dropped-by")
        self.objects["file"][attributes] = file_object
        self.misp_event.add_object(**file_object)

    def _parse_dns(self, value):
        dns_result = self._api_call(f"{self.base_url}/resolve/{value}")
        if dns_result.get("Passive") and dns_result["Passive"].get("records"):
            itype, ftype, value = self._fetch_types(dns_result["Passive"]["query"])
            misp_object = MISPObject("domain-ip")
            misp_object.add_attribute(itype, value)
            for record in dns_result["Passive"]["records"]:
                misp_object.add_attribute(ftype, record["value"])
            misp_object.add_reference(self.attribute.uuid, "related-to")
            self.misp_event.add_object(**misp_object)

    def _parse_hash(self, value):
        malware_result = self._api_call(f"{self.base_url}/malware/{value}")
        if malware_result and malware_result.get("malware"):
            malware_report = malware_result["malware"]
            for malware in malware_report.get("origins", {}).get("CnCServers", {}).get("rows", []):
                self._handle_file(malware, "related-to")

    def _parse_ip(self, value):
        self._parse_dns(value)
        self._parse_malware(value, "ipr")

    def _parse_malware(self, value, feature):
        malware_result = self._api_call(f"{self.base_url}/{feature}/malware/{value}")
        if malware_result and malware_result.get("malware"):
            for malware in malware_result["malware"]:
                self._handle_file(malware, "associated-with")

    def _parse_url(self, value):
        self._parse_dns(value)
        self._parse_malware(value, "url")

    def _parse_vulnerability(self, value):
        vulnerability_result = self._api_call(f"{self.base_url}/vulnerabilities/search/{value}")
        if vulnerability_result:
            for vulnerability in vulnerability_result:
                misp_object = MISPObject("vulnerability")
                for code in vulnerability["stdcode"]:
                    misp_object.add_attribute("id", code)
                for feature, relation in zip(
                    ("title", "description", "temporal_score"),
                    ("summary", "description", "cvss-score"),
                ):
                    misp_object.add_attribute(relation, vulnerability[feature])
                for reference in vulnerability["references"]:
                    misp_object.add_attribute("references", reference["link_target"])
                misp_object.add_reference(self.attribute.uuid, "related-to")
                self.misp_event.add_object(**misp_object)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("config") or not (request["config"].get("apikey") and request["config"].get("apipassword")):
        misperrors["error"] = "An API authentication is required (key and password)."
        return misperrors
    key = request["config"]["apikey"]
    password = request["config"]["apipassword"]
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message} which should contain at least a type, a value and an uuid."}
    if request["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    parser = XforceExchange(request["attribute"], key, password)
    parser.parse()
    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
