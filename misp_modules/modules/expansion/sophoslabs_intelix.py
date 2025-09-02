import base64
import json
from urllib.parse import quote

import requests
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, checking_error, standard_error_message

moduleinfo = {
    "version": "1.0",
    "author": "Ben Verschaeren",
    "description": (
        "An expansion module to query the Sophoslabs intelix API to get additional information about an ip address,"
        " url, domain or sha256 attribute."
    ),
    "module-type": ["expansion"],
    "name": "SophosLabs Intelix Lookup",
    "logo": "sophoslabs_intelix.svg",
    "requirements": ["A client_id and client_secret pair to authenticate to the SophosLabs Intelix API"],
    "features": (
        "The module takes an ip address, url, domain or sha256 attribute and queries the SophosLabs Intelix API with"
        " the attribute value. The result of this query is a SophosLabs Intelix hash report, or an ip or url lookup,"
        " that is then parsed and returned in a MISP object."
    ),
    "references": ["https://aws.amazon.com/marketplace/pp/B07SLZPMCS"],
    "input": "An ip address, url, domain or sha256 attribute.",
    "output": "SophosLabs Intelix report and lookup objects",
}

moduleconfig = ["client_id", "client_secret", "region"]

misperrors = {"error": "Error"}

misp_types_in = ["sha256", "ip", "ip-src", "ip-dst", "uri", "url", "domain", "hostname"]

mispattributes = {"input": misp_types_in, "format": "misp_standard"}


class SophosLabsApi:
    def __init__(self, client_id: str, client_secret: str, region: str) -> None:
        self.misp_event = MISPEvent()
        self.client_id = client_id
        self.client_secret = client_secret
        self.authToken = f"{self.client_id}:{self.client_secret}"
        self.baseurl = f"{region}.api.labs.sophos.com"
        d = {"grant_type": "client_credentials"}
        h = {
            "Authorization": f"Basic {base64.b64encode(self.authToken.encode('UTF-8')).decode('ascii')}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        r = requests.post("https://api.labs.sophos.com/oauth2/token", headers=h, data=d)
        if r.status_code == 200:
            j = json.loads(r.text)
            self.accessToken = j["access_token"]

    def _get_headers(self, auth_type: str = "Bearer") -> dict:
        if auth_type == "Basic":
            return {
                "Authorization": f"Basic {base64.b64encode(self.authToken.encode('UTF-8')).decode('ascii')}",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "misp-module",
            }
        return {
            "Authorization": f"{self.accessToken}",
            "User-Agent": "misp-module",
        }

    def _authenticate(self) -> str:
        d = {"grant_type": "client_credentials"}
        h = self._get_headers(auth_type="Basic")
        r = requests.post("https://api.labs.sophos.com/oauth2/token", headers=h, data=d)
        if r.status_code == 200:
            j = json.loads(r.text)
            return j["access_token"]
        raise RuntimeError(f"Authentication failed: {r.status_code} {r.text}")

    def _misp_error(self, status_code: int) -> None:
        self.misp_event.add_attribute("text", f"SophosLabs lookup failed: HTTP {status_code}")
        return None

    def get_result(self) -> dict:
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": results}

    def hash_lookup(self, filehash):
        obj = MISPObject("file")
        obj.add_attribute("sha256", type="sha256", value=filehash, to_ids=True)
        h = self._get_headers()
        r = requests.get(f"https://{self.baseurl}/lookup/files/v1/{filehash}", headers=h)
        if r.status_code == 200:
            j = r.json()
            if "reputationScore" in j:
                obj.add_attribute("Reputation Score", type="text", value=j["reputationScore"])
                if 0 <= j["reputationScore"] <= 19:
                    obj.add_attribute("Decision", type="text", value="This file is malicious")
                if 20 <= j["reputationScore"] <= 29:
                    obj.add_attribute(
                        "Decision",
                        type="text",
                        value="This file is potentially unwanted",
                    )
                if 30 <= j["reputationScore"] <= 69:
                    obj.add_attribute(
                        "Decision",
                        type="text",
                        value="This file is unknown and suspicious",
                    )
                if 70 <= j["reputationScore"] <= 100:
                    obj.add_attribute("Decision", type="text", value="This file is known good")
            if "detectionName" in j:
                obj.add_attribute("Detection Name", type="text", value=j["detectionName"])
            else:
                obj.add_attribute(
                    "Detection Name",
                    type="text",
                    value="No name associated with this IoC",
                )
        self.misp_event.add_object(obj)

    def ip_lookup(self, ip, attribute_type):
        obj = MISPObject("domain-ip")
        obj.add_attribute("ip", type=attribute_type, value=ip, to_ids=False)
        h = self._get_headers()
        r = requests.get(f"https://{self.baseurl}/lookup/ips/v1/{ip}", headers=h)
        if r.status_code == 200:
            j = r.json()
            if "category" in j:
                for c in j["category"]:
                    obj.add_attribute("IP Address Categorisation", type="text", value=c)
            else:
                obj.add_attribute(
                    "IP Address Categorisation",
                    type="text",
                    value="No category associated with IoC",
                )
        self.misp_event.add_object(obj)

    def url_lookup(self, url):
        obj = MISPObject("url")
        obj.add_attribute("url", type="url", value=url, to_ids=False)
        h = self._get_headers()
        r = requests.get(f"https://{self.baseurl}/lookup/urls/v1/{quote(url, safe='')}", headers=h)
        if r.status_code == 200:
            j = r.json()
            mapping = [
                ("productivityCategory", "Productivity Category"),
                ("riskLevel", "Risk Level"),
                ("securityCategory", "Security Category"),
            ]
            for key, label in mapping:
                val = j.get(key)
                if val is None:
                    continue
                obj.add_attribute(
                    label,
                    type="text",
                    category="External analysis",
                    value=f"{val}",
                    to_ids=False,
                )
        self.misp_event.add_object(obj)


def handler(q=False):
    if q is False:
        return False
    j = json.loads(q)
    if not j.get("config") or not j["config"].get("client_id") or not j["config"].get("client_secret"):
        misperrors["error"] = (
            "Missing client_id or client_secret value for SOPHOSLabs Intelix. It's free to sign up here"
            " https://aws.amazon.com/marketplace/pp/B07SLZPMCS."
        )
        return misperrors
    if j["config"]["region"] not in ["us", "de", "au"]:
        j["config"]["region"] = "de"
    to_check = (("type", "value"), ("type", "value1"))
    if not j.get("attribute") or not any(
        check_input_attribute(j["attribute"], requirements=check) for check in to_check
    ):
        return {"error": f"{standard_error_message}, {checking_error}."}
    attribute = j["attribute"]
    if attribute["type"] not in misp_types_in:
        return {"error": "Unsupported attribute type."}
    client = SophosLabsApi(j["config"]["client_id"], j["config"]["client_secret"], j["config"]["region"])

    attribute_value = attribute.get("value", attribute.get("value1"))
    attribute_type = attribute["type"]

    if attribute_type == "sha256":
        client.hash_lookup(attribute_value)
    elif attribute_type in ["ip-dst", "ip-src"]:
        client.ip_lookup(attribute_value, attribute_type)
    elif attribute_type in ["uri", "url", "domain", "hostname"]:
        client.url_lookup(attribute_value)
    else:
        return {"error": "Unsupported attribute type."}

    return client.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
