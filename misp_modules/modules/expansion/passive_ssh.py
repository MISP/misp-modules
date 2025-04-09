import json
from collections import defaultdict

import requests
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["ip-src", "ip-dst", "ssh-fingerprint"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "1",
    "author": "Jean-Louis Huynen",
    "description": (
        "An expansion module to enrich, SSH key fingerprints and IP addresses with information collected by passive-ssh"
    ),
    "module-type": ["expansion", "hover"],
    "name": "Passive SSH Enrichment",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}

moduleconfig = ["custom_api_url", "api_user", "api_key"]

passivessh_url = "https://passivessh.circl.lu/"

host_query = "/host/ssh"
fingerprint_query = "/fingerprint/all"


class PassivesshParser:
    def __init__(self, attribute, passivesshresult):
        self.attribute = attribute
        self.passivesshresult = passivesshresult
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.references = defaultdict(list)

    def get_result(self):
        if self.references:
            self.__build_references()
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": results}

    def parse_passivessh_information(self):
        passivessh_object = MISPObject("passive-ssh")
        if "first_seen" in self.passivesshresult:
            passivessh_object.add_attribute(
                "first_seen",
                **{"type": "datetime", "value": self.passivesshresult["first_seen"]},
            )
        if "last_seen" in self.passivesshresult:
            passivessh_object.add_attribute(
                "last_seen",
                **{"type": "datetime", "value": self.passivesshresult["last_seen"]},
            )
        if "base64" in self.passivesshresult:
            passivessh_object.add_attribute("base64", **{"type": "text", "value": self.passivesshresult["base64"]})
        if "keys" in self.passivesshresult:
            for key in self.passivesshresult["keys"]:
                passivessh_object.add_attribute(
                    "fingerprint",
                    **{"type": "ssh-fingerprint", "value": key["fingerprint"]},
                )
        if "hosts" in self.passivesshresult:
            for host in self.passivesshresult["hosts"]:
                passivessh_object.add_attribute("host", **{"type": "ip-dst", "value": host})

        passivessh_object.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(passivessh_object)

    def __build_references(self):
        for object_uuid, references in self.references.items():
            for misp_object in self.misp_event.objects:
                if misp_object.uuid == object_uuid:
                    for reference in references:
                        misp_object.add_reference(**reference)
                    break


def check_url(url):
    return "{}/".format(url) if not url.endswith("/") else url


def handler(q=False):

    if q is False:
        return False
    request = json.loads(q)

    api_url = (
        check_url(request["config"]["custom_api_url"]) if request["config"].get("custom_api_url") else passivessh_url
    )

    if request["config"].get("api_user"):
        api_user = request["config"].get("api_user")
    else:
        misperrors["error"] = "passive-ssh user required"
        return misperrors
    if request["config"].get("api_key"):
        api_key = request["config"].get("api_key")
    else:
        misperrors["error"] = "passive-ssh password required"
        return misperrors

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute.get("type") == "ip-src":
        type = host_query
        pass
    elif attribute.get("type") == "ip-dst":
        type = host_query
        pass
    elif attribute.get("type") == "ssh-fingerprint":
        type = fingerprint_query
        pass
    else:
        misperrors["error"] = "ip is missing."
        return misperrors

    r = requests.get("{}{}/{}".format(api_url, type, attribute["value"]), auth=(api_user, api_key))

    if r.status_code == 200:
        passivesshresult = r.json()
        if not passivesshresult:
            misperrors["error"] = "Empty result"
            return misperrors
    elif r.status_code == 404:
        misperrors["error"] = "Non existing hash"
        return misperrors
    else:
        misperrors["error"] = "API not accessible"
        return misperrors

    parser = PassivesshParser(attribute, passivesshresult)
    parser.parse_passivessh_information()
    result = parser.get_result()

    return result


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
