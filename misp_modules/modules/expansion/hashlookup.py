import json
from collections import defaultdict

import requests
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha1", "sha256"], "format": "misp_standard"}
moduleinfo = {
    "version": "2",
    "author": "Alexandre Dulaunoy",
    "description": (
        "An expansion module to query the CIRCL hashlookup services to find it if a hash is part of a known set such as"
        " NSRL."
    ),
    "module-type": ["expansion", "hover"],
    "name": "CIRCL Hashlookup Lookup",
    "logo": "circl.png",
    "requirements": [],
    "features": (
        "The module takes file hashes as input such as a MD5 or SHA1.\n It queries the public CIRCL.lu hashlookup"
        " service and return all the hits if the hashes are known in an existing dataset. The module can be configured"
        " with a custom hashlookup url if required.\n The module can be used an hover module but also an expansion"
        " model to add related MISP objects.\n"
    ),
    "references": ["https://www.circl.lu/services/hashlookup/"],
    "input": "File hashes (MD5, SHA1)",
    "output": "Object with the filename associated hashes if the hash is part of a known set.",
}
moduleconfig = ["custom_API"]
hashlookup_url = "https://hashlookup.circl.lu/"


class HashlookupParser:
    def __init__(self, attribute, hashlookupresult, api_url):
        self.attribute = attribute
        self.hashlookupresult = hashlookupresult
        self.api_url = api_url
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.references = defaultdict(list)

    def get_result(self):
        if self.references:
            self.__build_references()
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": results}

    def parse_hashlookup_information(self):
        hashlookup_object = MISPObject("hashlookup")
        if "source" in self.hashlookupresult:
            hashlookup_object.add_attribute("source", **{"type": "text", "value": self.hashlookupresult["source"]})
        if "KnownMalicious" in self.hashlookupresult:
            hashlookup_object.add_attribute(
                "KnownMalicious",
                **{"type": "text", "value": self.hashlookupresult["KnownMalicious"]},
            )
        if "MD5" in self.hashlookupresult:
            hashlookup_object.add_attribute("MD5", **{"type": "md5", "value": self.hashlookupresult["MD5"]})
        # SHA-1 is the default value in hashlookup it must always be present
        hashlookup_object.add_attribute("SHA-1", **{"type": "sha1", "value": self.hashlookupresult["SHA-1"]})
        if "SHA-256" in self.hashlookupresult:
            hashlookup_object.add_attribute(
                "SHA-256",
                **{"type": "sha256", "value": self.hashlookupresult["SHA-256"]},
            )
        if "SSDEEP" in self.hashlookupresult:
            hashlookup_object.add_attribute("SSDEEP", **{"type": "ssdeep", "value": self.hashlookupresult["SSDEEP"]})
        if "TLSH" in self.hashlookupresult:
            hashlookup_object.add_attribute("TLSH", **{"type": "tlsh", "value": self.hashlookupresult["TLSH"]})
        if "FileName" in self.hashlookupresult:
            hashlookup_object.add_attribute(
                "FileName",
                **{"type": "filename", "value": self.hashlookupresult["FileName"]},
            )
        if "FileSize" in self.hashlookupresult:
            hashlookup_object.add_attribute(
                "FileSize",
                **{"type": "size-in-bytes", "value": self.hashlookupresult["FileSize"]},
            )
        hashlookup_object.add_reference(self.attribute["uuid"], "related-to")
        self.misp_event.add_object(hashlookup_object)

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
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute.get("type") == "md5":
        pass
    elif attribute.get("type") == "sha1":
        pass
    elif attribute.get("type") == "sha256":
        pass
    else:
        misperrors["error"] = "md5 or sha1 or sha256 is missing."
        return misperrors
    api_url = check_url(request["config"]["custom_API"]) if request["config"].get("custom_API") else hashlookup_url
    r = requests.get("{}/lookup/{}/{}".format(api_url, attribute.get("type"), attribute["value"]))
    if r.status_code == 200:
        hashlookupresult = r.json()
        if not hashlookupresult:
            misperrors["error"] = "Empty result"
            return misperrors
    elif r.status_code == 404:
        misperrors["error"] = "Non existing hash"
        return misperrors
    else:
        misperrors["error"] = "API not accessible"
        return misperrors
    parser = HashlookupParser(attribute, hashlookupresult, api_url)
    parser.parse_hashlookup_information()
    result = parser.get_result()
    return result


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
