import json
import re

import requests
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, checking_error, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["md5", "sha1", "sha256"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.1",
    "author": "goodlandsecurity",
    "description": "Module to query the Stairwell API to get additional information about the input hash attribute",
    "module-type": ["expansion"],
    "name": "Stairwell Lookup",
    "logo": "stairwell.png",
    "requirements": ["Access to Stairwell platform (apikey)"],
    "features": (
        "The module takes a hash attribute as input and queries Stariwell's API to fetch additional data about it. The"
        " result, if the payload is observed in Stariwell, is a file object describing the file the input hash is"
        " related to."
    ),
    "references": ["https://stairwell.com", "https://docs.stairwell.com"],
    "input": "A hash attribute (md5, sha1, sha256).",
    "output": "File object related to the input attribute found on Stairwell platform.",
}
moduleconfig = ["apikey"]


def parse_response(response: dict):
    attribute_mapping = {
        "environments": {
            "type": "comment",
            "object_relation": "environment",
            "distribution": 5,
        },
        "imphash": {"type": "imphash", "object_relation": "impash", "distribution": 5},
        "magic": {"type": "comment", "object_relation": "magic", "distribution": 5},
        "malEval": {
            "probabilityBucket": {
                "type": "comment",
                "object_relation": "malEval-probability",
                "distribution": 5,
            },
            "severity": {
                "type": "comment",
                "object_relation": "malEval-severity",
                "distribution": 5,
            },
        },
        "md5": {"type": "md5", "object_relation": "md5", "distribution": 5},
        "mimeType": {
            "type": "mime-type",
            "object_relation": "mime-type",
            "distribution": 5,
        },
        "sha1": {"type": "sha1", "object_relation": "sha1", "distribution": 5},
        "sha256": {"type": "sha256", "object_relation": "sha256", "distribution": 5},
        "shannonEntropy": {
            "type": "float",
            "object_relation": "entropy",
            "distribution": 5,
        },
        "size": {
            "type": "size-in-bytes",
            "object_relation": "size-in-bytes",
            "distribution": 5,
        },
        "stairwellFirstSeenTime": {
            "type": "datetime",
            "object_relation": "stairwell-first-seen",
            "distribution": 5,
        },
        "tlsh": {"type": "tlsh", "object_relation": "tlsh", "distribution": 5},
        "yaraRuleMatches": {
            "type": "text",
            "object_relation": "yara-rule-match",
            "comment": "matching Stairwell yara rule name",
            "distribution": 5,
        },
    }
    environments_mapping = {
        "NCS2SM-YHB2KT-SAFUDX-JC7F6WYA": "Florian's Open Rules",
        "VR9Z98-4KU7ZC-PCNFEG-FURQ66FW": "Jotti",
        "D7W6M6-BA9BS4-BQ23Z4-NKCNWQ96": "Malshare",
        "D4447Q-WJJL6P-W7ME89-WHXJK8TW": "Malware Bazaar",
        "XAKLND-DKWP3Z-56RL88-6XJ5NH46": "Pro Rules",
        "GMEELM-K226XF-F95XZL-7VEJFKZ6": "Public Samples",
        "5HEG8N-9T7UPG-8SZJ7T-2J4XSDC6": "RH-ISAC",
        "2NN2BJ-HDVQHS-49824H-2SEDBBLJ": "RH-ISAC Malware Sharing",
        "VCZTNF-8S76AK-LUU53W-2SWFFZWJ": "Stairwell Experimental Rules",
        "GEG6FU-MRARGF-TLTM6X-H6MGDT5E": "Stairwell Methodology Rules",
        "EB3DXY-3ZYFVH-6HNKJQ-GAPKHESS": "Stairwell OSINT Rules",
        "NQNJM6-5LSCAF-3MC5FJ-W8EKGW6N": "Stairwell Research Rules",
        "TT9GM5-JUMD8H-9828FL-GAW5NNXE": "stairwell-public-verdicts",
        "MKYSAR-3XN9MB-3VAK3R-888ZJUTJ": "Threat Report Feeds",
        "6HP5R3-ZM7DAN-RB4732-X6QPCJ36": "Virusshare",
        "TV6WCV-7Y79LE-BK79EY-C8GUEY46": "vxintel",
    }

    misp_event = MISPEvent()
    misp_object = MISPObject("stairwell")
    for feature, attribute in attribute_mapping.items():
        if feature in response.keys() and response[feature]:
            if feature == "yaraRuleMatches":
                for rule in response[feature]:
                    env_pattern = r"\b[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{8}\b"
                    env = re.findall(env_pattern, rule.split("yaraRules/")[0])[0]
                    misp_attribute = {
                        "value": rule.split("yaraRules/")[1],
                        "comment": f'Rule from: {environments_mapping.get(env, "Unknown UUID!")}',
                    }
                    misp_attribute.update(attribute)
                    misp_object.add_attribute(**misp_attribute)
            elif feature == "environments":
                for env in response[feature]:
                    misp_attribute = {
                        "value": environments_mapping.get(env, f"Unknown Environment: {env}"),
                        "comment": "Hash observed in",
                    }
                    misp_attribute.update(attribute)
                    misp_object.add_attribute(**misp_attribute)
            elif feature == "malEval":
                for attr in attribute:
                    misp_attribute = {"value": response[feature][attr]}
                    misp_attribute.update(attribute[attr])
                    misp_object.add_attribute(**misp_attribute)
            else:
                misp_attribute = {"value": response[feature]}
                misp_attribute.update(attribute)
                attr = misp_object.add_attribute(**misp_attribute)
                if feature in ("md5", "sha1", "sha256"):
                    for label in response["malEval"]["labels"]:
                        attr.add_tag(label)
    misp_event.add_object(**misp_object)

    event = json.loads(misp_event.to_json())
    results = {"Object": event["Object"]}

    return {"results": results}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("config") or not request["config"].get("apikey"):
        misperrors["error"] = "A Stairwell api key is required for this module!"
        return misperrors
    if not request.get("attribute") or not check_input_attribute(request["attribute"], requirements=("type", "value")):
        misperrors["error"] = f"{standard_error_message}, {checking_error}."
        return misperrors
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        misperrors["error"] = "Unsupported attribute type!"
        return misperrors

    headers = {
        "Accept": "application/json",
        "Authorization": request["config"]["apikey"],
        "User-Agent": f"misp-module {__file__} {moduleinfo['version']}",
    }
    url = f"https://app.stairwell.com/v1/objects/{attribute['value']}/metadata"
    response = requests.get(url=url, headers=headers).json()

    if response.get("code") == 16:  # bad auth
        return {"error": f"{response['message']} Is api key valid?"}
    elif response.get("code") == 5:  # not found
        return {"error": f"{attribute['type']}:{attribute['value']} {response['message']}"}
    elif response.get("code") == 2:  # encoding/hex: invalid byte
        return {"error": response["message"]}
    elif response.get("code"):  # catchall for potential unforeseen errors
        return {"error": response["message"], "code": response["code"]}
    else:
        return parse_response(response)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
