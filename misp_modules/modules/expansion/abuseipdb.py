import json

import dns.resolver
import requests
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, checking_error, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["ip-src", "ip-dst", "hostname", "domain", "domain|ip"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.1",
    "author": "Stephanie S",
    "description": "AbuseIPDB MISP expansion module",
    "module-type": ["expansion", "hover"],
    "name": "Abuse IPDB",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}

moduleconfig = ["api_key", "max_age_in_days", "abuse_threshold"]


def get_ip(request):
    # Need to get the ip from the domain
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    try:
        ip = resolver.query(request["attribute"]["value"], "A")
        return ip
    except dns.resolver.NXDOMAIN:
        misperrors["error"] = "NXDOMAIN"
        return misperrors
    except dns.exception.Timeout:
        misperrors["error"] = "Timeout"
        return misperrors
    except Exception:
        misperrors["error"] = "DNS resolving error"
        return misperrors


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if "config" not in request or "api_key" not in request["config"]:
        return {"error": "AbuseIPDB API key is missing"}
    if "max_age_in_days" not in request["config"]:
        return {"error": "AbuseIPDB max age in days is missing"}
    if "abuse_threshold" not in request["config"]:
        return {"error": "AbuseIPDB abuse threshold is missing"}
    if not request.get("attribute") or not check_input_attribute(request["attribute"], requirements=("type", "value")):
        return {"error": f"{standard_error_message}, {checking_error}."}
    if request["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    if (
        request["attribute"]["type"] == "hostname"
        or request["attribute"]["type"] == "domain"
        or request["attribute"]["type"] == "domain|ip"
    ):
        ip = get_ip(request)[0]

    else:
        ip = request["attribute"]["value"]

    api_key = request["config"]["api_key"]
    max_age_in_days = request["config"]["max_age_in_days"]
    api_endpoint = "https://api.abuseipdb.com/api/v2/check"
    querystring = {"ipAddress": ip, "maxAgeInDays": max_age_in_days}
    headers = {"Accept": "application/json", "key": api_key}
    r = {"results": []}

    response = requests.request(method="GET", url=api_endpoint, headers=headers, params=querystring)

    if response.status_code == 200:
        response_json = json.loads(response.text)
        is_whitelisted = response_json["data"]["isWhitelisted"]
        is_tor = response_json["data"]["isTor"]
        is_public = response_json["data"]["isPublic"]
        abuse_confidence_score = response_json["data"]["abuseConfidenceScore"]

        abuse_threshold = request["config"]["abuse_threshold"]

        if request["config"]["abuse_threshold"] is not None:
            abuse_threshold = request["config"]["abuse_threshold"]
        else:
            abuse_threshold = 70

        if is_whitelisted == False:
            is_whitelisted = 0
        if is_tor == False:
            is_tor = 0
        if is_public == False:
            is_public = 0
        if abuse_confidence_score is None:
            abuse_confidence_score = 0

        if response_json.get("errors"):
            return {"error": "AbuseIPDB error, check logs"}
        else:
            event = MISPEvent()
            obj = MISPObject("abuseipdb")
            event.add_attribute(**request["attribute"])

            if int(abuse_confidence_score) >= int(abuse_threshold):
                malicious_attribute = obj.add_attribute("is-malicious", **{"type": "boolean", "value": 1})
                malicious_attribute.add_tag('ioc:artifact-state="malicious"')
            else:
                malicious_attribute = obj.add_attribute("is-malicious", **{"type": "boolean", "value": 0})
                malicious_attribute.add_tag('ioc:artifact-state="not-malicious"')

            if is_whitelisted is not None:
                obj.add_attribute("is-whitelisted", **{"type": "boolean", "value": is_whitelisted})
            obj.add_attribute("is-tor", **{"type": "boolean", "value": is_tor})
            obj.add_attribute("is-public", **{"type": "boolean", "value": is_public})
            obj.add_attribute(
                "abuse-confidence-score",
                **{"type": "counter", "value": abuse_confidence_score},
            )
            obj.add_reference(request["attribute"]["uuid"], "describes")
            event.add_object(obj)

            # Avoid serialization issue
            event = json.loads(event.to_json())

        r["results"] = {"Object": event["Object"], "Attribute": event["Attribute"]}
        return r

    else:
        try:
            response_json = json.loads(response.text)
            if response_json["errors"]:
                return {
                    "error": (
                        "API not reachable, status code: "
                        + str(response.status_code)
                        + " "
                        + str(response_json["errors"][0]["detail"])
                    )
                }
        except Exception:
            pass
        return {"error": "API not reachable, status code: " + str(response.status_code)}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
