# import requests
import json

from pymisp import MISPEvent, MISPObject
from pysafebrowsing import SafeBrowsing

from . import check_input_attribute, checking_error, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["url"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.1",
    "author": "Stephanie S",
    "description": "Google safe browsing expansion module",
    "module-type": ["expansion", "hover"],
    "name": "Google Safe Browsing Lookup",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}

moduleconfig = ["api_key"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if "config" not in request or "api_key" not in request["config"]:
        return {"error": "Google Safe Browsing API key is missing"}
    if not request.get("attribute") or not check_input_attribute(request["attribute"], requirements=("type", "value")):
        return {"error": f"{standard_error_message}, {checking_error}."}
    if request["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    api_key = request["config"]["api_key"]
    url = request["attribute"]["value"]

    s = SafeBrowsing(api_key)
    try:
        response = s.lookup_urls([url])

        event = MISPEvent()
        obj = MISPObject("google-safe-browsing")
        event.add_attribute(**request["attribute"])

        if response[url]["malicious"] != False:
            # gsb threat types: THREAT_TYPE_UNSPECIFIED, MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION
            gsb_circl_threat_taxonomy = {
                "MALWARE": "malware",
                "SOCIAL_ENGINEERING": "social-engineering",
            }

            threats = response[url]["threats"]
            malicious = response[url]["malicious"]
            platforms = response[url]["platforms"]

            malicious_attribute = obj.add_attribute("malicious", **{"type": "boolean", "value": malicious})
            malicious_attribute.add_tag('ioc:artifact-state="malicious"')
            threat_attribute = obj.add_attribute("threats", **{"type": "text", "value": str(" ".join(threats))})
            for threat in threats:
                # If the threat exists as a key in taxonomy_dict, add that tag
                if gsb_circl_threat_taxonomy.get(threat) is not None:
                    threat_attribute.add_tag(f'circl:incident="{gsb_circl_threat_taxonomy.get(threat)}"')
                else:
                    threat_attribute.add_tag(f"threat-type:{str(threat).lower()}")
            obj.add_attribute("platforms", **{"type": "text", "value": str(" ".join(platforms))})

        else:
            malicious_attribute = obj.add_attribute("malicious", **{"type": "boolean", "value": 0})  # 0 == False
            malicious_attribute.add_tag('ioc:artifact-state="not-malicious"')

        obj.add_reference(request["attribute"]["uuid"], "describes")
        event.add_object(obj)

        # Avoid serialization issue
        event = json.loads(event.to_json())
        return {"results": {"Object": event["Object"], "Attribute": event["Attribute"]}}

    except Exception as error:
        return {"error": "An error occurred: " + str(error)}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
