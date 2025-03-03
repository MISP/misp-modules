######################################################
#                                                    #
# Author: Stanislav Klevtsov, Ukraine; Feb 2019.     #
#                                                    #
#                                                    #
# Script was tested on the following configuration:  #
#    MISP v2.4.90                                    #
#    Cisco Firesight Manager Console v6.2.3 (bld 84) #
#                                                    #
######################################################

import base64
import json
from urllib.parse import quote

misperrors = {"error": "Error"}

moduleinfo = {
    "version": "1",
    "author": "Stanislav Klevtsov",
    "description": "Module to export malicious network activity attributes to Cisco fireSIGHT manager block rules.",
    "module-type": ["export"],
    "name": "Cisco fireSIGHT blockrule Export",
    "logo": "cisco.png",
    "requirements": ["Firesight manager console credentials"],
    "features": (
        "The module goes through the attributes to find all the network activity ones in order to create block rules"
        " for the Cisco fireSIGHT manager."
    ),
    "references": [],
    "input": "Network activity attributes (IPs, URLs).",
    "output": "Cisco fireSIGHT manager block rules.",
}


moduleconfig = ["fmc_ip_addr", "fmc_login", "fmc_pass", "domain_id", "acpolicy_id"]

fsmapping = {"ip-dst": "dst", "url": "request"}

mispattributes = {"input": list(fsmapping.keys())}

# options: event, attribute, event-collection, attribute-collection
inputSource = ["event"]

outputFileExtension = "sh"
responseType = "application/txt"

# .sh file templates
SH_FILE_HEADER = """#!/bin/sh\n\n"""

BLOCK_JSON_TMPL = """
BLOCK_RULE='{{ "action": "BLOCK", "enabled": true, "type": "AccessRule", "name": "{rule_name}", "destinationNetworks": {{ "literals": [ {dst_networks} ] }}, "urls": {{ "literals": [ {urls} ]  }}, "newComments": [ "{event_info_comment}" ] }}'\n
"""

BLOCK_DST_JSON_TMPL = """{{ "type": "Host", "value": "{ipdst}" }} """
BLOCK_URL_JSON_TMPL = """{{ "type": "Url", "url": "{url}" }} """

CURL_ADD_RULE_TMPL = """
curl -X POST -v -k -H 'Content-Type: application/json' -H \"Authorization: Basic $LOGINPASS_BASE64\" -H \"X-auth-access-token: $ACC_TOKEN\" -i \"https://$FIRESIGHT_IP_ADDR/api/fmc_config/v1/domain/$DOMAIN_ID/policy/accesspolicies/$ACPOLICY_ID/accessrules\" --data \"$BLOCK_RULE\" """


def handler(q=False):
    if q is False:
        return False

    r = {"results": []}
    request = json.loads(q)

    if "config" in request:
        config = request["config"]

    # check if config is empty
    if not config["fmc_ip_addr"]:
        config["fmc_ip_addr"] = "0.0.0.0"
    if not config["fmc_login"]:
        config["fmc_login"] = "login"
    if not config["fmc_pass"]:
        config["fmc_pass"] = "password"
    if not config["domain_id"]:
        config["domain_id"] = "SET_FIRESIGHT_DOMAIN_ID"
    if not config["acpolicy_id"]:
        config["acpolicy_id"] = "SET_FIRESIGHT_ACPOLICY_ID"

    data = request["data"]
    output = ""
    ipdst = []
    urls = []

    # populate the ACL rule with attributes
    for ev in data:

        event = ev["Attribute"]
        event_id = ev["Event"]["id"]
        event_info = ev["Event"]["info"]

        for index, attr in enumerate(event):
            if attr["to_ids"] is True:
                if attr["type"] in fsmapping:
                    if attr["type"] == "ip-dst":
                        ipdst.append(BLOCK_DST_JSON_TMPL.format(ipdst=attr["value"]))
                    else:
                        urls.append(BLOCK_URL_JSON_TMPL.format(url=quote(attr["value"], safe="@/:;?&=-_.,+!*")))

    # building the .sh file
    output += SH_FILE_HEADER
    output += "FIRESIGHT_IP_ADDR='{}'\n".format(config["fmc_ip_addr"])

    output += "LOGINPASS_BASE64=`echo -n '{}:{}' | base64`\n".format(config["fmc_login"], config["fmc_pass"])
    output += "DOMAIN_ID='{}'\n".format(config["domain_id"])
    output += "ACPOLICY_ID='{}'\n\n".format(config["acpolicy_id"])

    output += (
        'ACC_TOKEN=`curl -X POST -v -k -sD - -o /dev/null -H "Authorization: Basic $LOGINPASS_BASE64" -i'
        ' "https://$FIRESIGHT_IP_ADDR/api/fmc_platform/v1/auth/generatetoken" | grep -i x-auth-acc | sed \'s/.*:\\'
        " //g' | tr -d '[:space:]' | tr -d '\\n'`\n"
    )

    output += (
        BLOCK_JSON_TMPL.format(
            rule_name="misp_event_{}".format(event_id),
            dst_networks=", ".join(ipdst),
            urls=", ".join(urls),
            event_info_comment=event_info,
        )
        + "\n"
    )

    output += CURL_ADD_RULE_TMPL
    # END building the .sh file

    r = {"data": base64.b64encode(output.encode("utf-8")).decode("utf-8")}
    return r


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
