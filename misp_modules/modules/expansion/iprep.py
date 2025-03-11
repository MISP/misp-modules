# -*- coding: utf-8 -*-

import json

import requests

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst"], "output": ["text"]}
moduleinfo = {
    "version": "1.0",
    "author": "Keith Faber",
    "description": "Module to query IPRep data for IP addresses.",
    "module-type": ["expansion"],
    "name": "IPRep Lookup",
    "logo": "",
    "requirements": ["An access to the packetmail API (apikey)"],
    "features": (
        "This module takes an IP address attribute as input and queries the database from packetmail.net to get some"
        " information about the reputation of the IP."
    ),
    "references": ["https://github.com/mahesh557/packetmail"],
    "input": "An IP address MISP attribute.",
    "output": "Text describing additional information about the input after a query on the IPRep API.",
}

moduleconfig = ["apikey"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get("ip-src"):
        toquery = request["ip-src"]
    elif request.get("ip-dst"):
        toquery = request["ip-dst"]
    else:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors

    if not request.get("config") and not request["config"].get("apikey"):
        misperrors["error"] = "IPRep api key is missing"
        return misperrors

    err, rep = parse_iprep(toquery, request["config"].get("apikey"))
    if len(err) > 0:
        misperrors["error"] = ",".join(err)
        return misperrors
    return {"results": rep}


def parse_iprep(ip, api):
    meta_fields = [
        "origin",
        "Query_Time",
        "created_on",
        "IP_Lookup_History",
        "IPs_in_collection",
        "_id",
        "disclaimer",
        "MaxMind_Free_GeoIP",
        "Unique_Lookups",
        "query_result",
    ]
    rep = []
    err = []
    full_text = ""
    url = "https://www.packetmail.net/iprep.php/%s" % ip
    try:
        data = requests.get(url, params={"apikey": api}).json()
    except Exception:
        return ["Error pulling data"], rep
    # print '%s' % data
    for name, val in data.items():
        if name not in meta_fields:
            try:
                context = val["context"]
                if type(context) is list:
                    if context[0].get("alert"):
                        context = ",".join([hit["alert"]["signature"] for hit in context])
                    elif context[0].get("signature"):
                        context = ",".join([hit["signature"] for hit in context])
                    elif context[0].get("target_port") and context[0].get("protocol"):
                        context = ",".join(
                            ["Port Attacked: %s %s" % (hit["target_port"], hit["protocol"]) for hit in context]
                        )
                    elif context[0].get("phishing_kit") and context[0].get("url"):
                        context = ",".join(["%s (%s)" % (hit["phishing_kit"], hit["url"]) for hit in context])
                    else:
                        context = ";".join(["%s: %s" % (k, v) for k, v in context[0].items()])

                if val.get("special_note"):
                    context += "; " + val["special_note"]

                misp_val = context
                full_text += "\n%s" % context
                misp_comment = "IPRep Source %s: %s" % (name, val["last_seen"])
                rep.append(
                    {
                        "types": mispattributes["output"],
                        "categories": ["External analysis"],
                        "values": misp_val,
                        "comment": misp_comment,
                    }
                )
            except Exception:
                err.append("Error parsing source: %s" % name)

    rep.append(
        {
            "types": ["freetext"],
            "values": full_text,
            "comment": "Free text import of IPRep",
        }
    )
    return err, rep


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
