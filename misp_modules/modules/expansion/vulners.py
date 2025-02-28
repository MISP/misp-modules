import json

import vulners

misperrors = {"error": "Error"}
mispattributes = {"input": ["vulnerability"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Igor Ivanov",
    "description": "An expansion hover module to expand information about CVE id using Vulners API.",
    "module-type": ["hover"],
    "name": "Vulners Lookup",
    "logo": "vulners.png",
    "requirements": ["Vulners python library", "An access to the Vulners API"],
    "features": (
        "This module takes a vulnerability attribute as input and queries the Vulners API in order to get some"
        " additional data about it.\n\nThe API then returns details about the vulnerability."
    ),
    "references": ["https://vulners.com/"],
    "input": "A vulnerability attribute.",
    "output": "Text giving additional information about the CVE in input.",
}

# Get API key from https://vulners.com/userinfo
moduleconfig = ["apikey"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("vulnerability"):
        misperrors["error"] = "Vulnerability id missing"
        return misperrors

    ai_summary = ""
    exploit_summary = ""
    vuln_summary = ""

    if not request.get("config") or not request["config"].get("apikey"):
        return {"error": "A Vulners api key is required for this module."}

    key = request["config"]["apikey"]
    vulners_api = vulners.Vulners(api_key=key)
    vulnerability = request.get("vulnerability")
    vulners_document = vulners_api.document(vulnerability)

    # Get AI scoring from the document if it's already calculated
    # There is no need to call AI Scoring method
    if "score" in vulners_document.get("enchantments", {}):
        vulners_ai_score = vulners_document["enchantments"]["score"]["value"]
    else:
        vulners_ai_score = vulners_api.get_ai_score(vulnerability)
        if len(vulners_ai_score) == 2:
            vulners_ai_score = vulners_ai_score[0]

    vulners_exploits = vulners_api.searchExploit(vulnerability)

    if vulners_document:
        vuln_summary += vulners_document.get("description")
    else:
        vuln_summary += "Non existing CVE"

    if vulners_ai_score:
        ai_summary += "Vulners AI Score is " + str(vulners_ai_score) + " "

    if vulners_exploits:
        exploit_summary += " ||  " + str(len(vulners_exploits)) + " Public exploits available:\n  "
        for exploit in vulners_exploits:
            exploit_summary += exploit["title"] + " " + exploit["href"] + "\n  "
        exploit_summary += "|| Vulnerability Description:  " + vuln_summary

    summary = ai_summary + exploit_summary + vuln_summary

    r = {"results": [{"types": mispattributes["output"], "values": summary}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
