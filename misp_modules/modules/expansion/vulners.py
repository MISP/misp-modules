import json

import vulners
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["vulnerability"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.3",
    "author": "Igor Ivanov",
    "description": "An expansion hover module to expand information about CVE id using Vulners API.",
    "module-type": ["hover"],
    "name": "Vulners Lookup",
    "logo": "vulners.png",
    "requirements": ["Vulners python library", "An access to the Vulners API"],
    "features": (
        "This module takes a vulnerability attribute as input and queries the Vulners API in order to get some"
        " additional data about it.\n\nThe API then returns details about the vulnerability, the public exploits"
        " Vulners knows about, and the Vulners AI score."
    ),
    "references": ["https://vulners.com/"],
    "input": "A vulnerability attribute.",
    "output": "A vulnerability object, one exploit object per public exploit, and the Vulners AI score.",
}

# Get API key from https://vulners.com/userinfo
moduleconfig = ["apikey"]


def _add_if(misp_object, relation, value, attribute_type=None):
    if value is None or value == "":
        return
    if attribute_type is None:
        misp_object.add_attribute(relation, value)
    else:
        misp_object.add_attribute(relation, **{"type": attribute_type, "value": value})


def _parse_vulnerability(document, vulnerability):
    misp_object = MISPObject("vulnerability")
    misp_object.add_attribute("id", vulnerability)
    _add_if(misp_object, "summary", document.get("title"))
    _add_if(misp_object, "description", document.get("description"))
    cvss = document.get("cvss") or {}
    _add_if(misp_object, "cvss-score", cvss.get("score"))
    _add_if(misp_object, "cvss-string", cvss.get("vector"))
    _add_if(misp_object, "published", document.get("published"))
    _add_if(misp_object, "modified", document.get("modified"))
    for reference in document.get("references") or []:
        _add_if(misp_object, "references", reference)
    return misp_object


def _parse_exploit(exploit, vulnerability):
    misp_object = MISPObject("exploit")
    _add_if(misp_object, "title", exploit.get("title"))
    _add_if(misp_object, "reference", exploit.get("href"))
    _add_if(misp_object, "description", exploit.get("description"))
    misp_object.add_attribute("cve-id", vulnerability)
    # Only where Vulners actually carries the source. An entry it knows only
    # by title and link is satisfied by those from exploit template v2 on.
    _add_if(misp_object, "exploit", exploit.get("sourceData"))
    return misp_object


def _parse_ai_score(score):
    """The Vulners AI score is a verdict Vulners gives, not a CVSS score, so it
    goes in a reputation object rather than into cvss-score.

    The relations are typed explicitly because pymisp does not bundle the
    reputation template yet."""
    misp_object = MISPObject("reputation")
    misp_object.add_attribute("source", **{"type": "text", "value": "Vulners"})
    misp_object.add_attribute("score", **{"type": "float", "value": score})
    misp_object.add_attribute("text", **{"type": "text", "value": "Vulners AI Score, on a 0-10 scale."})
    return misp_object


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] != "vulnerability":
        return {"error": "Wrong input attribute type."}

    if not request.get("config") or not request["config"].get("apikey"):
        return {"error": "A Vulners api key is required for this module."}

    key = request["config"]["apikey"]
    vulners_api = vulners.Vulners(api_key=key)
    vulnerability = attribute["value"]
    vulners_document = vulners_api.document(vulnerability)
    if not vulners_document:
        return {"error": f"Vulners has no record of {vulnerability}."}

    # Get AI scoring from the document if it's already calculated
    # There is no need to call AI Scoring method
    if "score" in vulners_document.get("enchantments", {}):
        vulners_ai_score = vulners_document["enchantments"]["score"]["value"]
    else:
        vulners_ai_score = vulners_api.get_ai_score(vulnerability)
        if len(vulners_ai_score) == 2:
            vulners_ai_score = vulners_ai_score[0]

    vulners_exploits = vulners_api.searchExploit(vulnerability)

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    misp_object = _parse_vulnerability(vulners_document, vulnerability)
    misp_object.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(misp_object)

    if vulners_ai_score:
        misp_object = _parse_ai_score(vulners_ai_score)
        misp_object.add_reference(input_attribute.uuid, "related-to")
        misp_event.add_object(misp_object)

    for exploit in vulners_exploits or []:
        misp_object = _parse_exploit(exploit, vulnerability)
        misp_object.add_reference(input_attribute.uuid, "related-to")
        misp_event.add_object(misp_object)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
