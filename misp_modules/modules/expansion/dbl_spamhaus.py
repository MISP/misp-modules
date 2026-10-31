import json
import sys

original_path = sys.path
sys.path = original_path[1:]
import dns.resolver
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

sys.path = original_path
resolver = dns.resolver.Resolver()
resolver.timeout = 0.2
resolver.lifetime = 0.2


misperrors = {"error": "Error"}
mispattributes = {
    "input": ["domain", "domain|ip", "hostname", "hostname|port"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.2",
    "author": "Christian Studer",
    "description": "Checks Spamhaus DBL for a domain name.",
    "module-type": ["expansion", "hover"],
    "name": "DBL Spamhaus Lookup",
    "logo": "spamhaus.jpg",
    "requirements": ["dnspython3: DNS python3 library"],
    "features": (
        "This modules takes a domain or a hostname in input and queries the Domain Block List provided by Spamhaus to"
        " determine what kind of domain it is.\n\nDBL then returns a response code corresponding to a certain"
        " classification of the domain we display. If the queried domain is not in the list, it is also"
        " mentionned.\n\nPlease note that composite MISP attributes containing domain or hostname are supported as"
        " well."
    ),
    "references": ["https://www.spamhaus.org/faq/section/Spamhaus%20DBL"],
    "input": "Domain or hostname attribute.",
    "output": "A reputation object holding the classification Spamhaus DBL gives the input.",
}
moduleconfig = []

dbl = "dbl.spamhaus.org"
# Spamhaus return code -> (its own wording, the verdict MISP reads).
# 127.0.1.255 is an error rather than a listing, so it has no verdict.
dbl_mapping = {
    "127.0.1.2": ("spam domain", "malicious"),
    "127.0.1.4": ("phish domain", "malicious"),
    "127.0.1.5": ("malware domain", "malicious"),
    "127.0.1.6": ("botnet C&C domain", "malicious"),
    "127.0.1.102": ("abused legit spam", "suspicious"),
    "127.0.1.103": ("abused spammed redirector domain", "suspicious"),
    "127.0.1.104": ("abused legit phish", "suspicious"),
    "127.0.1.105": ("abused legit malware", "suspicious"),
    "127.0.1.106": ("abused legit botnet C&C", "suspicious"),
    "127.0.1.255": ("IP queries prohibited!", None),
}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors
    requested_value = attribute["value"].split("|")[0]

    query = "{}.{}".format(requested_value, dbl)
    try:
        query_result = str(resolver.resolve(query, "A")[0])
    except dns.resolver.NXDOMAIN:
        return {"error": f"{requested_value} is not listed on {dbl}."}
    except Exception as e:
        return {"error": f"Not able to reach {dbl}: {e}"}

    # An unmapped code used to raise KeyError here and be reported as an
    # unreachable dbl.spamhaus.org.
    if query_result not in dbl_mapping:
        return {"error": f"{dbl} answered with the unknown return code {query_result}."}
    wording, classification = dbl_mapping[query_result]
    if classification is None:
        return {"error": f"{dbl} refused the query: {wording}"}

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    # Typed explicitly, since pymisp does not bundle the reputation template
    # yet. Spamhaus's own wording goes in text: MISP reads classification as a
    # verdict, and "phish domain" is not one of the words it knows.
    misp_object = MISPObject("reputation")
    misp_object.add_attribute("classification", **{"type": "text", "value": classification})
    misp_object.add_attribute("source", **{"type": "text", "value": "Spamhaus"})
    misp_object.add_attribute("list-name", **{"type": "text", "value": dbl})
    misp_object.add_attribute("text", **{"type": "text", "value": wording})
    misp_object.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(misp_object)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
