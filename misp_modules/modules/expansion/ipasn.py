# -*- coding: utf-8 -*-

import json

from pyipasnhistory import IPASNHistory
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst", "ip"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.3",
    "author": "Raphaël Vinot",
    "description": "Module to query an IP ASN history service (https://github.com/D4-project/IPASN-History).",
    "module-type": ["expansion", "hover"],
    "name": "IPASN-History Lookup",
    "logo": "",
    "requirements": ["pyipasnhistory: Python library to access IPASN-history instance"],
    "features": (
        "This module takes an IP address attribute as input and queries the CIRCL IPASN service. The result of the"
        " query is the latest asn related to the IP address, that is returned as a MISP object."
    ),
    "references": ["https://github.com/D4-project/IPASN-History"],
    "input": "An IP address MISP attribute.",
    "output": "Asn object(s) objects related to the IP address used as input.",
}
moduleconfig = ["custom_api"]


def parse_result(attribute, values):
    event = MISPEvent()
    initial_attribute = MISPAttribute()
    initial_attribute.from_dict(**attribute)
    event.add_attribute(**initial_attribute)
    mapping = {"asn": ("AS", "asn"), "prefix": ("ip-src", "subnet-announced")}
    for last_seen, response in values["response"].items():
        asn = MISPObject("asn")
        asn.add_attribute("last-seen", **{"type": "datetime", "value": last_seen})
        for feature, attribute_fields in mapping.items():
            attribute_type, object_relation = attribute_fields
            asn.add_attribute(object_relation, **{"type": attribute_type, "value": response[feature]})
        asn.add_reference(initial_attribute.uuid, "related-to")
        event.add_object(**asn)
    event = json.loads(event.to_json())
    return {key: event[key] for key in ("Attribute", "Object")}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if request["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    if request["attribute"]["type"] == "ip":
        request["attribute"]["type"] = "ip-src"

    toquery = request["attribute"]["value"]

    ipasn_url = request["config"].get("custom_api") or "https://ipasnhistory.circl.lu/"

    ipasn = IPASNHistory(root_url=ipasn_url)
    values = ipasn.query(toquery)

    if not values:
        misperrors["error"] = "Unable to find the history of this IP"
        return misperrors
    return {"results": parse_result(request["attribute"], values)}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
