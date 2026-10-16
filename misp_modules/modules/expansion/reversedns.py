import json

from dns import exception, resolver, reversename
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["ip-src", "ip-dst", "domain|ip"],
    "format": "misp_standard",
}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "0.2",
    "author": "Andreas Muehlemann",
    "description": "Simple Reverse DNS expansion service to resolve reverse DNS from MISP attributes.",
    "module-type": ["expansion", "hover"],
    "name": "Reverse DNS",
    "logo": "",
    "requirements": ["DNS python library"],
    "features": (
        "The module takes an IP address as input and tries to find the hostnames this IP address is resolved"
        " into, returned as a dns-record object.\n\nThe address of the DNS resolver to use is also configurable, but if"
        " no configuration is set, we use the Google public DNS address (8.8.8.8).\n\nPlease note that composite MISP"
        " attributes containing IP addresses are supported as well."
    ),
    "references": [],
    "input": "An IP address attribute.",
    "output": "A dns-record object holding the PTR records the input resolves to.",
}

# config fields that your code expects from the site admin
moduleconfig = ["nameserver"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    toquery = attribute["value"].split("|")[1] if attribute["type"] == "domain|ip" else attribute["value"]

    # reverse lookup for ip
    try:
        revname = reversename.from_address(toquery)
    except Exception:
        return {"error": f"{toquery} is not a valid IP address."}
    r = resolver.Resolver()
    r.timeout = 2
    r.lifetime = 2
    r.nameservers = [(request.get("config") or {}).get("nameserver") or "8.8.8.8"]

    try:
        answer = r.resolve(revname, "PTR")
    except resolver.NXDOMAIN:
        misperrors["error"] = "NXDOMAIN"
        return misperrors
    except exception.Timeout:
        misperrors["error"] = "Timeout"
        return misperrors
    except Exception:
        misperrors["error"] = "DNS resolving error"
        return misperrors

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    dns_record = MISPObject("dns-record")
    # The name actually asked for, so the object says what was queried.
    dns_record.add_attribute("queried-domain", str(revname).rstrip("."))
    for record in answer:
        dns_record.add_attribute("ptr-record", str(record).rstrip("."))
    dns_record.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(dns_record)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
