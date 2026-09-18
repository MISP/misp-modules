import json

import dns.resolver
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["hostname", "domain", "domain|ip"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.5",
    "author": "Alexandre Dulaunoy",
    "description": "Simple DNS expansion service to resolve IP address from MISP attributes",
    "module-type": ["expansion", "hover"],
    "name": "DNS Resolver",
    "logo": "",
    "requirements": ["dnspython3: DNS python3 library"],
    "features": (
        "The module takes a domain of hostname attribute as input, and tries to resolve it. If no error is encountered,"
        " the A and AAAA records resolving the domain are returned as a dns-record object, otherwise the origin of the"
        " error is displayed.\n\nThe address of the DNS resolver to use is also configurable, but if no configuration"
        " is set, we use the Google public DNS address (8.8.8.8).\n\nPlease note that composite MISP attributes"
        " containing domain or hostname are supported as well."
    ),
    "references": [],
    "input": "Domain or hostname attribute.",
    "output": "A dns-record object holding the A and AAAA records the input resolves to.",
}

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
    toquery = attribute["value"].split("|")[0] if attribute["type"] == "domain|ip" else attribute["value"]

    r = dns.resolver.Resolver()
    r.timeout = 2
    r.lifetime = 2

    if request.get("config"):
        if request["config"].get("nameserver"):
            nameservers = []
            nameservers.append(request["config"].get("nameserver"))
            r.nameservers = nameservers
    else:
        r.nameservers = ["8.8.8.8"]

    records = {}
    for rdtype, relation in (("A", "a-record"), ("AAAA", "aaaa-record")):
        try:
            records[relation] = [str(record) for record in r.resolve(toquery, rdtype)]
        except dns.resolver.NXDOMAIN:
            misperrors["error"] = "NXDOMAIN"
            return misperrors
        except dns.exception.Timeout:
            misperrors["error"] = "Timeout"
            return misperrors
        except dns.resolver.NoAnswer:
            # The name exists but has no record of this type. A name with no A
            # record may still have a AAAA one, so this is not an error.
            records[relation] = []
        except Exception as e:
            misperrors["error"] = f"DNS resolving error {e}"
            return misperrors

    if not any(records.values()):
        misperrors["error"] = f"No A or AAAA record for {toquery}"
        return misperrors

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    dns_record = MISPObject("dns-record")
    dns_record.add_attribute("queried-domain", toquery)
    # The whole rrset, not just the first entry: a name with several A records
    # is exactly the case the plain attribute could not express.
    for relation, values in records.items():
        for value in values:
            dns_record.add_attribute(relation, value)
    dns_record.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(dns_record)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
