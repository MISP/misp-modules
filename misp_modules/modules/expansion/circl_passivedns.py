import pypdns
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {
    "input": ["hostname", "domain", "ip-src", "ip-dst", "ip-src|port", "ip-dst|port"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.2",
    "author": "Alexandre Dulaunoy",
    "description": "Module to access CIRCL Passive DNS.",
    "module-type": ["expansion", "hover"],
    "name": "CIRCL Passive DNS",
    "logo": "passivedns.png",
    "requirements": [
        "pypdns: Passive DNS python library",
        "A CIRCL passive DNS account with username & password",
    ],
    "features": (
        "This module takes a hostname, domain or ip-address (ip-src or ip-dst) attribute as input, and queries the"
        " CIRCL Passive DNS REST API to get the asssociated passive dns entries and return them as MISP objects.\n\nTo"
        " make it work a username and a password are thus required to authenticate to the CIRCL Passive DNS API."
    ),
    "references": [
        "https://www.circl.lu/services/passive-dns/",
        "https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/",
    ],
    "input": "Hostname, domain, or ip-address attribute.",
    "output": "",
    "ouput": "Passive DNS objects related to the input attribute.",
}
moduleconfig = ["username", "password"]


class PassiveDNSParser:
    def __init__(self, attribute, authentication):
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.attribute)
        self.pdns = pypdns.PyPDNS(basic_auth=authentication)

    def get_results(self):
        if hasattr(self, "result"):
            return self.result
        event = self.misp_event.to_dict()
        results = {key: event[key] for key in ("Attribute", "Object")}
        return {"results": results}

    def parse(self):
        value = self.attribute.value.split("|")[0] if "|" in self.attribute.type else self.attribute.value

        try:
            results = self.pdns.query(value)
        except Exception:
            self.result = {
                "error": "There is an authentication error, please make sure you supply correct credentials."
            }
            return

        if not results:
            self.result = {"error": "Not found"}
            return

        mapping = {
            "count": "counter",
            "origin": "text",
            "rrtype": "text",
            "rrname": "text",
            "rdata": "text",
        }
        for result in results:
            pdns_object = MISPObject("passive-dns")
            for relation, attribute_type in mapping.items():
                pdns_object.add_attribute(relation, result[relation], type=attribute_type)
            first_seen = result["time_first"]
            pdns_object.add_attribute("time_first", first_seen, type="datetime")
            pdns_object.first_seen = first_seen
            last_seen = result["time_last"]
            pdns_object.add_attribute("time_last", last_seen, type="datetime")
            pdns_object.last_seen = last_seen
            pdns_object.add_reference(self.attribute.uuid, "associated-to")
            self.misp_event.add_object(**pdns_object)


def dict_handler(request: dict):
    if not request.get("config"):
        return {"error": "CIRCL Passive DNS authentication is missing."}
    if not request["config"].get("username") or not request["config"].get("password"):
        return {"error": "CIRCL Passive DNS authentication is incomplete, please provide your username and password."}
    authentication = (request["config"]["username"], request["config"]["password"])
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if not any(input_type == attribute["type"] for input_type in mispattributes["input"]):
        return {"error": "Unsupported attribute type."}
    pdns_parser = PassiveDNSParser(attribute, authentication)
    pdns_parser.parse()
    return pdns_parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
