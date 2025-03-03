import json
from datetime import datetime

import dnsdb2
from pymisp import Distribution, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
standard_query_input = ["hostname", "domain", "ip-src", "ip-dst"]
flex_query_input = [
    "btc",
    "dkim",
    "email",
    "email-src",
    "email-dst",
    "domain|ip",
    "hex",
    "mac-address",
    "mac-eui-64",
    "other",
    "pattern-filename",
    "target-email",
    "text",
    "uri",
    "url",
    "whois-registrant-email",
]
mispattributes = {
    "input": standard_query_input + flex_query_input,
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.5",
    "author": "Christophe Vandeplas",
    "description": "Module to access Farsight DNSDB Passive DNS.",
    "module-type": ["expansion", "hover"],
    "name": "Farsight DNSDB Lookup",
    "logo": "farsight.png",
    "requirements": ["An access to the Farsight Passive DNS API (apikey)"],
    "features": (
        "This module takes a domain, hostname or IP address MISP attribute as input to query the Farsight Passive DNS"
        " API.\n  The results of rdata and rrset lookups are then returned and parsed into passive-dns objects.\n\nAn"
        " API key is required to submit queries to the API.\n  It is also possible to define a custom server URL, and"
        " to set a limit of results to get.\n  This limit is set for each lookup, which means we can have an up to the"
        " limit number of passive-dns objects resulting from an rdata query about an IP address, but an up to the limit"
        " number of passive-dns objects for each lookup queries about a domain or a hostname (== twice the limit)."
    ),
    "references": [
        "https://www.farsightsecurity.com/",
        "https://docs.dnsdb.info/dnsdb-api/",
    ],
    "input": "A domain, hostname or IP address MISP attribute.",
    "output": "Passive-dns objects, resulting from the query on the Farsight Passive DNS API.",
}
moduleconfig = ["apikey", "server", "limit", "flex_queries"]

DEFAULT_DNSDB_SERVER = "https://api.dnsdb.info"
DEFAULT_LIMIT = 10
DEFAULT_DISTRIBUTION_SETTING = Distribution.your_organisation_only.value
TYPE_TO_FEATURE = {
    "btc": "Bitcoin address",
    "dkim": "domainkeys identified mail",
    "domain": "domain name",
    "domain|ip": "domain name / IP address",
    "hex": "value in hexadecimal format",
    "hostname": "hostname",
    "mac-address": "MAC address",
    "mac-eui-64": "MAC EUI-64 address",
    "pattern-filename": "pattern in the name of a file",
    "target-email": "attack target email",
    "uri": "Uniform Resource Identifier",
    "url": "Uniform Resource Locator",
    "whois-registrant-email": "email of a domain's registrant",
}
TYPE_TO_FEATURE.update(dict.fromkeys(("ip-src", "ip-dst"), "IP address"))
TYPE_TO_FEATURE.update(dict.fromkeys(("email", "email-src", "email-dst"), "email address"))
TYPE_TO_FEATURE.update(dict.fromkeys(("other", "text"), "text"))


class FarsightDnsdbParser:
    def __init__(self, attribute):
        self.attribute = attribute
        self.misp_event = MISPEvent()
        self.misp_event.add_attribute(**attribute)
        self.passivedns_mapping = {
            "bailiwick": {"type": "domain", "object_relation": "bailiwick"},
            "count": {"type": "counter", "object_relation": "count"},
            "raw_rdata": {"type": "text", "object_relation": "raw_rdata"},
            "rdata": {"type": "text", "object_relation": "rdata"},
            "rrname": {"type": "text", "object_relation": "rrname"},
            "rrtype": {"type": "text", "object_relation": "rrtype"},
            "time_first": {"type": "datetime", "object_relation": "time_first"},
            "time_last": {"type": "datetime", "object_relation": "time_last"},
            "zone_time_first": {
                "type": "datetime",
                "object_relation": "zone_time_first",
            },
            "zone_time_last": {"type": "datetime", "object_relation": "zone_time_last"},
        }
        self.comment = "Result from a %s lookup on DNSDB about the %s: %s"

    def parse_passivedns_results(self, query_response):
        for query_type, results in query_response.items():
            comment = self.comment % (
                query_type,
                TYPE_TO_FEATURE[self.attribute["type"]],
                self.attribute["value"],
            )
            for result in results:
                passivedns_object = MISPObject("passive-dns")
                passivedns_object.distribution = DEFAULT_DISTRIBUTION_SETTING
                if result.get("rdata") and isinstance(result["rdata"], list):
                    for rdata in result.pop("rdata"):
                        passivedns_object.add_attribute(**self._parse_attribute(comment, "rdata", rdata))
                for feature, value in result.items():
                    passivedns_object.add_attribute(**self._parse_attribute(comment, feature, value))
                if result.get("time_first"):
                    passivedns_object.first_seen = result["time_first"]
                if result.get("time_last"):
                    passivedns_object.last_seen = result["time_last"]
                passivedns_object.add_reference(self.attribute["uuid"], "related-to")
                self.misp_event.add_object(passivedns_object)

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object")}
        return {"results": results}

    def _parse_attribute(self, comment, feature, value):
        attribute = {
            "value": value,
            "comment": comment,
            "distribution": DEFAULT_DISTRIBUTION_SETTING,
        }
        attribute.update(self.passivedns_mapping[feature])
        return attribute


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("config") or not request["config"].get("apikey"):
        misperrors["error"] = "Farsight DNSDB apikey is missing"
        return misperrors
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attributes type"}
    config = request["config"]
    if not config.get("server"):
        config["server"] = DEFAULT_DNSDB_SERVER
    client_args = {feature: config[feature] for feature in ("apikey", "server")}
    client = dnsdb2.Client(**client_args)
    to_query, args = parse_input(attribute, config)
    try:
        response = to_query(client, *args)
    except dnsdb2.DnsdbException as e:
        return {"error": e.__str__()}
    except dnsdb2.exceptions.QueryError:
        return {
            "error": (
                "Communication error occurs while executing a query, or the server reports an error due to invalid"
                " arguments."
            )
        }
    if not response:
        return {
            "error": (
                f"Empty results on Farsight DNSDB for the {TYPE_TO_FEATURE[attribute['type']]}: {attribute['value']}."
            )
        }
    parser = FarsightDnsdbParser(attribute)
    parser.parse_passivedns_results(response)
    return parser.get_results()


def parse_input(attribute, config):
    lookup_args = {
        "limit": config["limit"] if config.get("limit") else DEFAULT_LIMIT,
        "offset": 0,
        "ignore_limited": True,
        "humantime": True,
    }
    if attribute.get("first_seen"):
        lookup_args["time_first_after"] = parse_timestamp(attribute["first_seen"])
    attribute_type = attribute["type"]
    if attribute_type in flex_query_input:
        return flex_queries, (lookup_args, attribute["value"])
    flex = add_flex_queries(config.get("flex_queries"))
    to_query = lookup_ip if "ip-" in attribute_type else lookup_name
    return to_query, (lookup_args, attribute["value"], flex)


def parse_timestamp(str_date):
    datetime_date = datetime.strptime(str_date, "%Y-%m-%dT%H:%M:%S.%f%z")
    return str(int(datetime_date.timestamp()))


def add_flex_queries(flex):
    if not flex:
        return False
    if flex in ("True", "true", True, "1", 1):
        return True
    return False


def flex_queries(client, lookup_args, name):
    response = {}
    name = name.replace("@", ".")
    for feature in ("rdata", "rrnames"):
        to_call = getattr(client, f"flex_{feature}_regex")
        results = list(to_call(name, **lookup_args))
        for result in list(to_call(name.replace(".", "\\."), **lookup_args)):
            if result not in results:
                results.append(result)
        if results:
            response[f"flex_{feature}"] = results
    return response


def lookup_name(client, lookup_args, name, flex):
    response = {}
    # RRSET = entries in the left-hand side of the domain name related labels
    rrset_response = list(client.lookup_rrset(name, **lookup_args))
    if rrset_response:
        response["rrset"] = rrset_response
    # RDATA = entries on the right-hand side of the domain name related labels
    rdata_response = list(client.lookup_rdata_name(name, **lookup_args))
    if rdata_response:
        response["rdata"] = rdata_response
    if flex:
        response.update(flex_queries(client, lookup_args, name))
    return response


def lookup_ip(client, lookup_args, ip, flex):
    response = {}
    res = list(client.lookup_rdata_ip(ip, **lookup_args))
    if res:
        response["rdata"] = res
    if flex:
        response.update(flex_queries(client, lookup_args, ip))
    return response


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
