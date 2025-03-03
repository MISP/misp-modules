import json
import sys

original_path = sys.path
sys.path = original_path[1:]
import dns.resolver

sys.path = original_path
resolver = dns.resolver.Resolver()
resolver.timeout = 0.2
resolver.lifetime = 0.2


misperrors = {"error": "Error"}
mispattributes = {
    "input": ["domain", "domain|ip", "hostname", "hostname|port"],
    "output": ["text"],
}
moduleinfo = {
    "version": "0.1",
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
    "output": "Information about the nature of the input.",
}
moduleconfig = []

dbl = "dbl.spamhaus.org"
dbl_mapping = {
    "127.0.1.2": "spam domain",
    "127.0.1.4": "phish domain",
    "127.0.1.5": "malware domain",
    "127.0.1.6": "botnet C&C domain",
    "127.0.1.102": "abused legit spam",
    "127.0.1.103": "abused spammed redirector domain",
    "127.0.1.104": "abused legit phish",
    "127.0.1.105": "abused legit malware",
    "127.0.1.106": "abused legit botnet C&C",
    "127.0.1.255": "IP queries prohibited!",
}


def fetch_requested_value(request):
    for attribute_type in mispattributes["input"]:
        if request.get(attribute_type):
            return request[attribute_type].split("|")[0]
    return None


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    requested_value = fetch_requested_value(request)
    if requested_value is None:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors
    query = "{}.{}".format(requested_value, dbl)
    try:
        query_result = resolver.resolve(query, "A")[0]
        result = "{} - {}".format(requested_value, dbl_mapping[str(query_result)])
    except dns.resolver.NXDOMAIN as e:
        result = e.msg
    except Exception:
        return {"error": "Not able to reach dbl.spamhaus.org or something went wrong"}
    return {"results": [{"types": mispattributes.get("output"), "values": result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
