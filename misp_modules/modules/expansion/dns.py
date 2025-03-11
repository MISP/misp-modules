import json

import dns.resolver

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["hostname", "domain", "domain|ip"],
    "output": ["ip-src", "ip-dst"],
}
moduleinfo = {
    "version": "0.3",
    "author": "Alexandre Dulaunoy",
    "description": "Simple DNS expansion service to resolve IP address from MISP attributes",
    "module-type": ["expansion", "hover"],
    "name": "DNS Resolver",
    "logo": "",
    "requirements": ["dnspython3: DNS python3 library"],
    "features": (
        "The module takes a domain of hostname attribute as input, and tries to resolve it. If no error is encountered,"
        " the IP address that resolves the domain is returned, otherwise the origin of the error is displayed.\n\nThe"
        " address of the DNS resolver to use is also configurable, but if no configuration is set, we use the Google"
        " public DNS address (8.8.8.8).\n\nPlease note that composite MISP attributes containing domain or hostname are"
        " supported as well."
    ),
    "references": [],
    "input": "Domain or hostname attribute.",
    "output": "IP address resolving the input.",
}

moduleconfig = ["nameserver"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get("hostname"):
        toquery = request["hostname"]
    elif request.get("domain"):
        toquery = request["domain"]
    elif request.get("domain|ip"):
        toquery = request["domain|ip"].split("|")[0]
    else:
        return False
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

    try:
        answer = r.resolve(toquery, "A")
    except dns.resolver.NXDOMAIN:
        misperrors["error"] = "NXDOMAIN"
        return misperrors
    except dns.exception.Timeout:
        misperrors["error"] = "Timeout"
        return misperrors
    except Exception as e:
        misperrors["error"] = f"DNS resolving error {e}"
        return misperrors

    r = {"results": [{"types": mispattributes["output"], "values": [str(answer[0])]}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
