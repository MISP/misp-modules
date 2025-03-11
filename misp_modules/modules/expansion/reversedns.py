import json

from dns import exception, resolver, reversename

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst", "domain|ip"], "output": ["hostname"]}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "0.1",
    "author": "Andreas Muehlemann",
    "description": "Simple Reverse DNS expansion service to resolve reverse DNS from MISP attributes.",
    "module-type": ["expansion", "hover"],
    "name": "Reverse DNS",
    "logo": "",
    "requirements": ["DNS python library"],
    "features": (
        "The module takes an IP address as input and tries to find the hostname this IP address is resolved"
        " into.\n\nThe address of the DNS resolver to use is also configurable, but if no configuration is set, we use"
        " the Google public DNS address (8.8.8.8).\n\nPlease note that composite MISP attributes containing IP"
        " addresses are supported as well."
    ),
    "references": [],
    "input": "An IP address attribute.",
    "output": "Hostname attribute the input is resolved into.",
}

# config fields that your code expects from the site admin
moduleconfig = ["nameserver"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get("ip-dst"):
        toquery = request["ip-dst"]
    elif request.get("ip-src"):
        toquery = request["ip-src"]
    elif request.get("ip"):
        toquery = request["ip"]
    elif request.get("domain|ip"):
        toquery = request["domain|ip"].split("|")[1]
    else:
        return False

    # reverse lookup for ip
    revname = reversename.from_address(toquery)
    r = resolver.Resolver()
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

    r = {"results": [{"types": mispattributes["output"], "values": [str(answer[0])]}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
