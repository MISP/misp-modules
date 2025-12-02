# -*- coding: utf-8 -*-

import json

from onyphe import Onyphe

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["ip-src", "ip-dst", "hostname", "domain"],
    "output": ["hostname", "domain", "ip-src", "ip-dst", "url"],
}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {
    "version": "1",
    "author": "Sebastien Larinier @sebdraven",
    "description": "Module to process a full query on Onyphe.",
    "module-type": ["expansion", "hover"],
    "name": "Onyphe Full Lookup",
    "logo": "onyphe.jpg",
    "requirements": ["onyphe python library", "An access to the Onyphe API (apikey)"],
    "features": (
        "This module takes a domain, hostname, or IP address attribute as input in order to query the Onyphe API. Data"
        " fetched from the query is then parsed and MISP attributes are extracted.\n\nThe parsing is here more advanced"
        " than the one on onyphe module, and is returning more attributes, since more fields of the query result are"
        " watched and parsed."
    ),
    "references": ["https://www.onyphe.io/", "https://github.com/sebdraven/pyonyphe"],
    "input": "A domain, hostname or IP address MISP attribute.",
    "output": "MISP attributes fetched from the Onyphe query.",
}

# config fields that your code expects from the site admin
moduleconfig = ["apikey"]


def handler(q=False):
    if q:

        request = json.loads(q)

        if not request.get("config") or not request["config"].get("apikey"):
            misperrors["error"] = "Onyphe authentication is missing"
            return misperrors

        api = Onyphe(request["config"].get("apikey"))

        if not api:
            misperrors["error"] = "Onyphe Error instance api"

        ip = ""
        if request.get("ip-src"):
            ip = request["ip-src"]
            return handle_ip(api, ip, misperrors)
        elif request.get("ip-dst"):
            ip = request["ip-dst"]
            return handle_ip(api, ip, misperrors)
        elif request.get("domain"):
            domain = request["domain"]
            return handle_domain(api, domain, misperrors)
        elif request.get("hostname"):
            hostname = request["hostname"]
            return handle_domain(api, hostname, misperrors)
        else:
            misperrors["error"] = "Unsupported attributes type"
            return misperrors
    else:
        return False


def handle_domain(api, domain, misperrors):
    result_filtered = {"results": []}

    r, status_ok = expand_pastries(api, misperrors, domain=domain)

    if status_ok:
        result_filtered["results"].extend(r)
    else:
        misperrors["error"] = "Error pastries result"
        return misperrors

    r, status_ok = expand_datascan(api, misperrors, domain=domain)

    if status_ok:
        result_filtered["results"].extend(r)
    else:
        misperrors["error"] = "Error datascan result "
        return misperrors

    r, status_ok = expand_threatlist(api, misperrors, domain=domain)

    if status_ok:
        result_filtered["results"].extend(r)
    else:
        misperrors["error"] = "Error threat list"
        return misperrors

    return result_filtered


def handle_ip(api, ip, misperrors):
    result_filtered = {"results": []}

    r, status_ok = expand_syscan(api, ip, misperrors)

    if status_ok:
        result_filtered["results"].extend(r)
    else:
        misperrors["error"] = "Error syscan result"

    r, status_ok = expand_pastries(api, misperrors, ip=ip)

    if status_ok:
        result_filtered["results"].extend(r)
    else:
        misperrors["error"] = "Error pastries result"
        return misperrors

    r, status_ok = expand_datascan(api, misperrors, ip=ip)

    if status_ok:
        result_filtered["results"].extend(r)
    else:
        misperrors["error"] = "Error datascan result "
        return misperrors

    r, status_ok = expand_forward(api, ip, misperrors)

    if status_ok:
        result_filtered["results"].extend(r)
    else:
        misperrors["error"] = "Error forward result"
        return misperrors

    r, status_ok = expand_reverse(api, ip, misperrors)

    if status_ok:
        result_filtered["results"].extend(r)
    else:
        misperrors["error"] = "Error reverse result"
        return misperrors

    r, status_ok = expand_threatlist(api, misperrors, ip=ip)

    if status_ok:
        result_filtered["results"].extend(r)
    else:
        misperrors["error"] = "Error threat list"
        return misperrors

    return result_filtered


def expand_syscan(api, ip, misperror):
    status_ok = False
    r = []
    asn_list = []
    os_list = []
    geoloc = []
    orgs = []
    results = api.synscan(ip)

    if results["status"] == "ok":
        status_ok = True
        for elem in results["results"]:
            asn_list.append(elem["asn"])
            os_target = elem["os"]
            geoloc.append(elem["location"])
            orgs.append(elem["organization"])
            if os_target != "Unknown" and os_target != "Undefined":
                os_list.append(elem["os"])

        r.append(
            {
                "types": ["target-machine"],
                "values": list(set(os_list)),
                "categories": ["Targeting data"],
                "comment": "OS found on %s with synscan of Onyphe" % ip,
            }
        )

        r.append(
            {
                "types": ["target-location"],
                "values": list(set(geoloc)),
                "categories": ["Targeting data"],
                "comment": "Geolocalisation of %s found with synscan of Onyphe" % ip,
            }
        )

        r.append(
            {
                "types": ["target-org"],
                "values": list(set(orgs)),
                "categories": ["Targeting data"],
                "comment": "Organisations of %s found with synscan of Onyphe" % ip,
            }
        )

        r.append(
            {
                "types": ["AS"],
                "values": list(set(asn_list)),
                "categories": ["Network activity"],
                "comment": "As number of %s found with synscan of Onyphe" % ip,
            }
        )

    return r, status_ok


def expand_datascan(api, misperror, **kwargs):
    status_ok = False
    r = []
    # ip = ''
    query = ""
    asn_list = []
    geoloc = []
    orgs = []
    ports = []

    if "ip" in kwargs:
        query = kwargs.get("ip")
        results = api.datascan(query)
    else:
        query = kwargs.get("domain")
        results = api.search_datascan("domain:%s" % query)

    if results["status"] == "ok":
        status_ok = True
        for elem in results["results"]:
            asn_list.append(elem["asn"])
            geoloc.append(elem["location"])
            orgs.append(elem["organization"])
            ports.append(elem["port"])

        r.append(
            {
                "types": ["port"],
                "values": list(set(ports)),
                "categories": ["Other"],
                "comment": "Ports of %s found with datascan of Onyphe" % query,
            }
        )

        r.append(
            {
                "types": ["target-location"],
                "values": list(set(geoloc)),
                "categories": ["Targeting data"],
                "comment": "Geolocalisation of %s found with synscan of Onyphe" % query,
            }
        )

        r.append(
            {
                "types": ["target-org"],
                "values": list(set(orgs)),
                "categories": ["Targeting data"],
                "comment": "Organisations of %s found with synscan of Onyphe" % query,
            }
        )

        r.append(
            {
                "types": ["AS"],
                "values": list(set(asn_list)),
                "categories": ["Network activity"],
                "comment": "As number of %s found with synscan of Onyphe" % query,
            }
        )
    return r, status_ok


def expand_reverse(api, ip, misperror):
    status_ok = False
    r = None
    status_ok = False
    r = []
    results = api.reverse(ip)

    domains_reverse = []

    domains = []
    if results["status"] == "ok":
        status_ok = True

    for elem in results["results"]:
        domains_reverse.append(elem["reverse"])
        domains.append(elem["domain"])

    r.append(
        {
            "types": ["domain"],
            "values": list(set(domains)),
            "categories": ["Network activity"],
            "comment": "Domains of %s from forward service of Onyphe" % ip,
        }
    )

    r.append(
        {
            "types": ["domain"],
            "values": list(set(domains_reverse)),
            "categories": ["Network activity"],
            "comment": "Reverse Domains of %s from forward service of Onyphe" % ip,
        }
    )
    return r, status_ok


def expand_forward(api, ip, misperror):
    status_ok = False
    r = []
    results = api.forward(ip)

    domains_forward = []

    domains = []
    if results["status"] == "ok":
        status_ok = True

    for elem in results["results"]:
        domains_forward.append(elem["forward"])
        domains.append(elem["domain"])

    r.append(
        {
            "types": ["domain"],
            "values": list(set(domains)),
            "categories": ["Network activity"],
            "comment": "Domains of %s from forward service of Onyphe" % ip,
        }
    )

    r.append(
        {
            "types": ["domain"],
            "values": list(set(domains_forward)),
            "categories": ["Network activity"],
            "comment": "Forward Domains of %s from forward service of Onyphe" % ip,
        }
    )
    return r, status_ok


def expand_pastries(api, misperror, **kwargs):
    status_ok = False
    r = []

    query = None
    result = None
    urls_pasties = []
    domains = []
    ips = []
    if "ip" in kwargs:
        query = kwargs.get("ip")
        result = api.pastries(query)
    if "domain" in kwargs:
        query = kwargs.get("domain")
        result = api.search_pastries("domain:%s" % query)

    if result["status"] == "ok":
        status_ok = True
        for item in result["results"]:
            if item["@category"] == "pastries":
                if item["source"] == "pastebin":
                    urls_pasties.append("https://pastebin.com/raw/%s" % item["key"])

                    if "domain" in item:
                        domains.extend(item["domain"])
                    if "ip" in item:
                        ips.extend(item["ip"])
                    if "hostname" in item:
                        domains.extend(item["hostname"])

        r.append(
            {
                "types": ["url"],
                "values": urls_pasties,
                "categories": ["External analysis"],
                "comment": "URLs of pasties where %s has found" % query,
            }
        )
        r.append(
            {
                "types": ["domain"],
                "values": list(set(domains)),
                "categories": ["Network activity"],
                "comment": "Domains found in pasties of Onyphe",
            }
        )

        r.append(
            {
                "types": ["ip-dst"],
                "values": list(set(ips)),
                "categories": ["Network activity"],
                "comment": "IPs found in pasties of Onyphe",
            }
        )

    return r, status_ok


def expand_threatlist(api, misperror, **kwargs):
    status_ok = False
    r = []

    query = None

    threat_list = []

    if "ip" in kwargs:
        query = kwargs.get("ip")
        results = api.threatlist(query)
    else:
        query = kwargs.get("domain")
        results = api.search_threatlist("domain:%s" % query)

    if results["status"] == "ok":
        status_ok = True
        threat_list = ["seen %s on %s " % (item["seen_date"], item["threatlist"]) for item in results["results"]]

        r.append(
            {
                "types": ["comment"],
                "categories": ["Other"],
                "values": threat_list,
                "comment": "%s is present in threatlist" % query,
            }
        )

    return r, status_ok


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
