import json
import logging
import sys

from passivetotal.common.utilities import is_ip

log = logging.getLogger("passivetotal")
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "hostname",
        "domain",
        "ip-src",
        "ip-dst",
        "x509-fingerprint-sha1",
        "email-src",
        "email-dst",
        "target-email",
        "whois-registrant-email",
        "whois-registrant-phone",
        "text",
        "whois-registrant-name",
        "whois-registrar",
        "whois-creation-date",
    ],
    "output": [
        "hostname",
        "domain",
        "ip-src",
        "ip-dst",
        "x509-fingerprint-sha1",
        "email-src",
        "email-dst",
        "target-email",
        "whois-registrant-email",
        "whois-registrant-phone",
        "text",
        "whois-registrant-name",
        "whois-registrar",
        "whois-creation-date",
        "md5",
        "sha1",
        "sha256",
        "link",
    ],
}
moduleinfo = {
    "version": "1.0",
    "author": "Brandon Dixon",
    "description": (
        "The PassiveTotal MISP expansion module brings the datasets derived from Internet scanning directly into your"
        " MISP instance. This module supports passive DNS, historic SSL, WHOIS, and host attributes. In order to use"
        " the module, you must have a valid PassiveTotal account username and API key. Registration is free and can be"
        " done by visiting https://www.passivetotal.org/register"
    ),
    "module-type": ["expansion", "hover"],
    "name": "PassiveTotal Lookup",
    "logo": "passivetotal.png",
    "requirements": [
        "Passivetotal python library",
        "An access to the PassiveTotal API (apikey)",
    ],
    "features": (
        "The PassiveTotal MISP expansion module brings the datasets derived from Internet scanning directly into your"
        " MISP instance. This module supports passive DNS, historic SSL, WHOIS, and host attributes. In order to use"
        " the module, you must have a valid PassiveTotal account username and API key. Registration is free and can be"
        " done by visiting https://www.passivetotal.org/register"
    ),
    "references": ["https://www.passivetotal.org/register"],
    "input": (
        "A MISP attribute included in the following list:\n- hostname\n- domain\n- ip-src\n- ip-dst\n-"
        " x509-fingerprint-sha1\n- email-src\n- email-dst\n- target-email\n- whois-registrant-email\n-"
        " whois-registrant-phone\n- text\n- whois-registrant-name\n- whois-registrar\n- whois-creation-date"
    ),
    "output": (
        "MISP attributes mapped from the result of the query on PassiveTotal, included in the following list:\n-"
        " hostname\n- domain\n- ip-src\n- ip-dst\n- x509-fingerprint-sha1\n- email-src\n- email-dst\n- target-email\n-"
        " whois-registrant-email\n- whois-registrant-phone\n- text\n- whois-registrant-name\n- whois-registrar\n-"
        " whois-creation-date\n- md5\n- sha1\n- sha256\n- link"
    ),
}
moduleconfig = ["username", "api_key"]
query_playbook = [
    {
        "inputs": ["ip-src", "ip-dst", "hostname", "domain"],
        "services": ["whois", "ssl", "dns", "enrichment"],
        "name": "generic",
    },
    {
        "inputs": [
            "whois-registrant-email",
            "whois-registrant-phone",
            "whois-registrant-name",
            "email-src",
            "email-dst",
            "target-email",
        ],
        "services": ["whois"],
        "name": "reverse-whois",
    },
    {"inputs": ["x509-fingerprint-sha1"], "services": ["ssl"], "name": "ssl-history"},
]


def query_finder(request):
    """Find the query value in the client request."""
    for item in mispattributes["input"]:
        if not request.get(item, None):
            continue

        playbook = None
        for x in query_playbook:
            if item not in x["inputs"]:
                continue
            playbook = x
            break

        return {"type": item, "value": request.get(item), "playbook": playbook}


def build_profile(request):
    """Check the incoming request for a valid configuration."""
    output = {"success": False}
    config = request.get("config", None)
    if not config:
        misperrors["error"] = "Configuration is missing from the request."
        return output

    for item in moduleconfig:
        if config.get(item, None):
            continue
        misperrors["error"] = "PassiveTotal authentication is missing."
        return output

    profile = {"success": True, "config": config}
    profile.update(query_finder(request))

    return profile


def _generate_request_instance(conf, request_type):
    """Automatically generate a request instance to use.

    In the end, this saves us from having to load each request class in a
    explicit way. Loading via a string is helpful to reduce the code per
    call.

    :param request_type: Type of client to load
    :return: Loaded PassiveTotal client
    """
    pt_username = conf.get("username")
    pt_api_key = conf.get("api_key")

    class_lookup = {
        "dns": "DnsRequest",
        "whois": "WhoisRequest",
        "ssl": "SslRequest",
        "enrichment": "EnrichmentRequest",
        "attributes": "AttributeRequest",
    }
    class_name = class_lookup[request_type]
    mod = __import__("passivetotal.libs.%s" % request_type, fromlist=[class_name])
    loaded = getattr(mod, class_name)
    headers = {"PT-INTEGRATION": "MISP"}
    authenticated = loaded(pt_username, pt_api_key, headers=headers)
    return authenticated


def _has_error(results):
    """Check to see if there's an error in place and log it."""
    if "error" in results:
        msg = "%s - %s" % (
            results["error"]["message"],
            results["error"]["developer_message"],
        )
        misperrors["error"] = msg
        return True

    return False


def process_ssl_details(instance, query):
    """Process details for a specific certificate."""
    log.debug("SSL Details: starting")
    values = list()
    details = instance.get_ssl_certificate_details(query=query)
    err = _has_error(details)
    if err:
        raise Exception("We hit an error, time to bail!")
    if details.get("message") and details["message"].startswith("quota_exceeded"):
        raise Exception("API quota exceeded.")
    values = {value for value in details.values() if value}
    txt = [{"types": ["ssl-cert-attributes"], "values": list(values)}]
    log.debug("SSL Details: ending")

    return txt


def process_ssl_history(instance, query):
    """Process the history for an SSL certificate."""
    log.debug("SSL History: starting")

    type_map = {
        "ip": ["ip-src", "ip-dst"],
        "domain": ["domain", "hostname"],
        "sha1": ["x509-fingerprint-sha1"],
    }

    hits = {"ip": list(), "sha1": list(), "domain": list()}
    history = instance.get_ssl_certificate_history(query=query)
    err = _has_error(history)
    if err:
        raise Exception("We hit an error, time to bail!")
    if history.get("message") and history["message"].startswith("quota_exceeded"):
        raise Exception("API quota exceeded.")
    for item in history.get("results", []):
        hits["ip"] += item.get("ipAddresses", [])
        hits["sha1"].append(item["sha1"])
        hits["domain"] += item.get("domains", [])

    tmp = list()
    for key, value in hits.items():
        txt = {"types": type_map[key], "values": list(set(value))}
        tmp.append(txt)

    log.debug("SSL Details: ending")

    return tmp


def process_whois_details(instance, query):
    """Process the detail from the WHOIS record."""
    log.debug("WHOIS Details: starting")
    tmp = list()
    details = instance.get_whois_details(query=query, compact_record=True)
    err = _has_error(details)
    if err:
        raise Exception("We hit an error, time to bail!")
    if details.get("message") and details["message"].startswith("quota_exceeded"):
        raise Exception("API quota exceeded.")
    if details.get("contactEmail", None):
        tmp.append(
            {
                "types": ["whois-registrant-email"],
                "values": [details.get("contactEmail")],
            }
        )
    phones = details["compact"]["telephone"]["raw"]
    tmp.append({"types": ["whois-registrant-phone"], "values": phones})
    names = details["compact"]["name"]["raw"]
    tmp.append({"types": ["whois-registrant-name"], "values": names})
    if details.get("registrar", None):
        tmp.append({"types": ["whois-registrar"], "values": [details.get("registrar")]})
    if details.get("registered", None):
        tmp.append({"types": ["whois-creation-date"], "values": [details.get("registered")]})
    log.debug("WHOIS Details: ending")

    return tmp


def process_whois_search(instance, query, qtype):
    """Process a WHOIS search for a specific field value."""
    log.debug("WHOIS Search: starting")
    if qtype in ["whois-registrant-email", "email-src", "email-dst", "target-email"]:
        field_type = "email"
    if qtype in ["whois-registrant-phone"]:
        field_type = "phone"
    if qtype in ["whois-registrant-name"]:
        field_type = "name"

    domains = list()
    search = instance.search_whois_by_field(field=field_type, query=query)
    err = _has_error(search)
    if err:
        raise Exception("We hit an error, time to bail!")
    if search.get("message") and search["message"].startswith("quota_exceeded"):
        raise Exception("API quota exceeded.")
    for item in search.get("results", []):
        domain = item.get("domain", None)
        if not domain:
            continue
        domains.append(domain)

    tmp = [{"types": ["hostname", "domain"], "values": list(set(domains))}]
    log.debug("WHOIS Search: ending")

    return tmp


def process_passive_dns(instance, query):
    """Process passive DNS data."""
    log.debug("Passive DNS: starting")
    tmp = list()
    pdns = instance.get_unique_resolutions(query=query)
    err = _has_error(pdns)
    if err:
        raise Exception("We hit an error, time to bail!")
    if pdns.get("message") and pdns["message"].startswith("quota_exceeded"):
        raise Exception("API quota exceeded.")
    if is_ip(query):
        tmp = [{"types": ["domain", "hostname"], "values": pdns.get("results", [])}]
    else:
        tmp = [{"types": ["ip-src", "ip-dst"], "values": pdns.get("results", [])}]
    log.debug("Passive DNS: ending")

    return tmp


def process_osint(instance, query):
    """Process OSINT links."""
    log.debug("OSINT: starting")
    urls = list()
    osint = instance.get_osint(query=query)
    err = _has_error(osint)
    if err:
        raise Exception("We hit an error, time to bail!")
    if osint.get("message") and osint["message"].startswith("quota_exceeded"):
        raise Exception("API quota exceeded.")
    for item in osint.get("results", []):
        urls.append(item["sourceUrl"])

    tmp = [{"types": ["link"], "values": urls}]
    log.debug("OSINT: ending")

    return tmp


def process_malware(instance, query):
    """Process malware samples."""
    log.debug("Malware: starting")
    content = {"hashes": list(), "urls": list()}
    malware = instance.get_malware(query=query)
    err = _has_error(malware)
    if err:
        raise Exception("We hit an error, time to bail!")
    if malware.get("message") and malware["message"].startswith("quota_exceeded"):
        raise Exception("API quota exceeded.")
    for item in malware.get("results", []):
        content["hashes"].append(item["sample"])
        content["urls"].append(item["sourceUrl"])

    tmp = [{"types": ["link"], "values": content["urls"]}]
    hashes = {"md5": list(), "sha1": list(), "sha256": list()}
    for h in content["hashes"]:
        if len(h) == 32:
            hashes["md5"].append(h)
        elif len(h) == 41:
            hashes["sha1"].append(h)
        elif len(h) == 64:
            hashes["sha256"].append(h)
    tmp += [{"types": ["md5"], "values": hashes["md5"]}]
    tmp += [{"types": ["sha1"], "values": hashes["sha1"]}]
    tmp += [{"types": ["sha256"], "values": hashes["sha256"]}]
    log.debug("Malware: ending")

    return tmp


def handler(q=False):
    if not q:
        return q

    request = json.loads(q)
    profile = build_profile(request)
    if not profile["success"]:
        log.error(misperrors["error"])
        return misperrors

    output = {"results": list()}

    instances = dict()
    for service in profile["playbook"]["services"]:
        instances[service] = _generate_request_instance(profile["config"], service)

    play_type = profile["playbook"]["name"]
    query = profile["value"]
    qtype = profile["type"]
    try:
        if play_type == "generic":
            results = process_passive_dns(instances["dns"], query)
            output["results"] += results
            results = process_whois_details(instances["whois"], query)
            output["results"] += results
            results = process_ssl_history(instances["ssl"], query)
            output["results"] += results
            results = process_osint(instances["enrichment"], query)
            output["results"] += results
            results = process_malware(instances["enrichment"], query)
            output["results"] += results
        elif play_type == "reverse-whois":
            results = process_whois_search(instances["whois"], query, qtype)
            output["results"] += results
        elif play_type == "ssl-history":
            results = process_ssl_details(instances["ssl"], query)
            output["results"] += results
            results = process_ssl_history(instances["ssl"], query)
            output["results"] += results
        else:
            log.error("Unsupported query pattern issued.")
    except Exception as e:
        misperrors["error"] = e.__str__()
        return misperrors

    return output


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
