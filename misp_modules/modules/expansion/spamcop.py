import ipaddress
import json
import math

import dns.exception
import dns.resolver
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.1",
    "author": "MISP Project",
    "description": "Check an IPv4 address against the SpamCop Blocking List (SCBL).",
    "module-type": ["expansion", "hover"],
    "name": "SpamCop Lookup",
    "logo": "",
    "requirements": ["dnspython"],
    "features": (
        "Queries bl.spamcop.net using the reversed IPv4 address and accepts the documented 127.0.0.2 A record as a"
        " listing. A positive result produces a suspicious reputation object linked to the input attribute, with"
        " a SpamCop lookup URL. An address that is not listed produces an informational error, not a benign verdict."
        " DNS failures and unexpected response codes are reported separately. No API key is required. The optional"
        " timeout setting is a positive number of seconds (default: 5). IPv6 addresses are not supported."
    ),
    "references": [
        "https://www.spamcop.net/fom-serve/cache/351.html",
        "https://www.spamcop.net/fom-serve/cache/291.html",
    ],
    "input": "An ip-src or ip-dst attribute containing an IPv4 address.",
    "output": "A reputation object describing a SpamCop listing and referencing the original IP attribute.",
}
moduleconfig = ["timeout"]

BLOCKLIST = "bl.spamcop.net"
LISTED_CODE = "127.0.0.2"
DEFAULT_TIMEOUT = 5.0


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "The request must be a JSON object."}
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    try:
        if not isinstance(attribute["value"], str):
            raise ValueError
        ip = ipaddress.ip_address(attribute["value"])
    except ValueError:
        return {"error": "A valid IPv4 address is required."}
    if ip.version != 4:
        return {"error": "SpamCop lookups support IPv4 addresses only."}

    config = request.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        return {"error": "The config field must be a JSON object."}
    try:
        configured_timeout = config.get("timeout")
        timeout = DEFAULT_TIMEOUT if configured_timeout in (None, "") else float(configured_timeout)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        return {"error": "The timeout must be a positive, finite number of seconds."}

    query = f"{'.'.join(str(ip).split('.')[::-1])}.{BLOCKLIST}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        codes = {str(record) for record in resolver.resolve(query, "A")}
    except dns.resolver.NXDOMAIN:
        return {"error": f"{ip} is not listed on {BLOCKLIST}."}
    except dns.exception.DNSException as error:
        return {"error": f"Unable to query {BLOCKLIST}: {error}"}
    if codes != {LISTED_CODE}:
        return {
            "error": f"{BLOCKLIST} returned an unexpected A response: {', '.join(sorted(codes)) or 'empty answer'}."
        }

    event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    event.add_attribute(**input_attribute)

    # Explicit types also support PyMISP versions without the reputation template.
    reputation = MISPObject("reputation")
    reputation.add_attribute("classification", type="text", value="suspicious")
    reputation.add_attribute("source", type="text", value="SpamCop")
    reputation.add_attribute("list-name", type="text", value=BLOCKLIST)
    reputation.add_attribute("text", type="text", value=f"{ip} is listed on the SpamCop Blocking List ({LISTED_CODE}).")
    reputation.add_attribute("link", type="link", value=f"https://www.spamcop.net/bl.shtml?{ip}")
    reputation.add_reference(input_attribute.uuid, "related-to")
    event.add_object(reputation)

    result = json.loads(event.to_json())
    return {"results": {key: result[key] for key in ("Attribute", "Object") if result.get(key)}}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
