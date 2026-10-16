import json

import dns.resolver
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.3",
    "author": "Christian Studer",
    "description": "Module to check an IPv4 address against known RBLs.",
    "module-type": ["expansion", "hover"],
    "name": "Real-time Blackhost Lists Lookup",
    "logo": "",
    "requirements": ["dnspython3: DNS python3 library"],
    "features": (
        "This module takes an IP address attribute as input and queries multiple know Real-time Blackhost Lists to"
        " check if they have already seen this IP address.\n\nEach list that answers produces a reputation object"
        " naming the zone and carrying its TXT record."
    ),
    "references": [
        "[RBLs"
        " list](https://github.com/MISP/misp-modules/blob/8817de476572a10a9c9d03258ec81ca70f3d926d/misp_modules/modules/expansion/rbl.py#L20)"
    ],
    "input": "IP address attribute.",
    "output": "One reputation object per Real-time Blackhost List the IP address is listed on.",
}
moduleconfig = ["timeout"]

rbls = (
    "spam.spamrats.com",
    "spamguard.leadmon.net",
    "rbl-plus.mail-abuse.org",
    "web.dnsbl.sorbs.net",
    "ix.dnsbl.manitu.net",
    "virus.rbl.jp",
    "dul.dnsbl.sorbs.net",
    "bogons.cymru.com",
    "psbl.surriel.com",
    "misc.dnsbl.sorbs.net",
    "httpbl.abuse.ch",
    "combined.njabl.org",
    "smtp.dnsbl.sorbs.net",
    "korea.services.net",
    "drone.abuse.ch",
    "rbl.efnetrbl.org",
    "cbl.anti-spam.org.cn",
    "b.barracudacentral.org",
    "bl.spamcannibal.org",
    "xbl.spamhaus.org",
    "zen.spamhaus.org",
    "rbl.suresupport.com",
    "db.wpbl.info",
    "sbl.spamhaus.org",
    "http.dnsbl.sorbs.net",
    "csi.cloudmark.com",
    "rbl.interserver.net",
    "ubl.unsubscore.com",
    "dnsbl.sorbs.net",
    "virbl.bit.nl",
    "pbl.spamhaus.org",
    "socks.dnsbl.sorbs.net",
    "short.rbl.jp",
    "dnsbl.dronebl.org",
    "blackholes.mail-abuse.org",
    "truncate.gbudb.net",
    "dyna.spamrats.com",
    "spamrbl.imp.ch",
    "spam.dnsbl.sorbs.net",
    "wormrbl.imp.ch",
    "query.senderbase.org",
    "opm.tornevall.org",
    "netblock.pedantic.org",
    "access.redhawk.org",
    "cdl.anti-spam.org.cn",
    "multi.surbl.org",
    "noptr.spamrats.com",
    "dnsbl.inps.de",
    "bl.spamcop.net",
    "cbl.abuseat.org",
    "dsn.rfc-ignorant.org",
    "zombie.dnsbl.sorbs.net",
    "dnsbl.njabl.org",
    "relays.mail-abuse.org",
    "rbl.spamlab.com",
    "all.bl.blocklist.de",
)


# A clean "not listed" answer, as opposed to the resolver itself failing.
_NOT_LISTED = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)


def _parse_listing(zone, records):
    """A listing on a DNSBL zone, as a reputation object.

    Typed explicitly, since pymisp does not bundle the reputation template yet.
    The verdict is suspicious rather than malicious: the zones below are not
    all accusations - bogons.cymru.com is a routing statement - and the zone in
    list-name is what carries the real meaning."""
    misp_object = MISPObject("reputation")
    misp_object.add_attribute("classification", **{"type": "text", "value": "suspicious"})
    misp_object.add_attribute("list-name", **{"type": "text", "value": zone})
    if records:
        misp_object.add_attribute("text", **{"type": "text", "value": "  -  ".join(records)})
    return misp_object


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors
    ip = attribute["value"]

    resolver = dns.resolver.Resolver()
    try:
        timeout = float(request["config"]["timeout"])
    except (KeyError, TypeError, ValueError):
        timeout = 0.4
    resolver.timeout = timeout
    resolver.lifetime = timeout

    infos = {}
    failures = []
    ipRev = ".".join(ip.split(".")[::-1])
    for rbl in rbls:
        query = "{}.{}".format(ipRev, rbl)
        try:
            infos[rbl] = [str(t) for t in resolver.resolve(query, "TXT")]
        except _NOT_LISTED:
            continue
        except Exception as e:
            # Anything else is the resolver failing, not the zone answering
            # "not listed" - worth telling apart from a clean negative.
            failures.append(f"{rbl}: {e}")

    if not infos:
        if len(failures) == len(rbls):
            return {"error": f"Not able to query the RBLs: {failures[0]}"}
        return {"error": "No data found by querying known RBLs"}

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)
    for zone, records in infos.items():
        misp_object = _parse_listing(zone, records)
        misp_object.add_reference(input_attribute.uuid, "related-to")
        misp_event.add_object(misp_object)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
