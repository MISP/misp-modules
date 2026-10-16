"""Retrieve existing capture details without triggering external analysis or submissions."""

from ._lookyloo import CAPTURE_CONFIG, CONFIG, Client, LookylooError, Parser, capture_uuid, parse_request

mispattributes = {"input": ["link", "url", "text"], "format": "misp_standard"}
moduleconfig = CONFIG + CAPTURE_CONFIG
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Lookyloo capture",
    "description": "Enrich a Lookyloo capture link or UUID with observed resources and analysis context.",
    "module-type": ["expansion"],
    "requirements": ["requests", "A Lookyloo instance; API key optional", "lookyloo-capture object template (bundled)"],
    "references": ["https://lookyloo.circl.lu/doc/"],
    "features": (
        "Retrieve capture metadata, status, redirects, IPs, hostnames, URLs, SHA-512 hashes, statistics, cached module"
        " results and comparables. Optional cookies, favicons, extended JSON, MISP export and contact lookup. Links to"
        " screenshot and binary exports are returned."
    ),
    "input": "Lookyloo /tree/<uuid> link or a text attribute containing a capture UUID.",
    "output": "lookyloo-capture, url, file, image and optional cookie objects and contact attributes.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        attribute, config = parse_request(q, mispattributes["input"])
        with Client(config) as client:
            identifier = capture_uuid(attribute["value"].strip(), client.base_url)
            parser = Parser(attribute, client)
            parser.enrich(identifier)
            return parser.results()
    except (LookylooError, ValueError, TypeError) as error:
        return {"error": str(error)}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
