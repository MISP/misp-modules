"""Pivot from MISP observables to existing Lookyloo captures."""

import ipaddress

from ._lookyloo import (
    CAPTURE_CONFIG,
    CONFIG,
    Client,
    LookylooError,
    Parser,
    boolean,
    integer,
    parse_request,
    sha512,
    valid_url,
)

mispattributes = {
    "input": ["ip-src", "ip-dst", "domain|ip", "domain", "hostname", "url", "sha512", "filename|sha512"],
    "format": "misp_standard",
}
moduleconfig = CONFIG + CAPTURE_CONFIG + ["limit", "offset", "hash_lookup", "enrich_captures", "max_captures"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Lookyloo lookup",
    "description": "Find Lookyloo captures containing an IP, hostname, URL, resource hash or favicon hash.",
    "module-type": ["expansion"],
    "requirements": ["requests", "A Lookyloo instance; API key optional", "lookyloo-capture object template (bundled)"],
    "references": ["https://lookyloo.circl.lu/doc/"],
    "features": (
        "Pivot on existing captures using ip_info, hostname_info, url_info, hash_info and favicon_info. Optionally"
        " enrich matching captures. All new attributes use to_ids=false."
    ),
    "input": "IPv4/IPv6, domain, hostname, URL or SHA-512 attribute.",
    "output": "Related lookyloo-capture objects and observed URL/file objects, with optional capture enrichment.",
}


def handler(q=False):
    if q is False:
        return False
    try:
        attribute, config = parse_request(q, mispattributes["input"])
        value, type_ = attribute["value"].strip(), attribute["type"]
        if type_ in ("ip-src", "ip-dst", "domain|ip"):
            value = str(ipaddress.ip_address(value.rsplit("|", 1)[-1]))
            searches = [("ip_info", "ip")]
        elif type_ in ("sha512", "filename|sha512"):
            value = value.rsplit("|", 1)[-1].lower()
            if not sha512(value):
                raise LookylooError("Lookyloo hash lookups require a SHA-512 hash.")
            mode = config.get("hash_lookup") or "resource"
            if mode not in ("resource", "favicon", "both"):
                raise LookylooError("hash_lookup must be resource, favicon or both.")
            searches = []
            if mode in ("resource", "both"):
                searches.append(("hash_info", "body_hash"))
            if mode in ("favicon", "both"):
                searches.append(("favicon_info", "favicon"))
        elif type_ == "url":
            if not valid_url(value):
                raise LookylooError("Expected an HTTP(S) URL.")
            searches = [("url_info", "url")]
        else:
            if any(char.isspace() for char in value) or any(char in value for char in "/:@|"):
                raise LookylooError("Expected a hostname or domain.")
            searches = [("hostname_info", "hostname")]
        limit = integer(config, "limit", 20, 1, 100)
        offset = integer(config, "offset", 0, 0, 1000000)
        enrich = boolean(config, "enrich_captures")
        max_captures = integer(config, "max_captures", 5, 1, 10)
        with Client(config) as client:
            parser = Parser(attribute, client)
            for endpoint, key in searches:
                payload = {key: value, "limit": limit, "offset": offset, "cached_captures_only": True}
                if endpoint != "favicon_info":
                    payload["with_urls_occurrences"] = True
                result = client.request(f"/json/{endpoint}", payload=payload)
                parser.occurrences(result, endpoint, limit)
            if enrich:
                for index, (identifier, obj) in enumerate(list(parser.captures.items())):
                    if index >= max_captures:
                        parser.note(
                            obj, "Capture details skipped by max_captures; use lookyloo_capture to retrieve them."
                        )
                        continue
                    try:
                        parser.enrich(identifier)
                    except LookylooError as error:
                        parser.add(obj, "error", str(error), comment="info")
            return parser.results()
    except (LookylooError, ValueError, TypeError) as error:
        return {"error": str(error)}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
