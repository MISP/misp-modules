from misp_modules.lib.plum_island import COMMON_CONFIG, REFERENCE, PlumError, address, annotation, run, search_query

mispattributes = {
    "input": [
        "ip-src",
        "ip-dst",
        "domain",
        "hostname",
        "x509-fingerprint-md5",
        "x509-fingerprint-sha1",
        "x509-fingerprint-sha256",
    ],
    "format": "misp_standard",
}
moduleconfig = COMMON_CONFIG.copy()
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Plum Island Search",
    "description": "Find IPs observed with a domain, hostname, network or certificate fingerprint in Plum Island.",
    "module-type": ["expansion"],
    "data-source": "external",
    "requirements": ["requests", "pymisp"],
    "features": (
        "Uses read-only structured Discovery search, including requested and observed domain/hostname fields."
        " IP attributes may contain CIDRs. Certificate fingerprints use x509 indexes, not file hash indexes."
        " Configure HTTPS url and FAB username/password or access_token. max_results defaults to 25 (1-100),"
        " max_pages to 10 (1-20). Optional from_ts/to_ts are UTC epoch seconds; otherwise Plum defaults to the last"
        " three calendar months. Follows signed cursors across empty windows. Returns IP pivots with to_ids=False"
        " and referenced evidence annotations. Reports incomplete searches when either budget is reached."
        " Requires Discovery API v1, added after v0.2610.0."
    ),
    "references": [REFERENCE],
    "input": "IP/CIDR, domain, hostname or x509-fingerprint-md5/sha1/sha256 attribute.",
    "output": "IP destination attributes and referenced annotations with matching UIDs, timestamps and search scope.",
}


def _expand(event, source, client, config):
    query = search_query(source)
    payload = {"query": query, "limit": client.limit, **client.dates}
    found, cursors, complete = set(), set(), False
    for _ in range(client.max_pages):
        page = client.call("search", payload)
        matches = page.get("results")
        if (
            page.get("status") is not True
            or not isinstance(matches, dict)
            or len(matches) > payload["limit"]
            or "next_cursor" not in page
        ):
            raise PlumError("Plum Island returned invalid search results.")
        for ip, uids in matches.items():
            ip = address(ip)
            if not isinstance(uids, list) or not all(isinstance(uid, str) for uid in uids):
                raise PlumError("Plum Island returned invalid matching UIDs.")
            if ip not in found:
                event.add_attribute("ip-dst", ip, to_ids=False, comment="Historical Plum Island search match: " + query)
                found.add(ip)
        # Signed cursors contain private server state and must not be exported into MISP.
        evidence = {
            key: page[key]
            for key in ("results", "timestamps", "requested_hostnames", "time_range", "date_semantics")
            if key in page
        }
        annotation(event, source, "Plum Island search evidence", {"query": query, **evidence})
        cursor = page.get("next_cursor")
        if cursor is None:
            complete = True
            break
        if not isinstance(cursor, str) or not cursor or cursor in cursors:
            raise PlumError("Plum Island returned invalid search pagination.")
        cursors.add(cursor)
        if len(found) >= client.limit:
            break
        payload = {"cursor": cursor, "limit": client.limit - len(found)}
    annotation(
        event,
        source,
        "Plum Island search summary",
        {
            "query": query,
            "returned": len(found),
            "complete": complete,
            "notice": (
                "Historical last_seen-window discovery; a match does not prove current exposure or maliciousness."
            ),
        },
    )


def handler(q=False):
    return run(q, mispattributes["input"], _expand)


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
