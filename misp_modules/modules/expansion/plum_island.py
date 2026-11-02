from misp_modules.lib.plum_island import COMMON_CONFIG, REFERENCE, PlumError, address, annotation, domain, run

mispattributes = {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
moduleconfig = COMMON_CONFIG + ["hostname"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Plum Island IP History",
    "description": "Retrieve historical scan observations from the Plum Island Discovery API v1.",
    "module-type": ["expansion"],
    "data-source": "external",
    "requirements": ["requests", "pymisp"],
    "features": (
        "Read-only show_ip lookup for IPv4/IPv6. Configure an HTTPS base url and FAB username/password or access_token."
        " hostname selects one requested-hostname group; empty selects IP-only scans. max_results defaults to 25"
        " (1-100), max_pages to 10 (1-20). Optional from_ts/to_ts are UTC epoch seconds. Preserves raw documents, UID"
        " tags, observation times, missing-document warnings and hostname choices in referenced annotations with"
        " to_ids=False. Requires Discovery API v1, added after v0.2610.0. Never schedules scans."
    ),
    "references": [REFERENCE],
    "input": "ip-src or ip-dst attribute containing one IPv4/IPv6 address.",
    "output": "Referenced annotation objects containing scan evidence and pagination completeness.",
}


def _expand(event, source, client, config):
    ip = address(source["value"].strip())
    hostname = config.get("hostname") or ""
    if not isinstance(hostname, str):
        raise PlumError("hostname must be a string.")
    hostname = domain(hostname.strip()) if hostname.strip() else ""
    offset, returned, complete = 0, 0, False
    seen_offsets = set()
    for _ in range(client.max_pages):
        page = client.call(
            "show_ip",
            {"ip": ip, "hostname": hostname, "offset": offset, "limit": client.limit - returned, **client.dates},
        )
        observations = page.get("observations")
        if (
            page.get("ip") != ip
            or page.get("hostname") != hostname
            or not isinstance(observations, list)
            or len(observations) > client.limit - returned
            or not isinstance(page.get("requested_hostnames"), list)
            or type(page.get("total")) is not int
            or page["total"] < 0
            or "next_offset" not in page
        ):
            raise PlumError("Plum Island returned invalid IP observations.")
        for observation in observations:
            if (
                not isinstance(observation, dict)
                or not isinstance(observation.get("uid"), str)
                or not observation["uid"]
            ):
                raise PlumError("Plum Island returned an invalid observation.")
            annotation(
                event,
                source,
                "Plum Island scan observation",
                {"ip": ip, "hostname": hostname, "observation": observation},
            )
        returned += len(observations)
        next_offset = page.get("next_offset")
        if next_offset is None:
            complete = True
            break
        if type(next_offset) is not int or next_offset <= offset or next_offset > 10000 or next_offset in seen_offsets:
            raise PlumError("Plum Island returned invalid observation pagination.")
        seen_offsets.add(next_offset)
        offset = next_offset
        if returned >= client.limit:
            break
    annotation(
        event,
        source,
        "Plum Island IP history summary",
        {
            "ip": ip,
            "hostname": hostname,
            "requested_hostnames": page["requested_hostnames"],
            "total": page["total"],
            "returned": returned,
            "complete": complete,
            "time_range": page.get("time_range"),
            "date_semantics": page.get("date_semantics"),
            "notice": "Historical observations; UID tags apply to the whole scan, not necessarily each port.",
        },
    )


def handler(q=False):
    return run(q, mispattributes["input"], _expand)


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
