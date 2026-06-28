"""rst_ioc — enrich an indicator with RST threat intel (GET /ioc)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import rstapi

from ._rstcloud.client import (
    apply_to_source_attribute,
    error,
    host_only,
    misp_event_with_source,
    new_enrichment_object,
    rst_kwargs,
    rst_resolver_from_config,
    scan_group,
    standard_results,
    text_result,
    threat_tags,
    unwrap,
    value_from_request,
)

misperrors = {"error": "Error"}

_INPUTS = [
    "ip-src",
    "ip-dst",
    "domain",
    "hostname",
    "url",
    "md5",
    "sha1",
    "sha256",
    "ip-src|port",
    "ip-dst|port",
    "hostname|port",
    "domain|port",
]
mispattributes = {"input": _INPUTS, "format": "misp_standard"}

moduleinfo = {
    "version": "0.4",
    "author": "RST Cloud",
    "description": (
        "Enrich indicators with RST Cloud threat intelligence. Returns an"
        " rst-ioc object (score, attribution, geo/ASN for IPs, DNS/WHOIS"
        " for domains, parsed components for URLs, related hashes for file"
        " hashes) linked back to the enriched attribute."
    ),
    "module-type": ["expansion", "hover"],
    "name": "RST Cloud IoC Lookup",
    "requirements": ["An RST Cloud API key.", "rstapi>=1.2.0 (PyPI)."],
    "features": (
        "Queries RST Cloud GET /ioc for threat scores, attribution,"
        " geo/ASN, DNS, WHOIS, TTPs, CVEs, and related indicators. Returns"
        " a structured rst-ioc MISP object with galaxy tags and optional"
        " pivotable related hashes/IPs. When misp_url and misp_key are"
        " configured, also writes score/threat tags onto the enriched"
        " attribute via the MISP API."
    ),
    "references": [
        "https://api.rstcloud.net/",
        "https://pypi.org/project/rstapi/",
    ],
    "input": (
        "IP, domain, hostname, URL, or hash attribute (incl. host|port"
        " composites)."
    ),
    "output": (
        "rst-ioc MISP object, galaxy/score tags, and optional related"
        " attributes."
    ),
}
# misp_url/misp_key (optional): when set, tags + score note are also written
# directly onto the enriched attribute via the MISP API (like rst_noise).
moduleconfig = [
    "api_key",
    "base_url",
    "misp_url",
    "misp_key",
    "misp_verifycert",
]

_HASH_TYPES = {"md5", "sha1", "sha256"}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def _ts(val) -> str:
    """Unix timestamp string/int -> YYYY-MM-DD (UTC), or empty string."""
    try:
        return datetime.fromtimestamp(int(val), tz=timezone.utc).strftime(
            "%Y-%m-%d"
        )
    except (TypeError, ValueError, OSError):
        return ""


def _f(val, precision=1) -> str:
    try:
        return f"{float(val):.{precision}f}"
    except (TypeError, ValueError):
        return ""


def _known(v) -> bool:
    return bool(v) and str(v).strip().lower() not in (
        "",
        "none",
        "null",
        "n/a",
    )


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    config = request.get("config")
    if not rst_kwargs(config)["APIKEY"]:
        return error(
            "An RST Cloud API key is required (set api_key in the module"
            " config)."
        )
    value = host_only(value_from_request(request, _INPUTS))
    if not value:
        return error("No supported indicator value found in the request.")

    # /ioc always returns HTTP 200; a miss carries an "error" key and no "id".
    data, err = unwrap(
        rstapi.ioclookup(**rst_kwargs(config)).GetIndicator(value)
    )
    if err:
        return error(f"RST Cloud lookup failed: {err}")
    if not isinstance(data, dict) or data.get("error") or not data.get("id"):
        return text_result(
            f"{value}: not found in RST Cloud", "RST IoC Lookup"
        )

    ioc_type = (data.get("ioc_type") or "").lower()
    is_ip = ioc_type in ("ipv4", "ipv6")
    is_domain = ioc_type == "domain"
    is_url = ioc_type == "url"
    is_hash = ioc_type in _HASH_TYPES

    score_block = data.get("score") or {}
    total = score_block.get("total")
    try:
        total_int = int(float(str(total)))
    except (TypeError, ValueError):
        total_int = None
    conf_sub = _f(score_block.get("tags"), 2)  # context sub-score
    relev_sub = _f(score_block.get("frequency"), 2)  # relevance sub-score

    threats = data.get("threat") or []
    tags_str = (data.get("tags") or {}).get("str") or []
    ttp = data.get("ttp") or []
    cve = data.get("cve") or []
    industry = data.get("industry") or []
    fp = data.get("fp") or {}
    fp_alarm = str(fp.get("alarm") or "").strip().lower()
    fp_flagged = fp_alarm in ("true", "possible")
    geo = data.get("geo") or {}
    asn_blk = data.get("asn") or {}
    src_blk = data.get("src") or {}
    resolved = data.get("resolved") or {}
    parsed = data.get("parsed") or {}
    fseen = _ts(data.get("fseen"))
    lseen = _ts(data.get("lseen"))

    # -------------------------------------------------------------------------
    # Derive the type-specific context strings once; reused for both the typed
    # rst-ioc object and the annotation fallback text.
    # -------------------------------------------------------------------------
    geo_str = asn_str = whois_str = http_status = ""
    dns_records: list[str] = []  # ["A: 1.2.3.4", "CNAME: ..."]
    resolved_ips: list[str] = []  # pivotable A-record IPs (domains)
    url_parts: list[str] = []
    filenames = [f for f in data.get("filename") or [] if _known(f)]

    if is_ip:
        if geo.get("country"):
            parts = [geo["country"]]
            if geo.get("region") and geo["region"] != geo["country"]:
                parts.append(geo["region"])
            if geo.get("city") and geo["city"] not in parts:
                parts.append(geo["city"])
            geo_str = ", ".join(parts)
        if asn_blk.get("num"):
            asn_str = f"AS{asn_blk['num']}"
            if asn_blk.get("isp"):
                asn_str += f" {asn_blk['isp']}"
            if asn_blk.get("org") and asn_blk["org"] != asn_blk.get("isp"):
                asn_str += f" / {asn_blk['org']}"

    if is_domain:
        res_ip = resolved.get("ip") or {}
        a_records = [r for r in res_ip.get("a") or [] if _known(r)]
        cnames = [r for r in res_ip.get("cname") or [] if _known(r)]
        aliases = [r for r in res_ip.get("alias") or [] if _known(r)]
        resolved_ips = a_records
        if a_records:
            dns_records.append("A: " + ", ".join(a_records))
        if cnames:
            dns_records.append("CNAME: " + ", ".join(cnames))
        if aliases:
            dns_records.append("alias: " + ", ".join(aliases))

        whois = resolved.get("whois") or {}
        if whois.get("havedata") == "true" or whois.get("registrar"):
            w_parts = []
            if _known(whois.get("registrar")):
                w_parts.append(f"registrar: {whois['registrar']}")
            if _known(whois.get("registrant")):
                w_parts.append(f"registrant: {whois['registrant']}")
            if _known(whois.get("created")):
                w_parts.append(f"created: {whois['created'][:10]}")
            if _known(whois.get("expires")):
                w_parts.append(f"expires: {whois['expires'][:10]}")
            if _known(whois.get("updated")):
                w_parts.append(f"updated: {whois['updated'][:10]}")
            if _known(whois.get("age")):
                w_parts.append(f"age: {whois['age']} days")
            whois_str = ", ".join(w_parts)

    if is_url:
        if _known(parsed.get("domain")):
            url_parts.append(f"domain: {parsed['domain']}")
        if _known(parsed.get("path")) and parsed.get("path") not in (
            "/",
            "None",
            "none",
        ):
            url_parts.append(f"path: {parsed['path']}")
        if _known(parsed.get("port")) and parsed.get("port") != "None":
            url_parts.append(f"port: {parsed['port']}")
        if _known(resolved.get("status")):
            http_status = str(resolved["status"])

    # Source report URLs (deduped, order preserved).
    ref_urls: list[str] = []
    seen_refs: set[str] = set()
    for report_url in (src_blk.get("report") or "").split(","):
        report_url = report_url.strip()
        if report_url and report_url not in seen_refs:
            ref_urls.append(report_url)
            seen_refs.add(report_url)
    src_names = src_blk.get("name") or []

    # -------------------------------------------------------------------------
    # Annotation fallback text (also a useful human summary).
    # -------------------------------------------------------------------------
    lines: list[str] = []
    score_parts = []
    if total_int is not None:
        score_parts.append(f"total: {total_int}/100")
    if _f(score_block.get("src")):
        score_parts.append(f"src: {_f(score_block['src'])}")
    if conf_sub:
        score_parts.append(f"context: {conf_sub}")
    if relev_sub:
        score_parts.append(f"relevance: {relev_sub}")
    if score_parts:
        lines.append("Score: " + ", ".join(score_parts))
    if fseen or lseen:
        lines.append(f"Seen: {fseen or '?'} to {lseen or '?'}")
    if geo_str:
        lines.append("Geo: " + geo_str)
    if asn_str:
        lines.append("ASN: " + asn_str)
    if dns_records:
        lines.append("DNS: " + " | ".join(dns_records))
    if whois_str:
        lines.append("WHOIS: " + whois_str)
    if url_parts:
        lines.append("URL: " + ", ".join(url_parts))
    if http_status:
        lines.append("HTTP status: " + http_status)
    if is_hash:
        hash_parts = [
            f"{h.upper()}: {data[h]}"
            for h in ("md5", "sha1", "sha256")
            if _known(data.get(h))
        ]
        if hash_parts:
            lines.append("Hashes: " + ", ".join(hash_parts))
    if filenames:
        lines.append("Filenames: " + ", ".join(filenames))
    if industry:
        lines.append("Industry: " + ", ".join(industry))
    if threats:
        lines.append("Threats: " + ", ".join(threats))
    if tags_str:
        lines.append("Tags: " + ", ".join(tags_str))
    if ttp:
        lines.append("TTPs: " + ", ".join(ttp))
    if cve:
        lines.append("CVEs: " + ", ".join(cve))
    if fp_flagged:
        note = f"FP alarm: {fp_alarm}"
        if fp.get("descr"):
            note += f" - {fp['descr']}"
        lines.append(note)
    if data.get("description"):
        lines.append("Description: " + data["description"])
    if src_names:
        lines.append("Sources: " + ", ".join(src_names))

    # -------------------------------------------------------------------------
    # Galaxy + score / FP tags
    # -------------------------------------------------------------------------
    rst_resolver = rst_resolver_from_config(config)
    galaxy_tags = threat_tags(threats, rst_resolver)
    if total_int is not None:
        galaxy_tags.append(f'rstcloud:score-total="{total_int}"')
    if fp_flagged:
        risk = "high" if fp_alarm == "true" else "medium"
        galaxy_tags.append(f'false-positive:risk="{risk}"')

    # -------------------------------------------------------------------------
    # Build MISP result
    # -------------------------------------------------------------------------
    event, source = misp_event_with_source(request)
    anchor = scan_group(request, source)

    obj, dedicated = new_enrichment_object("rst-ioc")
    obj.comment = "RST IoC Lookup"

    if dedicated:
        tag_target = None
        if total_int is not None:
            tag_target = obj.add_attribute(
                "score-total", value=str(total_int), to_ids=False
            )
        if conf_sub:
            obj.add_attribute("score-confidence", value=conf_sub, to_ids=False)
        if relev_sub:
            obj.add_attribute("score-relevance", value=relev_sub, to_ids=False)
        if fseen:
            obj.add_attribute("first-seen", value=fseen, to_ids=False)
        if lseen:
            obj.add_attribute("last-seen", value=lseen, to_ids=False)
        for t in threats:
            a = obj.add_attribute("threat", value=t, to_ids=False)
            tag_target = tag_target or a
        for t in ttp:
            obj.add_attribute("ttp", value=t, to_ids=False)
        for c in cve:
            obj.add_attribute("cve", value=c, to_ids=False)
        for ind in industry:
            obj.add_attribute("industry", value=ind, to_ids=False)
        for t in tags_str:
            obj.add_attribute("tag", value=t, to_ids=False)
        if fp_flagged:
            fp_val = fp_alarm + (
                f" - {fp['descr']}" if fp.get("descr") else ""
            )
            obj.add_attribute("false-positive", value=fp_val, to_ids=False)
        if geo_str:
            obj.add_attribute("geo", value=geo_str, to_ids=False)
        if asn_str:
            obj.add_attribute("asn", value=asn_str, to_ids=False)
        for rec in dns_records:
            obj.add_attribute("dns", value=rec, to_ids=False)
        if whois_str:
            obj.add_attribute("whois", value=whois_str, to_ids=False)
        if http_status:
            obj.add_attribute("http-status", value=http_status, to_ids=False)
        for fn in filenames:
            obj.add_attribute("filename", value=fn, to_ids=False)
        if data.get("description"):
            obj.add_attribute(
                "description", value=data["description"], to_ids=False
            )
        for ref in ref_urls:
            obj.add_attribute("ref", value=ref, to_ids=False)
        # Fall back to a text attribute as the tag anchor if nothing else
        # exists.
        tag_target = tag_target or obj.add_attribute(
            "description", value="\n".join(lines), to_ids=False
        )
    else:
        obj.add_attribute("type", value="RST IoC Lookup", to_ids=False)
        tag_target = obj.add_attribute(
            "text", value="\n".join(lines), to_ids=False
        )
        if fseen:
            obj.add_attribute("creation-date", value=fseen, to_ids=False)
        for ref in ref_urls:
            obj.add_attribute("ref", value=ref, to_ids=False)

    for tag in galaxy_tags:
        tag_target.add_tag(tag)
    if anchor:
        obj.add_reference(anchor, "characterizes")
    event.add_object(obj)

    # Pivotable hashes: expose related hash values as searchable IOC
    # attributes (separate from the object) so they correlate across events.
    if is_hash:
        for htype in ("md5", "sha1", "sha256"):
            hval = data.get(htype)
            if _known(hval) and hval != value:
                a = event.add_attribute(
                    htype,
                    value=hval,
                    to_ids=True,
                    comment="RST IoC Lookup - related hash",
                )
                for tag in galaxy_tags:
                    a.add_tag(tag)

    # Pivotable resolved IPs for domains (context, not detection-worthy).
    for rip in resolved_ips:
        event.add_attribute(
            "ip-dst",
            value=rip,
            to_ids=False,
            comment="RST IoC Lookup - resolved IP",
        )

    # Optional write-back: apply tags + brief note onto the enriched attribute
    # directly via the MISP API when misp_url/misp_key are configured.
    apply_to_source_attribute(
        config,
        request,
        tags=galaxy_tags,
        comment_note=(
            f"RST score {total_int}/100"
            + (f"; threats: {', '.join(threats)}" if threats else "")
        ),
        comment_prefix="RST score",
    )

    return standard_results(event)


if __name__ == "__main__":
    print(json.dumps(version(), indent=2))
