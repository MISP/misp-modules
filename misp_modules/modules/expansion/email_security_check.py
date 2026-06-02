import json

try:
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
except ImportError:
    print("dnspython is missing, use 'pip install dnspython' to install it.")

from pymisp import MISPAttribute, MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "hostname"], "format": "misp_standard"}
moduleinfo = {
    "version": "0.2",
    "author": "Mihai Saveanu",
    "description": "Check email security posture (SPF, DKIM, DMARC, MTA-STS) for a domain.",
    "module-type": ["expansion", "hover"],
    "name": "Email Security Check",
    "logo": "",
    "requirements": ["dnspython"],
    "features": (
        "The module takes a domain or hostname attribute as input and queries DNS"
        " for email security records: SPF (TXT), DMARC (_dmarc), DKIM (common selectors),"
        " and MTA-STS (_mta-sts). Returns structured MISP attributes with a domain-ip"
        " object linking the findings to the queried domain."
    ),
    "references": [
        "https://tools.ietf.org/html/rfc7208",
        "https://tools.ietf.org/html/rfc7489",
    ],
    "input": "A domain or hostname attribute.",
    "output": "Domain-ip MISP object with email security assessment attributes.",
}
moduleconfig = ["custom_resolver"]

DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mandrill",
    "everlytickey1",
    "everlytickey2",
    "dkim",
    "s1",
    "s2",
    "mailo",
]


def _query_txt(domain):
    try:
        answers = resolver.resolve(domain, "TXT")
        return [str(rdata).strip('"') for rdata in answers]
    except Exception:
        return []


def _check_spf(domain):
    records = _query_txt(domain)
    spf = [r for r in records if r.startswith("v=spf1")]
    if spf:
        return {"status": "FOUND", "record": spf[0]}
    return {"status": "MISSING", "record": None}


def _check_dmarc(domain):
    records = _query_txt(f"_dmarc.{domain}")
    dmarc = [r for r in records if r.startswith("v=DMARC1")]
    if dmarc:
        policy = "none"
        for part in dmarc[0].split(";"):
            part = part.strip()
            if part.startswith("p="):
                policy = part[2:]
        return {"status": "FOUND", "record": dmarc[0], "policy": policy}
    return {"status": "MISSING", "record": None, "policy": None}


def _check_dkim(domain):
    found = []
    for selector in DKIM_SELECTORS:
        records = _query_txt(f"{selector}._domainkey.{domain}")
        dkim = [r for r in records if "DKIM1" in r or "k=" in r or "p=" in r]
        if dkim:
            found.append({"selector": selector, "record": dkim[0]})
    return found


def _check_mta_sts(domain):
    records = _query_txt(f"_mta-sts.{domain}")
    sts = [r for r in records if r.startswith("v=STSv1")]
    if sts:
        return {"status": "FOUND", "record": sts[0]}
    return {"status": "MISSING", "record": None}


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    if not request.get("attribute") or not request["attribute"].get("type"):
        return {"error": "Missing or invalid attribute."}

    attribute = request["attribute"]
    if attribute["type"] not in mispattributes["input"]:
        return {"error": f"Unsupported attribute type: {attribute['type']}"}

    domain = attribute["value"]

    if request.get("config", {}).get("custom_resolver"):
        resolver.nameservers = [request["config"]["custom_resolver"]]

    spf = _check_spf(domain)
    dmarc = _check_dmarc(domain)
    dkim = _check_dkim(domain)
    mta_sts = _check_mta_sts(domain)

    event = MISPEvent()
    initial_attribute = MISPAttribute()
    initial_attribute.from_dict(**attribute)
    event.add_attribute(**initial_attribute)

    domain_obj = MISPObject("domain-ip")
    domain_obj.add_attribute("domain", **{"type": "domain", "value": domain})

    score = 0

    if spf["status"] == "FOUND":
        score += 1
        domain_obj.add_attribute(
            "text",
            **{"type": "text", "value": f"SPF: {spf['record']}", "comment": "SPF record", "disable_correlation": True},
        )
    else:
        domain_obj.add_attribute(
            "text",
            **{"type": "text", "value": "SPF: MISSING", "comment": "SPF record", "disable_correlation": True},
        )

    if dmarc["status"] == "FOUND":
        score += 1
        if dmarc["policy"] in ("reject", "quarantine"):
            score += 1
        domain_obj.add_attribute(
            "text",
            **{
                "type": "text",
                "value": f"DMARC: {dmarc['policy']} — {dmarc['record']}",
                "comment": "DMARC record and policy",
                "disable_correlation": True,
            },
        )
    else:
        domain_obj.add_attribute(
            "text",
            **{"type": "text", "value": "DMARC: MISSING", "comment": "DMARC record", "disable_correlation": True},
        )

    if dkim:
        score += 1
        selectors = ", ".join(d["selector"] for d in dkim)
        domain_obj.add_attribute(
            "text",
            **{
                "type": "text",
                "value": f"DKIM: FOUND ({len(dkim)} selector(s): {selectors})",
                "comment": "DKIM selectors found",
                "disable_correlation": True,
            },
        )
    else:
        domain_obj.add_attribute(
            "text",
            **{
                "type": "text",
                "value": "DKIM: NOT FOUND (tested common selectors)",
                "comment": "DKIM check",
                "disable_correlation": True,
            },
        )

    if mta_sts["status"] == "FOUND":
        score += 1
        domain_obj.add_attribute(
            "text",
            **{"type": "text", "value": f"MTA-STS: {mta_sts['record']}", "comment": "MTA-STS record", "disable_correlation": True},
        )
    else:
        domain_obj.add_attribute(
            "text",
            **{"type": "text", "value": "MTA-STS: MISSING", "comment": "MTA-STS record", "disable_correlation": True},
        )

    domain_obj.add_attribute(
        "text",
        **{
            "type": "text",
            "value": f"Email Security Score: {score}/5",
            "comment": "Overall email security posture score",
            "disable_correlation": True,
        },
    )

    domain_obj.add_reference(initial_attribute.uuid, "related-to")
    event.add_object(**domain_obj)

    ev = json.loads(event.to_json())
    results = {key: ev[key] for key in ("Attribute", "Object") if key in ev and ev[key]}
    return {"results": results}


def introspection():
    return mispattributes


def version():
    return moduleinfo
