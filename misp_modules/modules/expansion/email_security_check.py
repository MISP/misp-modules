import json

try:
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
except ImportError:
    print("dnspython is missing, use 'pip install dnspython' to install it.")

misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "hostname"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Mihai Catalin Teodosiu",
    "description": "Check email security posture (SPF, DKIM, DMARC, MTA-STS) for a domain.",
    "module-type": ["expansion", "hover"],
    "name": "Email Security Check",
    "logo": "",
    "requirements": ["dnspython"],
    "features": (
        "The module takes a domain or hostname attribute as input and queries DNS"
        " for email security records: SPF (TXT), DMARC (_dmarc), DKIM (common selectors),"
        " and MTA-STS (_mta-sts). Results include record content and a pass/fail assessment."
    ),
    "references": [
        "https://tools.ietf.org/html/rfc7208",
        "https://tools.ietf.org/html/rfc7489",
    ],
    "input": "A domain or hostname attribute.",
    "output": "Text containing email security posture assessment.",
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

    domain = request.get("domain") or request.get("hostname")
    if not domain:
        misperrors["error"] = "A domain or hostname attribute is required."
        return misperrors

    if request.get("config", {}).get("custom_resolver"):
        resolver.nameservers = [request["config"]["custom_resolver"]]

    spf = _check_spf(domain)
    dmarc = _check_dmarc(domain)
    dkim = _check_dkim(domain)
    mta_sts = _check_mta_sts(domain)

    lines = [f"=== Email Security Posture: {domain} ===", ""]

    lines.append(f"SPF: {spf['status']}")
    if spf["record"]:
        lines.append(f"  Record: {spf['record']}")

    lines.append(f"\nDMARC: {dmarc['status']}")
    if dmarc["record"]:
        lines.append(f"  Policy: {dmarc['policy']}")
        lines.append(f"  Record: {dmarc['record']}")

    if dkim:
        lines.append(f"\nDKIM: FOUND ({len(dkim)} selector(s))")
        for entry in dkim:
            lines.append(f"  Selector '{entry['selector']}': {entry['record'][:80]}...")
    else:
        lines.append("\nDKIM: NOT FOUND (tested common selectors)")

    lines.append(f"\nMTA-STS: {mta_sts['status']}")
    if mta_sts["record"]:
        lines.append(f"  Record: {mta_sts['record']}")

    score = sum([
        1 if spf["status"] == "FOUND" else 0,
        1 if dmarc["status"] == "FOUND" else 0,
        1 if dmarc.get("policy") in ("reject", "quarantine") else 0,
        1 if dkim else 0,
        1 if mta_sts["status"] == "FOUND" else 0,
    ])
    lines.append(f"\nSecurity Score: {score}/5")

    result_text = "\n".join(lines)
    return {"results": [{"types": ["text"], "values": result_text}]}


def introspection():
    return mispattributes


def version():
    return moduleinfo
