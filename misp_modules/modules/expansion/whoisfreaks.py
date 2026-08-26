import json
from concurrent.futures import ThreadPoolExecutor

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["domain", "ip-src", "ip-dst", "ip"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "3",
    "author": "WhoisFreaks",
    "description": (
        "An expansion module for https://whoisfreaks.com/ that enriches a domain or an IP address. For a domain it"
        " queries the WHOIS, DNS and Domain Reputation APIs; for an IP address it queries the IP WHOIS, Geolocation"
        " and IP Security APIs. All lookups for a given attribute are executed in parallel."
    ),
    "module-type": ["expansion", "hover"],
    "name": "WhoisFreaks Lookup",
    "logo": "whoisfreaks.png",
    "requirements": ["An access to the Whoisfreaks API_KEY"],
    "features": (
        "The module takes a domain or an IP address as input.\n\nFor a domain it queries the Whoisfreaks WHOIS"
        " (v1.0), DNS (v2.0) and Domain Reputation APIs in parallel. For an IP address it queries the IP WHOIS,"
        " Geolocation and IP Security APIs in parallel.\n\nThe results are mapped to MISP attributes, objects"
        " (geolocation, asn, reputation and security) and tags."
    ),
    "references": ["https://whoisfreaks.com/"],
    "input": "A domain or an IP address (ip-src, ip-dst or ip).",
    "output": (
        "MISP attributes, objects and tags resulting from the WhoisFreaks WHOIS, DNS, Domain Reputation, IP WHOIS,"
        " Geolocation and IP Security APIs."
    ),
}

# config fields that your code expects from the site admin
moduleconfig = ["apikey"]

# WhoisFreaks API endpoints (verified live against api.whoisfreaks.com).
WHOIS_API_URL = "https://api.whoisfreaks.com/v1.0/whois"
DNS_API_URL = "https://api.whoisfreaks.com/v2.0/dns/live"
DOMAIN_REPUTATION_API_URL = "https://api.whoisfreaks.com/v1/domain/security"
IP_WHOIS_API_URL = "https://api.whoisfreaks.com/v1.0/ip-whois"
GEOLOCATION_API_URL = "https://api.whoisfreaks.com/v1.0/geolocation"
IP_SECURITY_API_URL = "https://api.whoisfreaks.com/v1.0/security"
DNS_RECORD_TYPES = "A,AAAA,MX,SOA"
API_TIMEOUT = 30


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
def _is_redacted(value):
    """Return True for empty values or WhoisFreaks/registry privacy placeholders."""
    if not value or not isinstance(value, str):
        return True
    lowered = value.lower()
    return "gdpr" in lowered or "data has been removed" in lowered or "redacted" in lowered


def _clean_host(value):
    """Normalise a hostname coming from DNS/WHOIS (strip the trailing root dot)."""
    if not value:
        return ""
    return value.rstrip(".")


def _soa_admin_to_email(admin):
    """Convert an SOA RNAME (e.g. ``hostmaster.example.com.``) into an email address."""
    admin = admin.rstrip(".")
    if "@" in admin:
        return admin
    local = []
    i = 0
    while i < len(admin):
        char = admin[i]
        if char == "\\" and i + 1 < len(admin):
            local.append(admin[i + 1])
            i += 2
            continue
        if char == ".":
            return "%s@%s" % ("".join(local), admin[i + 1 :])
        local.append(char)
        i += 1
    return admin


def _attribute(types, values, category, comment):
    return {"types": types, "values": values, "categories": [category], "comment": comment}


def _dedupe_results(results):
    """Drop duplicate values sharing the same attribute type, keeping first occurrence."""
    seen = {}
    deduped = []
    for attr in results:
        type_key = tuple(attr["types"])
        seen_values = seen.setdefault(type_key, set())
        new_values = [v for v in attr["values"] if not (v in seen_values or seen_values.add(v))]
        if new_values:
            attr["values"] = new_values
            deduped.append(attr)
    return deduped


def _api_get(url, params, label):
    """Perform a GET against a WhoisFreaks API, returning (json, error)."""
    try:
        query = requests.get(url, params=params, timeout=API_TIMEOUT)
    except requests.RequestException as e:
        return None, "Error while querying WhoisFreaks %s API: %s" % (label, e)
    if query.status_code not in (200, 206):
        return None, "Error while querying WhoisFreaks %s API - %s: %s" % (label, query.status_code, query.reason)
    try:
        return query.json(), None
    except ValueError:
        return None, "Invalid JSON received from WhoisFreaks %s API" % label


def _add_flat_attributes(misp_event, flat):
    """Add simple {types, values, categories, comment} entries to the event."""
    for attr in flat:
        a_type = attr["types"][0]
        category = attr["categories"][0]
        comment = attr.get("comment")
        for value in attr["values"]:
            misp_event.add_attribute(a_type, value, category=category, comment=comment)


def _obj_add(obj, relation, value, type_):
    """Add an attribute to a (custom) MISP object, skipping empty values."""
    if value is None or value == "":
        return
    obj.add_attribute(relation, value=value, type=type_)


# ---------------------------------------------------------------------------
# Module interface
# ---------------------------------------------------------------------------
def handler(q=False):
    if not q:
        return False

    request = json.loads(q)

    config = request.get("config") or {}
    apikey = config.get("apikey") or config.get("apiKey")
    if not apikey:
        misperrors["error"] = "WhoisFreaks authentication is missing (apikey)"
        return misperrors

    attribute = request.get("attribute")
    if not attribute or not attribute.get("type") or not attribute.get("value"):
        misperrors["error"] = "Unsupported input, an attribute with a type and a value is required"
        return misperrors

    input_type = attribute["type"]
    if input_type == "domain":
        return handle_domain(apikey, attribute)
    if input_type in ("ip-src", "ip-dst", "ip"):
        return handle_ip(apikey, attribute)

    misperrors["error"] = "Unsupported attribute type (expected domain, ip-src, ip-dst or ip)"
    return misperrors


def _finalize(misp_event, errors, produced):
    if not produced:
        error = next((e for e in errors if e), None)
        if error:
            misperrors["error"] = error
            return misperrors
    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if key in event}}


# ---------------------------------------------------------------------------
# Domain enrichment
# ---------------------------------------------------------------------------
def handle_domain(apikey, attribute):
    domain = attribute["value"]

    with ThreadPoolExecutor(max_workers=3) as executor:
        whois_future = executor.submit(expand_whois, apikey, domain)
        dns_future = executor.submit(expand_dns, apikey, domain)
        reputation_future = executor.submit(get_domain_reputation, apikey, domain)
        whois_results, whois_error = whois_future.result()
        dns_results, dns_error = dns_future.result()
        reputation_data, reputation_error = reputation_future.result()

    flat = _dedupe_results(whois_results + dns_results)

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)

    reputation_attrs = []
    reputation_object = None
    if reputation_data:
        reputation_attrs, reputation_tags, reputation_object = parse_domain_reputation(reputation_data, domain)
        for tag in reputation_tags:
            input_attribute.add_tag(tag)

    misp_event.add_attribute(**input_attribute)
    _add_flat_attributes(misp_event, flat)
    _add_flat_attributes(misp_event, reputation_attrs)
    if reputation_object is not None:
        reputation_object.add_reference(input_attribute.uuid, "characterizes")
        misp_event.add_object(reputation_object)

    produced = bool(flat or reputation_attrs or reputation_object)
    return _finalize(misp_event, (whois_error, dns_error, reputation_error), produced)


def expand_whois(apikey, domain):
    results, error = get_whois_response(apikey, domain)
    if error:
        return [], error

    r = []
    if not isinstance(results, dict):
        return r, None

    create_date = results.get("create_date")
    if not _is_redacted(create_date):
        r.append(
            _attribute(
                ["whois-creation-date"], [create_date], "Attribution", "Creation date for %s by WhoisFreaks" % domain
            )
        )

    registrar = results.get("domain_registrar") or {}
    if not _is_redacted(registrar.get("registrar_name")):
        r.append(
            _attribute(
                ["whois-registrar"],
                [registrar["registrar_name"]],
                "Attribution",
                "Registrar of %s by WhoisFreaks" % domain,
            )
        )

    registrant = results.get("registrant_contact") or {}
    for name_value in (registrant.get("name"), registrant.get("company")):
        if not _is_redacted(name_value):
            r.append(
                _attribute(
                    ["whois-registrant-name"], [name_value], "Attribution", "Registrant of %s by WhoisFreaks" % domain
                )
            )
    if not _is_redacted(registrant.get("email_address")):
        r.append(
            _attribute(
                ["whois-registrant-email"],
                [registrant["email_address"]],
                "Attribution",
                "Registrant email of %s by WhoisFreaks" % domain,
            )
        )
    if not _is_redacted(registrant.get("phone")):
        r.append(
            _attribute(
                ["whois-registrant-phone"],
                [registrant["phone"]],
                "Attribution",
                "Registrant phone of %s by WhoisFreaks" % domain,
            )
        )

    name_servers = [_clean_host(ns) for ns in results.get("name_servers") or [] if _clean_host(ns)]
    if name_servers:
        r.append(_attribute(["domain"], name_servers, "Network activity", "Name server for %s by WhoisFreaks" % domain))

    return r, None


def expand_dns(apikey, domain):
    results, error = get_dns_response(apikey, domain)
    if error:
        return [], error

    r = []
    if not isinstance(results, dict):
        return r, None

    list_ipv4 = []
    list_ipv6 = []
    servers_mx = []
    soa_emails = []
    soa_hostnames = []

    for record in results.get("dnsRecords") or []:
        dns_type = record.get("dnsType")
        if dns_type == "A" and record.get("address"):
            list_ipv4.append(record["address"])
        elif dns_type == "AAAA" and record.get("address"):
            list_ipv6.append(record["address"])
        elif dns_type == "MX":
            mx_target = _clean_host(record.get("target"))
            if mx_target:
                servers_mx.append(mx_target)
        elif dns_type == "SOA":
            if not _is_redacted(record.get("admin")):
                soa_emails.append(_soa_admin_to_email(record["admin"]))
            soa_host = _clean_host(record.get("host"))
            if soa_host:
                soa_hostnames.append(soa_host)

    if list_ipv4:
        r.append(
            _attribute(
                ["domain|ip"], ["%s|%s" % (domain, ip) for ip in list_ipv4], "Network activity", "ipv4 of %s" % domain
            )
        )
    if list_ipv6:
        r.append(
            _attribute(
                ["domain|ip"], ["%s|%s" % (domain, ip) for ip in list_ipv6], "Network activity", "ipv6 of %s" % domain
            )
        )
    if servers_mx:
        r.append(_attribute(["domain"], servers_mx, "Network activity", "mx of %s" % domain))
    if soa_emails:
        r.append(_attribute(["dns-soa-email"], soa_emails, "Network activity", "soa email of %s" % domain))
    if soa_hostnames:
        r.append(_attribute(["domain"], soa_hostnames, "Network activity", "soa hostname of %s" % domain))

    return r, None


def parse_domain_reputation(data, domain):
    """Return (flat_attributes, tags, reputation_object) from a Domain Reputation response."""
    attrs = []
    tags = []

    intelligence = data.get("intelligence") or {}
    for ioc in intelligence.get("related_iocs") or []:
        value = ioc.get("value")
        if value and ioc.get("type") in ("ipv4", "ipv6"):
            attrs.append(
                _attribute(
                    ["ip-dst"],
                    [value],
                    "Network activity",
                    "Related IOC (confidence %s) for %s by WhoisFreaks" % (ioc.get("confidence"), domain),
                )
            )
    stix_pattern = intelligence.get("stix_pattern")
    if stix_pattern:
        attrs.append(
            _attribute(["stix2-pattern"], [stix_pattern], "Other", "STIX pattern for %s by WhoisFreaks" % domain)
        )

    deliverability = data.get("email_deliverability") or {}
    infrastructure = deliverability.get("infrastructure") or {}
    mx_records = [_clean_host(mx) for mx in infrastructure.get("mx_records") or [] if _clean_host(mx)]
    if mx_records:
        attrs.append(_attribute(["domain"], mx_records, "Network activity", "mx of %s by WhoisFreaks" % domain))
    spf_record = ((deliverability.get("authentication") or {}).get("spf") or {}).get("record")
    if spf_record:
        attrs.append(_attribute(["text"], [spf_record], "Other", "SPF record of %s by WhoisFreaks" % domain))

    # Tags: feed_tags are already MISP tag-shaped; add derived verdict/severity/action tags.
    for tag in intelligence.get("feed_tags") or []:
        tags.append(tag)
    risk = data.get("risk_category") or {}
    if risk.get("verdict"):
        tags.append('whoisfreaks:verdict="%s"' % risk["verdict"])
    if risk.get("severity"):
        tags.append('whoisfreaks:severity="%s"' % risk["severity"])
    for threat in risk.get("threat_types") or []:
        tags.append('whoisfreaks:threat-type="%s"' % threat)
    if intelligence.get("recommended_action"):
        tags.append('whoisfreaks:action="%s"' % intelligence["recommended_action"])

    # Reputation scores/verdicts have no native attribute types -> custom object.
    obj = MISPObject("whoisfreaks-domain-reputation")
    obj.description = "WhoisFreaks domain reputation assessment"
    setattr(obj, "meta-category", "network")
    _obj_add(obj, "verdict", risk.get("verdict"), "text")
    _obj_add(obj, "confidence", risk.get("confidence"), "float")
    _obj_add(obj, "severity", risk.get("severity"), "text")
    _obj_add(obj, "primary-threat", risk.get("primary_threat"), "text")

    dga = data.get("dga_score") or {}
    _obj_add(obj, "dga-score", dga.get("score"), "float")
    if dga.get("is_dga") is not None:
        _obj_add(obj, "is-dga", dga.get("is_dga"), "boolean")

    trust = data.get("trust_signals") or {}
    _obj_add(obj, "trust-score", trust.get("trust_score"), "counter")
    _obj_add(obj, "trust-band", trust.get("trust_band"), "text")

    _obj_add(obj, "email-deliverability-score", deliverability.get("score"), "counter")
    _obj_add(obj, "email-grade", deliverability.get("grade"), "text")
    reputation = deliverability.get("reputation") or {}
    if reputation.get("spam_blacklisted") is not None:
        _obj_add(obj, "spam-blacklisted", reputation.get("spam_blacklisted"), "boolean")

    _obj_add(obj, "recommended-action", intelligence.get("recommended_action"), "text")
    _obj_add(obj, "assessed-at", data.get("assessed_at"), "datetime")

    if not obj.attributes:
        obj = None
    return attrs, tags, obj


# ---------------------------------------------------------------------------
# IP enrichment
# ---------------------------------------------------------------------------
def handle_ip(apikey, attribute):
    ip = attribute["value"]

    with ThreadPoolExecutor(max_workers=3) as executor:
        whois_future = executor.submit(get_ip_whois, apikey, ip)
        geo_future = executor.submit(get_geolocation, apikey, ip)
        security_future = executor.submit(get_ip_security, apikey, ip)
        ip_whois_data, ip_whois_error = whois_future.result()
        geo_data, geo_error = geo_future.result()
        security_data, security_error = security_future.result()

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    # "ip" is a convenience alias and not a valid MISP attribute type, so map it
    # to ip-dst before building the event attribute.
    normalized_attribute = dict(attribute)
    if normalized_attribute.get("type") == "ip":
        normalized_attribute["type"] = "ip-dst"
    input_attribute.from_dict(**normalized_attribute)

    flat_attrs = []
    objects = []
    security_tags = []

    if geo_data:
        geo_obj = build_geolocation_object((geo_data.get("location") or {}))
        asn_obj = build_asn_object((geo_data.get("network") or {}))
        objects.extend(o for o in (geo_obj, asn_obj) if o is not None)

    if security_data:
        security_obj, security_tags = parse_ip_security(security_data.get("security") or {})
        if security_obj is not None:
            objects.append(security_obj)

    if ip_whois_data:
        flat_attrs = parse_ip_whois(ip_whois_data)

    for tag in security_tags:
        input_attribute.add_tag(tag)
    misp_event.add_attribute(**input_attribute)
    _add_flat_attributes(misp_event, flat_attrs)
    for obj in objects:
        obj.add_reference(input_attribute.uuid, "characterizes")
        misp_event.add_object(obj)

    produced = bool(flat_attrs or objects)
    return _finalize(misp_event, (ip_whois_error, geo_error, security_error), produced)


def build_geolocation_object(location):
    if not isinstance(location, dict) or not location:
        return None
    obj = MISPObject("geolocation")
    mapping = {
        "country_code2": "countrycode",
        "country_name": "country",
        "state_prov": "region",
        "city": "city",
        "zipcode": "zipcode",
        "latitude": "latitude",
        "longitude": "longitude",
        "accuracy_radius": "accuracy-radius",
    }
    for field, relation in mapping.items():
        value = location.get(field)
        if value not in (None, ""):
            obj.add_attribute(relation, value)
    return obj if obj.attributes else None


def build_asn_object(network):
    asn_info = (network or {}).get("asn") or {}
    if not asn_info:
        return None
    obj = MISPObject("asn")
    if asn_info.get("as_number"):
        obj.add_attribute("asn", asn_info["as_number"])
    description = asn_info.get("asn_name") or asn_info.get("organization")
    if description:
        obj.add_attribute("description", description)
    if asn_info.get("country"):
        obj.add_attribute("country", asn_info["country"])
    return obj if obj.attributes else None


def parse_ip_security(security):
    """Return (security_object, tags) from an IP Security response 'security' block."""
    if not isinstance(security, dict) or not security:
        return None, []

    obj = MISPObject("whoisfreaks-ip-security")
    obj.description = "WhoisFreaks IP security assessment"
    setattr(obj, "meta-category", "network")
    _obj_add(obj, "threat-score", security.get("threat_score"), "float")

    flag_relations = {
        "is_tor": "is-tor",
        "is_proxy": "is-proxy",
        "is_anonymous": "is-anonymous",
        "is_known_attacker": "is-known-attacker",
        "is_spam": "is-spam",
        "is_bot": "is-bot",
        "is_cloud_provider": "is-cloud-provider",
    }
    tags = []
    for field, relation in flag_relations.items():
        value = security.get(field)
        if value is not None:
            _obj_add(obj, relation, value, "boolean")
            if value is True:
                tags.append('whoisfreaks:ip-flag="%s"' % relation[3:])

    _obj_add(obj, "proxy-type", security.get("proxy_type"), "text")
    _obj_add(obj, "proxy-provider", security.get("proxy_provider"), "text")
    _obj_add(obj, "cloud-provider", security.get("cloud_provider"), "text")

    return (obj if obj.attributes else None), tags


def parse_ip_whois(data):
    """Return flat attributes (abuse email, organization, netblock) from an IP WHOIS response."""
    attrs = []
    if not isinstance(data, dict):
        return attrs

    organization = data.get("organization") or {}
    for email_field in ("abuse_mailbox", "email"):
        email = organization.get(email_field)
        if email and not _is_redacted(email):
            attrs.append(
                _attribute(
                    ["email-src"],
                    [email],
                    "Attribution",
                    "Abuse contact for %s by WhoisFreaks" % data.get("ip_address", ""),
                )
            )
            break
    for contact in data.get("abuse_contacts") or []:
        email = contact.get("email") if isinstance(contact, dict) else None
        if email and not _is_redacted(email):
            attrs.append(_attribute(["email-src"], [email], "Attribution", "Abuse contact by WhoisFreaks"))

    if organization.get("name"):
        attrs.append(
            _attribute(["text"], [organization["name"]], "Attribution", "IP WHOIS organization by WhoisFreaks")
        )

    cidrs = []
    for inet in data.get("inet_nums") or []:
        for cidr in inet.get("cidr") or []:
            cidrs.append(cidr)
    if cidrs:
        attrs.append(_attribute(["text"], cidrs, "Network activity", "Netblock by WhoisFreaks"))

    return attrs


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------
def get_whois_response(apikey, domain):
    return _api_get(WHOIS_API_URL, {"apiKey": apikey, "whois": "live", "domainName": domain, "format": "json"}, "WHOIS")


def get_dns_response(apikey, domain):
    return _api_get(
        DNS_API_URL, {"apiKey": apikey, "domainName": domain, "type": DNS_RECORD_TYPES, "format": "json"}, "DNS"
    )


def get_domain_reputation(apikey, domain):
    return _api_get(
        DOMAIN_REPUTATION_API_URL, {"apiKey": apikey, "domainName": domain, "format": "json"}, "Domain Reputation"
    )


def get_ip_whois(apikey, ip):
    return _api_get(IP_WHOIS_API_URL, {"apiKey": apikey, "ip": ip, "format": "json"}, "IP WHOIS")


def get_geolocation(apikey, ip):
    return _api_get(GEOLOCATION_API_URL, {"apiKey": apikey, "ip": ip}, "Geolocation")


def get_ip_security(apikey, ip):
    return _api_get(IP_SECURITY_API_URL, {"apiKey": apikey, "ip": ip}, "IP Security")


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
