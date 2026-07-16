"""APIFreaks MISP expansion/hover module.

An expansion + hover module for https://apifreaks.com/ that enriches MISP
attributes using the APIFreaks WHOIS, Domain and DNS API families.

Depending on the type of the input attribute, the module queries the relevant
APIFreaks endpoints and maps the results back into MISP attributes:

  * domain / hostname -> WHOIS live, WHOIS history, DNS live, DNS history,
                         subdomains, domain availability
  * ip-src / ip-dst   -> IP WHOIS, reverse DNS
  * AS                -> ASN WHOIS
  * *-email           -> reverse WHOIS (by registrant email)

All endpoints are documented at https://apifreaks.com/api and authenticated
with a personal API key sent in the ``X-apiKey`` header.
"""

import json

import requests

misperrors = {"error": "Error"}

# --- MISP module interface metadata -----------------------------------------

# Attribute types the module accepts as input and can produce as output.
mispattributes = {
    "input": [
        "domain",
        "hostname",
        "ip-src",
        "ip-dst",
        "AS",
        "email-src",
        "email-dst",
        "target-email",
        "whois-registrant-email",
    ],
    "output": [
        "domain",
        "hostname",
        "ip-src",
        "ip-dst",
        "AS",
        "whois-registrant-email",
        "whois-registrant-phone",
        "whois-registrant-name",
        "whois-registrar",
        "whois-creation-date",
        "dns-soa-email",
        "email-src",
        "datetime",
        "text",
    ],
}

moduleinfo = {
    "version": "1.0",
    "author": "APIFreaks",
    "description": (
        "An expansion module for https://apifreaks.com/ that provides an"
        " enriched analysis of a domain, hostname, IP address, ASN or email"
        " address, including WHOIS, DNS, subdomains and domain-availability"
        " information."
    ),
    "module-type": ["expansion", "hover"],
    "name": "APIFreaks Lookup",
    "logo": "apifreaks.png",
    "requirements": ["An access to the APIFreaks API (apikey)"],
    "features": (
        "The module takes a domain, hostname, IP address, ASN or email"
        " attribute as input and queries the relevant APIFreaks WHOIS, Domain"
        " and DNS endpoints with it. The results of the queries are then"
        " parsed to extract as much information as possible and mapped into"
        " compatible MISP attributes."
    ),
    "references": ["https://apifreaks.com/", "https://apifreaks.com/api"],
    "input": (
        "A domain, hostname, IP address (ip-src/ip-dst), ASN (AS) or email"
        " (email-src/email-dst/target-email/whois-registrant-email) attribute."
    ),
    "output": (
        "MISP attributes resulting from the queries on the APIFreaks API,"
        " included in the following list:\n"
        "- domain\n- hostname\n- ip-src\n- ip-dst\n- AS\n"
        "- whois-registrant-email\n- whois-registrant-phone\n"
        "- whois-registrant-name\n- whois-registrar\n- whois-creation-date\n"
        "- dns-soa-email\n- email-src\n- datetime\n- text"
    ),
}

# Values shown in the MISP UI so an administrator can configure the module.
# The first entry is always the API key; the remaining entries are on/off
# toggles (accepting "1"/"true"/"yes") that let operators control which
# lookups run, since each lookup consumes API credits.
moduleconfig = [
    "apikey",
    "do_whois",
    "do_dns",
    "do_subdomains",
    "do_availability",
    "do_history",
    "do_reverse_dns",
]

# --- APIFreaks API details --------------------------------------------------

API_BASE = "https://api.apifreaks.com"
ENDPOINTS = {
    "whois_live": "/v1.0/domain/whois/live",
    "whois_history": "/v1.0/domain/whois/history",
    "whois_reverse": "/v1.0/domain/whois/reverse",
    "ip_whois": "/v1.0/ip/whois/live",
    "asn_whois": "/v1.0/asn/whois/live",
    "dns_live": "/v1.0/domain/dns/live",
    "dns_history": "/v1.0/domain/dns/history",
    "dns_reverse": "/v1.0/domain/dns/reverse",
    "availability": "/v1.0/domain/availability",
    "subdomains": "/v1.0/subdomains/lookup",
}

DEFAULT_DNS_TYPES = "A,AAAA,MX,NS,SOA,SPF,TXT,CNAME"
REDACTED_MARKERS = ("redacted", "privacy", "not disclosed", "data protected")

_EMAIL_INPUTS = {
    "email-src",
    "email-dst",
    "target-email",
    "whois-registrant-email",
}


# --- Small helpers ----------------------------------------------------------

def _is_truthy(value, default=True):
    """Interpret a MISP string config toggle as a boolean.

    An unset/empty toggle falls back to ``default`` so operators only have to
    change the toggles they care about.
    """
    if value is None or value == "":
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def _clean_host(value):
    """Normalise a DNS name into a valid hostname attribute (drop trailing dot)."""
    if not value:
        return None
    return str(value).rstrip(".").strip() or None


def _is_redacted(value):
    if not value:
        return True
    low = str(value).lower()
    return any(marker in low for marker in REDACTED_MARKERS)


class _ResultBuilder:
    """Accumulate deduplicated MISP result rows."""

    def __init__(self):
        self._rows = []
        self._seen = set()
        self._summary = []

    def add(self, misp_type, value, category=None, comment=None):
        if value is None:
            return
        value = str(value).strip()
        if not value:
            return
        key = (misp_type, value)
        if key in self._seen:
            return
        self._seen.add(key)
        row = {"types": [misp_type], "values": [value]}
        if category:
            row["categories"] = [category]
        if comment:
            row["comment"] = comment
        self._rows.append(row)

    def note(self, line):
        if line:
            self._summary.append(str(line))

    def build(self):
        if self._summary:
            self._rows.append(
                {"types": ["text"], "values": ["\n".join(self._summary)]}
            )
        return {"results": self._rows}


def _query(endpoint, apikey, params):
    """Perform a GET request against an APIFreaks endpoint."""
    headers = {"X-apiKey": apikey, "Accept": "application/json"}
    params = dict(params or {})
    params.setdefault("format", "json")
    response = requests.get(
        f"{API_BASE}{endpoint}", headers=headers, params=params, timeout=30
    )
    response.raise_for_status()
    return response.json()


# --- Per-endpoint parsers ---------------------------------------------------

def _parse_whois_live(data, rb):
    if not isinstance(data, dict):
        return
    rb.add("domain", data.get("domain_name"), "Network activity")
    rb.add("whois-creation-date", data.get("create_date"), "Attribution")

    registrar = data.get("domain_registrar") or {}
    rb.add("whois-registrar", registrar.get("registrar_name"), "Attribution")

    registrant = data.get("registrant_contact") or {}
    if not _is_redacted(registrant.get("name")):
        rb.add("whois-registrant-name", registrant.get("name"), "Attribution")
    if not _is_redacted(registrant.get("company")):
        rb.add("whois-registrant-name", registrant.get("company"), "Attribution")
    if not _is_redacted(registrant.get("email_address")):
        rb.add(
            "whois-registrant-email",
            registrant.get("email_address"),
            "Attribution",
        )
    if not _is_redacted(registrant.get("phone")):
        rb.add("whois-registrant-phone", registrant.get("phone"), "Attribution")

    for ns in data.get("name_servers") or []:
        rb.add("hostname", _clean_host(ns), "Network activity")

    registered = data.get("domain_registered")
    if registered:
        rb.note(f"WHOIS: domain registered = {registered}")
    if data.get("expiry_date"):
        rb.note(f"WHOIS: expiry date = {data.get('expiry_date')}")


def _parse_whois_history(data, rb):
    if not isinstance(data, dict):
        return
    total = data.get("total_records")
    if total:
        rb.note(f"WHOIS history: {total} historical record(s) found.")
    records = data.get("whois_domains_historical") or []
    # Pull registrar / registrant details from the most recent record.
    for record in records[-1:]:
        _parse_whois_live(record, rb)


def _parse_whois_reverse(data, rb):
    if not isinstance(data, dict):
        return
    total = data.get("total_records") or data.get("totalRecords")
    if total:
        rb.note(f"Reverse WHOIS: {total} related domain(s).")
    domains = (
        data.get("whois_domains")
        or data.get("domains")
        or data.get("result")
        or []
    )
    for item in domains:
        name = item.get("domain_name") if isinstance(item, dict) else item
        rb.add("domain", name, "Network activity")


def _parse_ip_whois(data, rb):
    if not isinstance(data, dict):
        return
    org = data.get("organization") or {}
    if org.get("name"):
        rb.note(f"IP WHOIS org: {org.get('name')}")
    for inet in data.get("inet_nums") or []:
        for cidr in inet.get("cidr") or []:
            rb.note(f"IP WHOIS netblock: {cidr} ({inet.get('net_name', '')})")
    for contact in data.get("abuse_contacts") or []:
        for email in contact.get("email") or []:
            rb.add("email-src", email, "Attribution", comment="Abuse contact")


def _parse_asn_whois(data, rb):
    if not isinstance(data, dict):
        return
    parts = [
        f"AS{data.get('asNumber')}" if data.get("asNumber") else None,
        data.get("asName"),
        data.get("orgName"),
        data.get("country"),
        data.get("type"),
    ]
    summary = " | ".join(p for p in parts if p)
    if summary:
        rb.note(f"ASN WHOIS: {summary}")
    rb.add("domain", data.get("domain"), "Network activity")


def _parse_dns_records(records, rb):
    for record in records or []:
        dns_type = (record.get("dnsType") or "").upper()
        if dns_type in ("A", "AAAA"):
            rb.add("ip-dst", record.get("address"), "Network activity")
        elif dns_type in ("NS", "CNAME"):
            rb.add("hostname", _clean_host(record.get("singleName")),
                   "Network activity")
        elif dns_type == "MX":
            target = record.get("singleName") or record.get("exchange")
            rb.add("hostname", _clean_host(target), "Network activity")
        elif dns_type == "SOA":
            rb.add("dns-soa-email", _clean_host(record.get("admin")),
                   "Network activity")
        elif dns_type in ("TXT", "SPF"):
            raw = record.get("rawText") or record.get("text")
            if raw:
                rb.note(f"DNS {dns_type}: {raw}")


def _parse_dns_live(data, rb):
    if isinstance(data, dict):
        _parse_dns_records(data.get("dnsRecords"), rb)


def _parse_dns_history(data, rb):
    if not isinstance(data, dict):
        return
    if data.get("totalRecords"):
        rb.note(f"DNS history: {data.get('totalRecords')} record set(s).")
    for entry in data.get("historicalDnsRecords") or []:
        _parse_dns_records(entry.get("dnsRecords"), rb)


def _parse_dns_reverse(data, rb):
    if not isinstance(data, dict):
        return
    if data.get("totalRecords"):
        rb.note(f"Reverse DNS: {data.get('totalRecords')} match(es).")
    for entry in data.get("reverseDnsRecords") or []:
        rb.add("hostname", _clean_host(entry.get("domainName")),
               "Network activity")


def _parse_subdomains(data, rb):
    if not isinstance(data, dict):
        return
    if data.get("total_records"):
        rb.note(f"Subdomains: {data.get('total_records')} found.")
    for entry in data.get("subdomains") or []:
        name = entry.get("subdomain") if isinstance(entry, dict) else entry
        rb.add("hostname", _clean_host(name), "Network activity")


def _parse_availability(data, rb):
    if not isinstance(data, dict):
        return
    available = data.get("domainAvailability")
    domain = data.get("domain")
    if available is not None and domain:
        state = "available" if available else "registered / taken"
        rb.note(f"Domain availability: {domain} is {state}.")


# --- Input extraction -------------------------------------------------------

def _extract_input(request):
    """Return (attribute_type, attribute_value) from a MISP module request.

    Supports both the modern ``attribute`` payload and the legacy flat keys.
    """
    attribute = request.get("attribute")
    if isinstance(attribute, dict) and attribute.get("value"):
        return attribute.get("type"), attribute.get("value")
    for attr_type in mispattributes["input"]:
        if request.get(attr_type):
            return attr_type, request[attr_type]
    return None, None


# --- Dispatch per attribute type -------------------------------------------

def _handle_domain(value, apikey, cfg, rb):
    if _is_truthy(cfg.get("do_whois")):
        _parse_whois_live(
            _query(ENDPOINTS["whois_live"], apikey, {"domainName": value}), rb
        )
    if _is_truthy(cfg.get("do_dns")):
        _parse_dns_live(
            _query(
                ENDPOINTS["dns_live"], apikey,
                {"host-name": value, "type": DEFAULT_DNS_TYPES},
            ),
            rb,
        )
    if _is_truthy(cfg.get("do_availability")):
        _parse_availability(
            _query(ENDPOINTS["availability"], apikey, {"domain": value}), rb
        )
    if _is_truthy(cfg.get("do_subdomains")):
        _parse_subdomains(
            _query(ENDPOINTS["subdomains"], apikey, {"domain": value}), rb
        )
    if _is_truthy(cfg.get("do_history")):
        _parse_whois_history(
            _query(ENDPOINTS["whois_history"], apikey, {"domainName": value}), rb
        )
        _parse_dns_history(
            _query(
                ENDPOINTS["dns_history"], apikey,
                {"host-name": value, "type": DEFAULT_DNS_TYPES},
            ),
            rb,
        )


def _handle_ip(value, apikey, cfg, rb):
    if _is_truthy(cfg.get("do_whois")):
        _parse_ip_whois(
            _query(ENDPOINTS["ip_whois"], apikey, {"ip": value}), rb
        )
    if _is_truthy(cfg.get("do_reverse_dns"), default=False):
        _parse_dns_reverse(
            _query(
                ENDPOINTS["dns_reverse"], apikey,
                {"type": "A", "value": value},
            ),
            rb,
        )


def _handle_asn(value, apikey, cfg, rb):
    _parse_asn_whois(
        _query(ENDPOINTS["asn_whois"], apikey, {"asn": value}), rb
    )


def _handle_email(value, apikey, cfg, rb):
    _parse_whois_reverse(
        _query(ENDPOINTS["whois_reverse"], apikey, {"email": value}), rb
    )


# --- Module entry points ----------------------------------------------------

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    config = request.get("config") or {}
    apikey = config.get("apikey")
    if not apikey:
        misperrors["error"] = "An APIFreaks API key (apikey) is required."
        return misperrors

    attr_type, value = _extract_input(request)
    if not value:
        misperrors["error"] = "Unsupported or missing input attribute."
        return misperrors

    rb = _ResultBuilder()
    try:
        if attr_type in ("domain", "hostname"):
            _handle_domain(value, apikey, config, rb)
        elif attr_type in ("ip-src", "ip-dst"):
            _handle_ip(value, apikey, config, rb)
        elif attr_type == "AS":
            _handle_asn(value, apikey, config, rb)
        elif attr_type in _EMAIL_INPUTS:
            _handle_email(value, apikey, config, rb)
        else:
            misperrors["error"] = f"Unsupported attribute type: {attr_type}"
            return misperrors
    except requests.exceptions.HTTPError as error:
        status = error.response.status_code if error.response is not None else "?"
        misperrors["error"] = f"APIFreaks API returned HTTP {status}."
        return misperrors
    except requests.exceptions.RequestException:
        misperrors["error"] = "Could not reach the APIFreaks API."
        return misperrors

    return rb.build()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
