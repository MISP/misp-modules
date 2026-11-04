import ipaddress
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["domain", "hostname", "url", "domain|ip", "ip-src", "ip-dst"],
    "output": ["text", "datetime", "link"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.2",
    "author": "Slava Olesik",
    "description": (
        "Check a domain, hostname, URL or IP address against the NetAPI compromised feeds and get the domain's"
        " position in the NetAPI Top 1M."
    ),
    "module-type": ["expansion", "hover"],
    "name": "NetAPI Lookup",
    "logo": "netapi.png",
    "requirements": [],
    "features": (
        "The module takes a domain, hostname, URL (by its host) or IP address attribute and queries the free"
        " compromised-check method of the NetAPI JSON API."
        "\n\nFor a domain or hostname it says whether the value, or the registered domain a hostname belongs to,"
        " is in the NetAPI feed of hosts that public threat feeds report for malware or phishing: listed now (seen"
        " within the last 24 hours), listed in the past only, or never listed, with the first and last seen dates,"
        " the reporting feed and the registrar of the domain. A second free method, domain-rank, gives the position"
        " of the registered domain in the NetAPI Top 1M, a daily popularity ranking: a top-ranked domain in the"
        " feed is more likely a compromised legitimate site than infrastructure set up by the attacker."
        "\n\nFor an IP address it checks the NetAPI compromised IP feed, the IPv4 addresses that attacked the"
        " sensors of NetAPI Nightwatch, NetAPI's own honeypot network: listed now (seen within the last 48 hours),"
        " listed in the past only, or never listed, with the first seen date, the time of the last attack and the"
        " type of attack. Private, loopback and reserved addresses are not sent."
        "\n\nThe answer is a reputation object linked to the queried attribute: classification malicious when the"
        " value is listed now, suspicious when only its registered domain is, and unknown when it is listed in the"
        " past only or never (the feed holds no opinion on a value it does not list), with the first and last seen"
        " dates, a link to the NetAPI domain or IP lookup and the details (for a domain also the Top 1M rank) in"
        " its text."
        "\n\nNo API key is required. An optional NetAPI API token only raises the request limits (30 requests a"
        " minute and 1,000 a day per IP address without one). Only the queried indicator leaves the MISP instance."
    ),
    "references": [
        "https://netapi.com/compromised-urls/",
        "https://netapi.com/compromised-ips/",
        "https://netapi.com/top-1-mln-websites/",
        "https://netapi.com/help/api/#json-api",
    ],
    "input": "A domain, hostname, URL or IP address.",
    "output": "A reputation object with the feed listing and, for a domain, the Top 1M rank.",
}
# No API key is needed: api_token only raises the request limits, and api_url is exposed
# only so an operator can point the module at a different deployment.
moduleconfig = ["api_token", "api_url"]

DEFAULT_API_URL = "https://netapi.com/api-json/"
USER_AGENT = "netapi-misp/1.2 (+https://github.com/MISP/misp-modules)"
LOOKUP_URL = "https://netapi.com/lookup-domain/{}/"
LOOKUP_IP_URL = "https://netapi.com/lookup-ip/{}/"
TIMEOUT = 30


class NetAPIError(Exception):
    """The API refused the request or could not be reached; the message says why."""


def _query_value(attribute):
    """Return the host name to look up."""
    value = str(attribute.get("value", "")).strip()
    attribute_type = attribute.get("type")

    if attribute_type == "domain|ip" and "|" in value:
        return value.split("|", 1)[0].strip()
    if attribute_type == "url":
        # A URL stored without a scheme is still a URL to MISP; urlparse only finds the
        # host after "//".
        parsed = urlparse(value if "://" in value else "//" + value)
        return (parsed.hostname or "").rstrip(".")
    return value.rstrip(".").lower()


def _ip(value):
    """The value as an IP address, or None for a host name."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _get(api_url, token, method, **params):
    """GET one JSON API method. Errors come back as {"error": {"code", "message"}}."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = requests.get(api_url, params={"method": method, **params}, headers=headers, timeout=TIMEOUT)
    except requests.exceptions.RequestException as error:
        raise NetAPIError(f"the NetAPI API could not be reached: {error}") from error

    try:
        body = response.json()
    except ValueError as error:
        raise NetAPIError(f"the NetAPI API returned HTTP {response.status_code} without JSON") from error

    if response.status_code >= 400 or not isinstance(body, dict):
        error = body.get("error") if isinstance(body, dict) else None
        message = (error or {}).get("message") if isinstance(error, dict) else None
        message = message or f"HTTP {response.status_code}"
        if response.status_code == 429 and response.headers.get("Retry-After"):
            message += f" (retry after {response.headers['Retry-After']} s)"
        raise NetAPIError(message)
    return body


def _listing_summary(value, check):
    """One line describing what the feed says about the value."""
    if not check.get("listed_ever"):
        return f"NetAPI compromised feed: {value} is not listed, now or in the past"

    if check.get("listed_now"):
        # The IP feed keeps an address for 48 hours after its last attack, the domain feed 24 hours.
        hours = 48 if check.get("type") == "ip" else 24
        status = f"listed now (seen within the last {hours} hours)"
    else:
        last_seen = str(check.get("last_seen") or "")[:10]
        status = f"listed in the past (last seen {last_seen}), not in the current feed"

    parts = [f"NetAPI compromised feed: {value} is {status}"]
    matched = check.get("matched_value")
    if matched and matched != value:
        parts.append(f"matched entry: {matched} (the registered domain)")
    if check.get("first_seen"):
        parts.append(f"first seen {check['first_seen']}")
    if check.get("last_seen"):
        parts.append(f"last seen {check['last_seen']}")
    if check.get("block_reason"):
        parts.append(f"reported by {check['block_reason']}")
    registrar = check.get("registrar")
    if isinstance(registrar, dict) and (registrar.get("brand_name") or registrar.get("name")):
        parts.append(f"registrar {registrar.get('brand_name') or registrar.get('name')}")
    return " | ".join(parts)


def _rank_summary(rank):
    """One line with the Top 1M position of the registered domain."""
    domain = rank.get("domain")
    if rank.get("in_top_1m"):
        snapshot = f" (snapshot of {rank['snapshot_date']})" if rank.get("snapshot_date") else ""
        return f"NetAPI Top 1M: {domain} is ranked #{rank.get('rank')}{snapshot}"
    return f"NetAPI Top 1M: {domain} is not in the NetAPI Top 1M"


def _classification(query, check):
    """
    MISP reads malicious, suspicious and benign as a verdict and any other word as no opinion.
    Only a current listing is a verdict; a hostname that matched through its registered domain
    is not itself on the list, so it gets the weaker word.
    """
    if not check.get("listed_now"):
        return "unknown"
    matched = check.get("matched_value")
    return "malicious" if not matched or matched == query else "suspicious"


def _iso_datetime(value):
    """
    The API gives "2026-10-26 01:05:27 UTC" or a bare date. pymisp raises on a datetime it cannot
    parse, so any other form is left out of the field; the text still carries it.
    """
    value = str(value or "").strip()
    for date_format in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, date_format).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an UUID."}

    attribute = request["attribute"]
    if attribute.get("type") not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    query = _query_value(attribute)
    if not query:
        return {"error": "The provided attribute value is empty."}
    address = _ip(query)
    if address is not None and not address.is_global:
        return {"error": "Private, loopback and reserved addresses are not looked up."}

    config = request.get("config") or {}
    api_url = str(config.get("api_url") or DEFAULT_API_URL)
    token = str(config.get("api_token") or "").strip() or None

    try:
        check = _get(api_url, token, "compromised-check", value=query)
    except NetAPIError as error:
        return {"error": f"NetAPI lookup failed: {error}"}

    text = _listing_summary(query, check)
    if address is not None:
        # The Top 1M ranks domains only.
        list_name, lookup_url = "NetAPI compromised IPs", LOOKUP_IP_URL
    else:
        list_name, lookup_url = "NetAPI compromised domains", LOOKUP_URL
        # The rank is context, so a failure here is reported next to the listing instead of
        # discarding the answer that was already obtained.
        try:
            text += "\n" + _rank_summary(_get(api_url, token, "domain-rank", domain=query))
        except NetAPIError as error:
            text += f"\nNetAPI Top 1M rank unavailable: {error}"

    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    # Typed explicitly, since pymisp does not bundle the reputation template yet. Nothing in
    # the object correlates: every lookup would otherwise share "NetAPI", the list name and
    # the verdict word with every other one.
    reputation = MISPObject("reputation")
    fields = [
        ("classification", "text", _classification(query, check)),
        ("source", "text", "NetAPI"),
        ("list-name", "text", list_name),
        ("first-seen", "datetime", _iso_datetime(check.get("first_seen"))),
        ("last-seen", "datetime", _iso_datetime(check.get("last_seen"))),
        ("link", "link", lookup_url.format(check.get("matched_value") or query)),
        ("text", "text", text),
    ]
    for relation, attribute_type, value in fields:
        if value:
            reputation.add_attribute(relation, type=attribute_type, value=value, to_ids=False, disable_correlation=True)
    reputation.add_reference(input_attribute.uuid, "related-to")
    misp_event.add_object(reputation)

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if event.get(key)}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
