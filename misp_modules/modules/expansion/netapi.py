import ipaddress
import json
from urllib.parse import urlparse

import requests
from pymisp import MISPEvent

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["domain", "hostname", "url", "domain|ip"],
    "output": ["text"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.0",
    "author": "Slava Olesik",
    "description": (
        "Check a domain, hostname or URL against the NetAPI compromised feed and get the domain's position in the"
        " NetAPI Top 1M."
    ),
    "module-type": ["expansion", "hover"],
    "name": "NetAPI Lookup",
    "logo": "netapi.png",
    "requirements": [],
    "features": (
        "The module takes a domain, hostname or URL (by its host) attribute and queries two free methods of the"
        " NetAPI JSON API. compromised-check says whether the value, or the registered domain a hostname belongs"
        " to, is in the NetAPI feed of hosts that public threat feeds report for malware or phishing: listed now"
        " (seen within the last 24 hours), listed in the past only, or never listed, with the first and last seen"
        " dates, the reporting feed and the registrar of the domain. domain-rank gives the position of the"
        " registered domain in the NetAPI Top 1M, a daily popularity ranking: a top-ranked domain in the feed is"
        " more likely a compromised legitimate site than infrastructure set up by the attacker. IP addresses are"
        " not covered, so a URL whose host is an IP address is not looked up."
        "\n\nNo API key is required. An optional NetAPI API token only raises the request limits (30 requests a"
        " minute and 1,000 a day per IP address without one). Only the queried indicator leaves the MISP instance."
    ),
    "references": [
        "https://netapi.com/compromised-urls/",
        "https://netapi.com/top-1-mln-websites/",
        "https://netapi.com/help/api/#json-api",
    ],
    "input": "A domain, hostname or URL.",
    "output": "Text attributes describing the feed listing and the Top 1M rank.",
}
# No API key is needed: api_token only raises the request limits, and api_url is exposed
# only so an operator can point the module at a different deployment.
moduleconfig = ["api_token", "api_url"]

DEFAULT_API_URL = "https://netapi.com/api-json/"
USER_AGENT = "netapi-misp/1.0 (+https://github.com/MISP/misp-modules)"
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


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


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
        status = "listed now (seen within the last 24 hours)"
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
    if _is_ip(query):
        return {"error": "NetAPI covers domain names only. IP addresses are not looked up."}

    config = request.get("config") or {}
    api_url = str(config.get("api_url") or DEFAULT_API_URL)
    token = str(config.get("api_token") or "").strip() or None

    try:
        check = _get(api_url, token, "compromised-check", value=query)
    except NetAPIError as error:
        return {"error": f"NetAPI lookup failed: {error}"}

    misp_event = MISPEvent()
    misp_event.add_attribute(
        type="text",
        value=_listing_summary(query, check),
        comment="NetAPI: compromised feed listing",
        disable_correlation=True,
    )

    # The rank is context, so a failure here is reported next to the listing instead of
    # discarding the answer that was already obtained.
    try:
        rank_value = _rank_summary(_get(api_url, token, "domain-rank", domain=query))
    except NetAPIError as error:
        rank_value = f"NetAPI Top 1M rank unavailable: {error}"
    misp_event.add_attribute(
        type="text",
        value=rank_value,
        comment="NetAPI: Top 1M popularity rank",
        disable_correlation=True,
    )

    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if event.get(key)}}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
