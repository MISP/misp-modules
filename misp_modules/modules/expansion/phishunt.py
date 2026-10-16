"""phishunt Lookup expansion/hover module.

Queries the phishunt (phishunt.io) public search API for phishing detections
of a host. The API needs no key. It does a substring match on the stored URL,
domain and IP fields (at most 200 rows, most recently first seen first), so
the module keeps only the rows whose host is exactly the queried host. Every
field of a row other than "domain" and "url" is optional, so every access
below goes through .get() defensively.

Only the read-only search endpoint is used. The /analyze endpoints of phishunt
are never called: they log the queried value and queue unknown domains for
analysis, which would leak an analyst's (possibly TLP-restricted) data into
the phishunt pipeline.

Mapping to MISP:
  - each phishunt detection (one row per reported URL) of the queried host
    becomes a `phishing` object (url, hostname, ip, targeted brand, first
    seen time and the phishunt uuid), referenced with "related-to" from the
    queried attribute. At most 25 objects are returned, the most recently
    first seen ones;
  - the object comment carries the context that has no object attribute:
    last check, hosting (ASN, organisation, country), TLS certificate issuer,
    the official provider IP range that contains the IP (network context, not
    a verdict) and the other feeds that flag the same URL;
  - one `link` attribute points to the phishunt search page of the host.

Only the "malicious_*" flags that are true are reported: a false flag means
the source did not flag the URL when checked (or was never asked), which is
not a clean verdict.

No confidence score, TLP or MISP tag is ever asserted: phishunt detections are
automated and can contain false positives. The url and ip attributes are not
flagged for IDS export either.
"""

import json
import time
from urllib.parse import quote, urlsplit

import requests
from pymisp import MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["domain", "hostname", "url"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "1",
    "author": "Daniel López",
    "description": (
        "Look up a host in phishunt (phishunt.io), the free CC0 feed of live phishing domains: the phishing URLs"
        " detected on that exact host, the brand they target, when they were first seen, where they are hosted and"
        " which other feeds flag them."
    ),
    "module-type": ["expansion", "hover"],
    "name": "phishunt Lookup",
    "requirements": ["No API key required."],
    "features": (
        "The module takes a domain, hostname or URL attribute (for a URL only the host is used) and queries the"
        " phishunt search API for it. The API does a substring match, so only the rows whose host is exactly the"
        " queried one are kept. Matches come back as phishing objects (URL, hostname, IP, targeted brand, first"
        " seen time) with hosting, TLS issuer, provider IP range and the other feeds that flag the same URL"
        " (OpenPhish, PhishTank, urlscan.io, Google Safe Browsing, TweetFeed) in the object comment, plus a link to"
        " the phishunt search page. At most 25 objects are returned. Only the read-only search endpoint is used:"
        " the phishunt analyze endpoints, which would submit the value for analysis, are never called. Detections"
        " are automated and can contain false positives, so no MISP tag or confidence score is set from them."
    ),
    "references": ["https://phishunt.io", "https://phishunt.io/api/", "https://phishunt.io/openapi.yaml"],
    "input": "A domain, hostname or URL attribute.",
    "output": (
        "phishing objects with the detected URLs, hostname, IP, targeted brand and first seen time, and a link"
        " attribute to the phishunt search page."
    ),
}
moduleconfig = []

API_URL = "https://phishunt.io/api/v1/search.json"
SEARCH_PAGE_URL = "https://phishunt.io/search/?q="
USER_AGENT = "misp-modules phishunt-expansion/1"
TIMEOUT = 15
SEARCH_LIMIT = 200
MAX_RESULTS = 25
MIN_QUERY_LENGTH = 3
DEFAULT_BACKOFF = 10
MAX_BACKOFF = 15

_FLAG_NAMES = {
    "malicious_google": "Google Safe Browsing",
    "malicious_openphish": "OpenPhish",
    "malicious_phishtank": "PhishTank",
    "malicious_tweetfeed": "TweetFeed",
    "malicious_urlscan": "urlscan.io",
}


def _normalise_host(host):
    """Lowercase, drop a trailing dot and convert an IDN host to its ASCII (punycode) form."""
    host = host.strip().replace("[.]", ".").lower().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _extract_host(attr_type, value):
    value = str(value).strip().replace("[.]", ".")
    if attr_type != "url":
        return _normalise_host(value)
    if "://" not in value and not value.startswith("//"):
        value = "//" + value
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return None
    return _normalise_host(host) if host else None


def _text(row, key):
    value = row.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _retry_delay(response):
    headers = getattr(response, "headers", None) or {}
    try:
        delay = float(headers.get("Retry-After", DEFAULT_BACKOFF))
    except (TypeError, ValueError):
        delay = DEFAULT_BACKOFF
    return min(max(delay, 1), MAX_BACKOFF)


def _fetch(host):
    """GET the search API, backing off once on HTTP 429 (Cloudflare rule: 20 requests per 10 s per IP)."""
    response = None
    for attempt in range(2):
        response = requests.get(
            API_URL, params={"q": host, "limit": SEARCH_LIMIT}, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT
        )
        if response.status_code != 429:
            break
        if attempt == 0:
            time.sleep(_retry_delay(response))
    return response


def _exact_matches(rows, host):
    matches = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not _text(row, "url"):
            continue
        domain = _text(row, "domain")
        if not domain or domain.lower().rstrip(".") != host:
            continue
        key = _text(row, "uuid") or row["url"]
        if key in seen:
            continue
        seen.add(key)
        matches.append(row)
    matches.sort(key=lambda row: str(row.get("first_seen") or ""), reverse=True)
    return matches


def _range_text(service_range):
    best = service_range.get("best") if isinstance(service_range, dict) else None
    if not isinstance(best, dict):
        return None
    provider = " ".join(part for part in (_text(best, "provider"), _text(best, "service")) if part)
    where = ", ".join(part for part in (_text(best, "region"), _text(best, "prefix")) if part)
    kind = _text(best, "kind_label")
    if not provider and not where:
        return None
    text = f"IP is inside the official range of {provider or 'a provider'}"
    if where:
        text += f" ({where})"
    if kind:
        text += f", {kind}"
    return text + " (network context, not a verdict)"


def _comment(row):
    parts = ["phishunt detection"]
    timing = []
    if _text(row, "first_seen"):
        timing.append(f"first seen {row['first_seen'].strip()}")
    if _text(row, "date"):
        timing.append(f"last checked {row['date'].strip()}")
    if timing:
        parts.append(", ".join(timing))

    hosting = []
    asn = _text(row, "asn")
    if asn:
        hosting.append(asn if asn.upper().startswith("AS") else f"AS{asn}")
    for key in ("org", "country"):
        if _text(row, key):
            hosting.append(row[key].strip())
    if hosting:
        parts.append("hosting: " + ", ".join(hosting))
    if _text(row, "cert"):
        parts.append(f"TLS issuer: {row['cert'].strip()}")
    range_text = _range_text(row.get("service_range"))
    if range_text:
        parts.append(range_text)
    flagged = [name for key, name in _FLAG_NAMES.items() if row.get(key) is True]
    if flagged:
        parts.append("also flagged by " + ", ".join(flagged))
    return " | ".join(parts)


def _new_phishing_object(row, uuid):
    obj = MISPObject("phishing")
    obj.comment = _comment(row)
    obj.add_attribute("url", type="url", value=row["url"].strip(), to_ids=False)
    obj.add_attribute("hostname", type="hostname", value=row["domain"].strip(), to_ids=False)
    if _text(row, "ip"):
        obj.add_attribute("ip", type="ip-dst", value=row["ip"].strip(), to_ids=False)
    if _text(row, "company"):
        obj.add_attribute("target", type="text", value=row["company"].strip(), disable_correlation=True)
    if _text(row, "first_seen"):
        obj.add_attribute("submission-time", type="datetime", value=row["first_seen"].strip())
    if _text(row, "uuid"):
        obj.add_attribute(
            "internal-reference", type="text", value=f"phishunt:{row['uuid'].strip()}", disable_correlation=True
        )
    if uuid:
        obj.add_reference(uuid, "related-to")
    return obj


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}

    attribute = request["attribute"]
    if attribute.get("type") not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    host = _extract_host(attribute["type"], attribute["value"])
    if not host:
        return {"error": "Could not extract a host from the attribute value."}
    if len(host) < MIN_QUERY_LENGTH:
        return {"error": f"The phishunt search needs at least {MIN_QUERY_LENGTH} characters."}
    uuid = attribute.get("uuid")

    try:
        response = _fetch(host)
    except requests.exceptions.RequestException as request_error:
        return {"error": f"phishunt API request failed: {request_error}"}

    if response.status_code == 429:
        return {
            "error": (
                "phishunt API rate limit reached (20 requests per 10 seconds per IP) and the retry was refused too."
                " Wait about 10 seconds and try again."
            )
        }
    if response.status_code != 200:
        return {"error": f"phishunt API returned HTTP {response.status_code}"}

    try:
        data = response.json()
    except ValueError:
        return {"error": "phishunt API returned an invalid JSON response."}
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return {"error": "phishunt API returned an unexpected response."}

    rows = data["results"]
    capped = len(rows) >= SEARCH_LIMIT
    matches = _exact_matches(rows, host)
    if not matches:
        message = f"No phishunt detection found for exactly {host}."
        if rows:
            message += f" {len(rows)} partial match(es) of other hosts were ignored."
        if capped:
            message += f" The search returned its {SEARCH_LIMIT}-row cap, so older rows may be missing."
        return {"error": message}

    misp_event = MISPEvent()
    for row in matches[:MAX_RESULTS]:
        misp_event.add_object(_new_phishing_object(row, uuid))

    comment = f"phishunt search page for {host}: {len(matches)} exact match(es)"
    if len(matches) > MAX_RESULTS:
        comment += f", the {MAX_RESULTS} most recently first seen are returned"
    if capped:
        comment += f"; the search returned its {SEARCH_LIMIT}-row cap, so older rows may be missing"
    misp_event.add_attribute(
        type="link", value=SEARCH_PAGE_URL + quote(host, safe=""), comment=comment, disable_correlation=True
    )

    event = json.loads(misp_event.to_json())
    results = {key: event[key] for key in ("Attribute", "Object") if event.get(key)}
    return {"results": results}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
