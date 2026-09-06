"""TweetFeed Lookup expansion/hover module.

Queries the TweetFeed (tweetfeed.live) public API for IOCs (URLs, domains,
IPs, MD5/SHA256 hashes) reported by the infosec community on X/Twitter. The
API is queried with the attribute value unchanged (only whitespace-stripped);
TweetFeed normalises the value itself (defang, scheme, case). Every field
returned by the API other than found/query/window/records is optional, so
every access below goes through .get() defensively.

Mapping to MISP:
  - each TweetFeed "record" (one report of the queried value, extracted from
    a tweet) becomes a `microblog` object per underlying tweet URL. Tweet
    URLs are deduplicated: several records can point to the same tweet when
    it mentioned the value in more than one form (e.g. as both a domain and
    a URL);
  - IOCs "related" to the queried value (co-reported in the same tweet)
    become MISP attributes, referenced with "mentions" from the microblog
    object(s) they were extracted from;
  - the "ai" block becomes a single free-text attribute holding the
    LLM-generated summary. It is unverified, community-authored analysis: no
    MISP tag and no confidence score are asserted from it;
  - "reg" (domain registration/hosting) becomes a `domain-ip` object;
  - "net" (IP network metadata) becomes a free-text attribute;
  - "external" (corroboration from ThreatFox/URLhaus/...) becomes a link (or
    text) attribute per source;
  - "campaigns" (TweetFeed's own clustering) becomes a link attribute per
    campaign;
  - "archive" records (older than the 365-day live window) become
    `microblog` objects without a resolvable username, since the archive
    only keeps a synthetic status URL built from the tweet id.

No confidence score, TLP or MISP tag is ever asserted: everything TweetFeed
reports is community-submitted and not independently verified.
"""
import json
import re

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["ip-src", "ip-dst", "domain", "hostname", "url", "md5", "sha256"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "1",
    "author": "Daniel López",
    "description": (
        "Look up an IOC in TweetFeed (tweetfeed.live), the free CC0 feed of URLs, domains, IPs and hashes shared by"
        " the infosec community on X/Twitter: who reported it and when, the source tweets and hashtags, cross-feed"
        " corroboration, AI-generated context and campaign membership."
    ),
    "module-type": ["expansion", "hover"],
    "name": "TweetFeed Lookup",
    "requirements": ["No API key required."],
    "features": (
        "The module takes an IP, domain, hostname, URL, MD5 or SHA-256 attribute and queries the TweetFeed API for"
        " it. Matches come back as microblog objects for the source tweets (reporter, hashtags, first/last seen),"
        " plus attributes for co-reported IOCs, AI-generated context, domain registration and hosting, IP network"
        " metadata, corroboration from other feeds and campaign membership. Everything returned is community"
        " reported and unverified: no MISP tag or confidence score is set from it. The live 365-day window is"
        " queried first, and IOCs older than that are looked up in TweetFeed's separate archive."
    ),
    "references": ["https://tweetfeed.live", "https://tweetfeed.live/api/", "https://tweetfeed.live/hunt/"],
    "input": "An IP address, domain, hostname, URL, MD5 or SHA-256 attribute.",
    "output": (
        "microblog objects for the source tweets, domain-ip / text / link attributes with registration, network,"
        " corroboration, AI context and campaign data."
    ),
}
moduleconfig = []

API_URL = "https://api.tweetfeed.live/v1/ioc"
USER_AGENT = "misp-modules tweetfeed-expansion/1"
TIMEOUT = 15

_TWEET_URL_RE = re.compile(r"^https?://(?:www\.)?(?:x|twitter)\.com/([^/]+)/status/\d+", re.IGNORECASE)

_RELATED_TYPE_MAP = {"url": "url", "domain": "domain", "ip": "ip-dst", "sha256": "sha256", "md5": "md5"}

_EXTERNAL_SOURCE_NAMES = {
    "threatfox": "ThreatFox",
    "urlhaus": "URLhaus",
    "malwarebazaar": "MalwareBazaar",
    "usom": "USOM",
    "ipsum": "IPsum",
}


def _extract_username(tweet_url):
    match = _TWEET_URL_RE.match(tweet_url or "")
    return match.group(1) if match else None


def _new_microblog(uuid, tweet_url, username, tags, creation_date, comment):
    obj = MISPObject("microblog")
    obj.comment = comment
    obj.add_attribute("type", type="text", value="Twitter")
    obj.add_attribute("url", type="url", value=tweet_url)
    if username:
        obj.add_attribute("username", type="text", value=username)
    for tag in tags:
        obj.add_attribute("hashtag", type="text", value=tag)
    if creation_date:
        obj.add_attribute("creation-date", type="datetime", value=creation_date)
    if uuid:
        obj.add_reference(uuid, "mentions")
    return obj


def _add_records(misp_event, uuid, value, records):
    """Create microblog objects for each unique tweet, and attributes for the co-reported IOCs."""
    seen_tweets = set()
    record_objects = []
    for record in records:
        tweets = record.get("tweets") or []
        objs = []
        for tweet_url in tweets:
            if not tweet_url or tweet_url in seen_tweets:
                continue
            seen_tweets.add(tweet_url)
            creation_date = record.get("first_seen") if len(tweets) == 1 else None
            comment = (
                f"TweetFeed: {record.get('count')} report(s) of {record.get('value')}, first seen"
                f" {record.get('first_seen')}, last seen {record.get('last_seen')}"
            )
            objs.append(
                _new_microblog(
                    uuid, tweet_url, _extract_username(tweet_url), record.get("tags") or [], creation_date, comment
                )
            )
        if objs:
            record_objects.append((record, objs))

    related_uuids = {}
    for record, objs in record_objects:
        for related in record.get("related") or []:
            if not isinstance(related, (list, tuple)) or len(related) != 2:
                continue
            related_type, related_value = related
            if related_value == value:
                continue
            mapped_type = _RELATED_TYPE_MAP.get(related_type)
            if not mapped_type:
                continue
            key = (mapped_type, related_value)
            if key not in related_uuids:
                attribute = MISPAttribute()
                attribute.from_dict(
                    type=mapped_type,
                    value=related_value,
                    to_ids=False,
                    comment=f"Co-reported with {value} in the same tweet (TweetFeed)",
                )
                misp_event.add_attribute(**attribute)
                related_uuids[key] = attribute.uuid
            for obj in objs:
                obj.add_reference(related_uuids[key], "mentions")

    for _, objs in record_objects:
        for obj in objs:
            misp_event.add_object(obj)


def _add_ai(misp_event, ai):
    summary = ai.get("summary")
    if not summary:
        return
    value = summary
    if ai.get("threat_type"):
        value += f" | threat_type: {ai['threat_type']}"
    if ai.get("family"):
        value += f" | family: {ai['family']}"
    misp_event.add_attribute(
        type="text",
        value=value,
        comment="TweetFeed AI enrichment: LLM-generated from the source tweet, unverified",
        disable_correlation=True,
    )


def _add_reg(misp_event, uuid, reg):
    apex = reg.get("apex")
    if not apex:
        return
    obj = MISPObject("domain-ip")
    obj.add_attribute("domain", type="domain", value=apex)
    for ip in reg.get("ips") or []:
        obj.add_attribute("ip", type="ip-dst", value=ip, to_ids=False)
    if reg.get("created"):
        obj.add_attribute("registration-date", type="datetime", value=reg["created"])
    parts = []
    if reg.get("registrar"):
        parts.append(f"registrar: {reg['registrar']}")
    if reg.get("ns"):
        parts.append(f"NS: {', '.join(reg['ns'])}")
    if reg.get("asn") or reg.get("org"):
        parts.append(f"{reg.get('asn') or ''} {reg.get('org') or ''}".strip())
    if reg.get("age_days_at_report") is not None:
        age_text = f"{reg['age_days_at_report']} days old when first reported"
        if reg.get("newly_registered"):
            age_text += " (newly registered)"
        parts.append(age_text)
    if parts:
        obj.add_attribute("text", type="text", value=" | ".join(parts))
    if uuid:
        obj.add_reference(uuid, "related-to")
    misp_event.add_object(obj)


def _add_net(misp_event, net):
    parts = []
    if net.get("org"):
        asn = f" ({net['asn']})" if net.get("asn") else ""
        parts.append(f"{net['org']}{asn}")
    for key in ("city", "country"):
        if net.get(key):
            parts.append(net[key])
    if not parts:
        return
    value = "Network: " + ", ".join(parts)
    if net.get("fetched_at"):
        value += f" - as of {net['fetched_at']}"
    misp_event.add_attribute(type="text", value=value, comment="TweetFeed IP metadata", disable_correlation=True)


def _add_external(misp_event, external_entries):
    for entry in external_entries or []:
        name = _EXTERNAL_SOURCE_NAMES.get(entry.get("src"), entry.get("src"))
        sentence = f"Also listed in {name}: {entry.get('threat')} (added {entry.get('added')})"
        if entry.get("link"):
            misp_event.add_attribute(type="link", value=entry["link"], comment=sentence, disable_correlation=True)
        else:
            misp_event.add_attribute(type="text", value=sentence, disable_correlation=True)


def _add_campaigns(misp_event, campaigns):
    for campaign in campaigns or []:
        campaign_id = campaign.get("id")
        if not campaign_id:
            continue
        value = f"https://tweetfeed.live/campaigns/#{campaign_id}"
        comment = (
            f"TweetFeed campaign '{campaign.get('name')}' ({campaign.get('ioc_count')} IOCs, confidence"
            f" {campaign.get('confidence')}, last seen {campaign.get('last_seen')}); export:"
            f" https://api.tweetfeed.live/v1/campaigns/{campaign_id}"
        )
        misp_event.add_attribute(type="link", value=value, comment=comment, disable_correlation=True)


def _add_archive(misp_event, uuid, archive):
    for record in archive.get("records") or []:
        tweet_id = record.get("tweet_id")
        if not tweet_id:
            continue
        comment = (
            f"TweetFeed archive (older than 365 days): {record.get('count')} report(s), first seen"
            f" {record.get('first_seen')}, last seen {record.get('last_seen')}"
        )
        obj = MISPObject("microblog")
        obj.comment = comment
        obj.add_attribute("type", type="text", value="Twitter")
        obj.add_attribute("url", type="url", value=f"https://x.com/i/web/status/{tweet_id}")
        for tag in record.get("tags") or []:
            obj.add_attribute("hashtag", type="text", value=tag)
        if record.get("first_seen"):
            obj.add_attribute("creation-date", type="datetime", value=record["first_seen"])
        if uuid:
            obj.add_reference(uuid, "mentions")
        misp_event.add_object(obj)


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}

    attribute = request["attribute"]
    if attribute.get("type") not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    value = str(attribute["value"]).strip()
    uuid = attribute.get("uuid")

    try:
        response = requests.get(API_URL, params={"value": value}, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    except requests.exceptions.RequestException as request_error:
        return {"error": f"TweetFeed API request failed: {request_error}"}

    if response.status_code != 200:
        return {"error": f"TweetFeed API returned HTTP {response.status_code}"}

    try:
        data = response.json()
    except ValueError:
        return {"error": "TweetFeed API returned an invalid JSON response."}

    records = data.get("records") or []
    archive = data.get("archive") or {}
    archive_records = archive.get("records") or []
    if not data.get("found") and not records and not archive_records:
        return {"error": "No IOC report found on TweetFeed for this value."}

    misp_event = MISPEvent()
    _add_records(misp_event, uuid, value, records)
    if data.get("ai"):
        _add_ai(misp_event, data["ai"])
    if data.get("reg"):
        _add_reg(misp_event, uuid, data["reg"])
    if data.get("net"):
        _add_net(misp_event, data["net"])
    if data.get("external"):
        _add_external(misp_event, data["external"])
    if data.get("campaigns"):
        _add_campaigns(misp_event, data["campaigns"])
    if archive_records:
        _add_archive(misp_event, uuid, archive)

    event = json.loads(misp_event.to_json())
    results = {key: event[key] for key in ("Attribute", "Object") if event.get(key)}
    return {"results": results}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
