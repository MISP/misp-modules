"""
SOCRadar Threat Intelligence Expansion Module for MISP
=======================================================
Enrich MISP attributes (IP, domain, URL, hash) by querying SOCRadar's
IoC Enrichment API. Returns threat context including categorization,
malware families, threat actors, MITRE ATT&CK mappings, confidence
levels, feed source history, and geographic attribution.

Two enrichment modes:
  1. STIX mode (default) — calls /indicator_details_stix for fast,
     structured STIX 2.1 output. Best for automated enrichment.
  2. Full mode — calls /indicator_details for rich JSON output with
     categorization, classifications, score, history, and optionally
     AI-generated insight (slower due to AI processing).

Requires a SOCRadar Advanced Threat Intelligence API key.
Get yours at: https://platform.socradar.com → API Management

Configuration (MISP → Server Settings → Plugin Settings → Enrichment):
  - socradar_api_key:    SOCRadar API key (required)
  - socradar_api_url:    API base URL (default: https://platform.socradar.com/api)
  - socradar_mode:       "stix" (fast) or "full" (detailed). Default: full
  - socradar_ai_insight: Include AI insight in full mode (slower). Default: false
"""

import json
import re

import requests

misperrors = {"error": "Error"}

mispattributes = {
    "input": [
        "ip-src",
        "ip-dst",
        "domain",
        "hostname",
        "url",
        "md5",
        "sha1",
        "sha256",
        "email-src",
        "email-dst",
    ],
    "output": ["text"],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "1.0",
    "author": "SOCRadar",
    "description": (
        "Enrich MISP attributes with SOCRadar threat intelligence. "
        "Queries SOCRadar IoC Enrichment API for categorization, "
        "malware families, threat actors, confidence scores, "
        "feed source history, and geographic attribution."
    ),
    "module-type": ["expansion", "hover"],
    "name": "SOCRadar Threat Intelligence",
    "logo": "socradar.png",
    "requirements": ["requests"],
    "features": (
        "Query SOCRadar IoC Enrichment API to enrich MISP attributes with "
        "threat intelligence context. Supports IP, domain, URL, hash, and "
        "email lookups. Two modes: STIX (fast) and Full (detailed with "
        "categorization, history, and optional AI insight). "
        "Requires a SOCRadar Advanced Threat Intelligence API key."
    ),
    "references": [
        "https://socradar.io",
        "https://platform.socradar.com",
    ],
    "input": (
        "A MISP attribute of type ip-src, ip-dst, domain, hostname, url, md5, sha1, sha256, email-src, or email-dst."
    ),
    "output": (
        "Enrichment data including categorization, malware families, "
        "threat actors, confidence score, SOCRadar threat score, "
        "feed source history, and country attribution."
    ),
}

moduleconfig = [
    "socradar_api_key",
    "socradar_api_url",
    "socradar_mode",
    "socradar_ai_insight",
]

# ═══════════════════════════════════════════════════════════════════════════
# API base URL
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_API_URL = "https://platform.socradar.com/api"

# ═══════════════════════════════════════════════════════════════════════════
# API calls
# ═══════════════════════════════════════════════════════════════════════════


def _api_headers(api_key):
    return {
        "Content-Type": "application/json",
        "API-Key": api_key,
    }


def _call_indicator_details(api_url, api_key, indicator, include_ai=False):
    """Call /ioc_enrichment/get/indicator_details for rich JSON output."""
    url = f"{api_url}/ioc_enrichment/get/indicator_details"

    fields = [
        "indicator_details",
        "indicator_history",
        "indicator_relations",
    ]
    if include_ai:
        fields.append("indicator_ai_insight")

    payload = {
        "indicator": indicator,
        "fields": fields,
    }

    resp = requests.post(
        url,
        headers=_api_headers(api_key),
        json=payload,
        timeout=30 if not include_ai else 60,
    )
    resp.raise_for_status()
    return resp.json()


def _call_indicator_details_stix(api_url, api_key, indicator):
    """Call /ioc_enrichment/get/indicator_details_stix for STIX output."""
    url = f"{api_url}/ioc_enrichment/get/indicator_details_stix"

    payload = {
        "indicator": indicator,
        "show_credit_details": False,
    }

    resp = requests.post(
        url,
        headers=_api_headers(api_key),
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


# ═══════════════════════════════════════════════════════════════════════════
# Result formatters
# ═══════════════════════════════════════════════════════════════════════════


def _format_full_result(data, indicator):
    """Format /indicator_details JSON response into readable text + tags."""
    lines = []
    tags = []

    lines.append("══════ SOCRadar Threat Intelligence ══════")
    lines.append(f"Indicator: {indicator}")
    lines.append("")

    # --- Score & Confidence ---
    details = data.get("details", {})
    score = details.get("score")
    if score is not None:
        lines.append(f"SOCRadar Score: {score}/100")
        tags.append(f"socradar:score={score}")

    cross_conf = data.get("cross_source_confidence")
    if cross_conf:
        lines.append(f"Cross-Source Confidence: {cross_conf}")
        conf_map = {
            "Very High": 'confidence-level:confidence="completely-confident"',
            "High": 'confidence-level:confidence="usually-confident"',
            "Medium": 'confidence-level:confidence="fairly-confident"',
            "Low": 'confidence-level:confidence="rarely-confident"',
        }
        if cross_conf in conf_map:
            tags.append(conf_map[cross_conf])

    signal = data.get("ioc_signal_strength")
    if signal:
        lines.append(f"IoC Signal Strength: {signal}")
        tags.append(f"socradar:signal={signal.lower().replace(' ', '-')}")

    lines.append("")

    # --- Categorization ---
    cat = data.get("categorization", {})
    active_cats = [k for k, v in cat.items() if v is True]
    if active_cats:
        lines.append(f"Categorization: {', '.join(active_cats)}")
        for c in active_cats:
            tags.append(f"socradar:category={c}")
        lines.append("")

    # --- Classifications ---
    cls = data.get("classifications", {})

    malwares = cls.get("malwares", [])
    if malwares:
        lines.append(f"Malware Families: {', '.join(malwares)}")
        for mw in malwares:
            tags.append(f"malware:{mw.lower()}")

    threat_actors = cls.get("threat_actors", [])
    if threat_actors:
        lines.append(f"Threat Actors: {', '.join(threat_actors)}")
        for ta in threat_actors:
            tags.append(f"threat-actor:{ta.lower()}")

    industries = cls.get("industries", [])
    if industries:
        lines.append(f"Targeted Industries: {', '.join(industries)}")

    campaign = cls.get("campaign")
    if campaign:
        lines.append(f"Campaign: {campaign}")

    target_countries = cls.get("target_country_list", [])
    if target_countries:
        lines.append(f"Target Countries: {', '.join(target_countries)}")

    country = cls.get("country")
    if country:
        lines.append(f"Origin Country: {country}")
        tags.append(f"country:{country.lower()}")

    lines.append("")

    # --- Summary (ASN, geo) ---
    summary = data.get("summary", {})
    if summary:
        geo_parts = []
        if summary.get("city"):
            geo_parts.append(summary["city"])
        if summary.get("region"):
            geo_parts.append(summary["region"])
        if summary.get("country"):
            geo_parts.append(summary["country"])
        if geo_parts:
            lines.append(f"Location: {', '.join(geo_parts)}")

        asn = summary.get("asn_name")
        asn_code = summary.get("asn_code")
        if asn:
            lines.append(f"ASN: {asn} (AS{asn_code})" if asn_code else f"ASN: {asn}")

        lines.append("")

    # --- Details (dates) ---
    first_seen = details.get("first_seen_date")
    last_seen = details.get("last_seen_date")
    if first_seen:
        lines.append(f"First Seen: {first_seen}")
    if last_seen:
        lines.append(f"Last Seen: {last_seen}")

    # --- History ---
    history = data.get("history", {})
    hist_items = history.get("indicator_history", [])
    if hist_items:
        lines.append("")
        lines.append(f"Feed History ({len(hist_items)} records):")
        for h in hist_items[:10]:  # Show max 10
            event = h.get("event", "")
            source = h.get("feed_source", "")
            date = h.get("insert_date", "")
            lines.append(f"  [{date}] {source}: {event[:80]}")
            if source:
                tags.append(f"feed-source:{source}")
        if len(hist_items) > 10:
            lines.append(f"  ... and {len(hist_items) - 10} more")

    # --- AI Insight ---
    ai = data.get("ai_insight", {})
    insight = ai.get("insight")
    if insight:
        lines.append("")
        lines.append("AI Insight:")
        lines.append(f"  {insight[:500]}")
        if len(insight) > 500:
            lines.append("  [truncated]")

    # Dedup tags
    tags = list(dict.fromkeys(tags))

    # Add source tag
    tags.insert(0, "source:SOCRadar")

    return "\n".join(lines), tags


def _format_stix_result(data, indicator):
    """Format /indicator_details_stix STIX bundle into readable text + tags."""
    lines = []
    tags = ["source:SOCRadar"]

    lines.append("══════ SOCRadar Threat Intelligence (STIX) ══════")
    lines.append(f"Indicator: {indicator}")
    lines.append("")

    objects = data.get("objects", [])

    # Find indicator objects
    for obj in objects:
        if obj.get("type") != "indicator":
            continue

        name = obj.get("name", "")
        pattern = obj.get("pattern", "")
        labels = obj.get("labels", [])

        if name:
            lines.append(f"Name: {name}")
        if pattern:
            lines.append(f"Pattern: {pattern}")

        if labels:
            lines.append(f"Labels: {', '.join(labels)}")

            # Extract MITRE techniques
            for lbl in labels:
                for tid in re.findall(r"[Tt]\d{4}(?:\.\d{3})?", lbl):
                    tags.append(f"mitre-attack:{tid.upper()}")

        # Check for extensions
        ext = obj.get("extensions", {}).get("extra-info-ext", {})
        score = ext.get("score")
        if score is not None:
            lines.append(f"SOCRadar Score: {score}")
            tags.append(f"socradar:score={score}")

        ext_tags = ext.get("tags", [])
        mitre_tags = [t for t in ext_tags if t.get("type") == "MITRE_ATTCK"]
        if mitre_tags:
            lines.append("")
            lines.append("MITRE ATT&CK:")
            for mt in mitre_tags:
                tid = mt.get("tag", "").upper()
                desc = mt.get("description", "")
                lines.append(f"  {tid}: {desc}" if desc else f"  {tid}")
                tags.append(f"mitre-attack:{tid}")

        content_tags = [t for t in ext_tags if t.get("type") == "TAG"]
        if content_tags:
            tag_names = [t.get("tag", "") for t in content_tags if t.get("tag")]
            lines.append(f"Tags: {', '.join(tag_names)}")

        country_tags = [t for t in ext_tags if t.get("type") == "COUNTRY"]
        if country_tags:
            countries = [t.get("tag", "") for t in country_tags if t.get("tag")]
            lines.append(f"Country: {', '.join(countries)}")
            for c in countries:
                tags.append(f"country:{c.lower()}")

        feed_sources = ext.get("feed_source_list", [])
        if feed_sources:
            lines.append("")
            lines.append("Feed Sources:")
            for fs in feed_sources:
                name = fs.get("source_name", "")
                count = fs.get("seen_count", "")
                first = fs.get("first_seen_date", "")
                lines.append(f"  {name} (seen: {count}, first: {first})")
                if name:
                    tags.append(f"feed-source:{name}")

    # Find identity objects
    for obj in objects:
        if obj.get("type") == "identity":
            identity_name = obj.get("name", "")
            if identity_name:
                lines.append(f"Source Identity: {identity_name}")

    # Dedup tags
    tags = list(dict.fromkeys(tags))

    return "\n".join(lines), tags


# ═══════════════════════════════════════════════════════════════════════════
# MISP module interface
# ═══════════════════════════════════════════════════════════════════════════


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)
    config = request.get("config", {})

    # --- Validate API key ---
    api_key = config.get("socradar_api_key", "").strip()
    if not api_key:
        misperrors["error"] = (
            "SOCRadar API key is required. "
            "Get your Advanced Threat Intelligence API key at "
            "https://platform.socradar.com → API Management"
        )
        return misperrors

    api_url = config.get("socradar_api_url", DEFAULT_API_URL).rstrip("/")
    mode = config.get("socradar_mode", "full").strip().lower()
    include_ai = config.get("socradar_ai_insight", "false").strip().lower() in ("true", "1", "yes")

    # --- Extract attribute value ---
    attribute = request.get("attribute", {})
    search_value = attribute.get("value", "")

    if not search_value:
        for attr_type in mispattributes["input"]:
            if attr_type in request:
                search_value = request[attr_type]
                break

    if not search_value:
        misperrors["error"] = "No attribute value provided for enrichment"
        return misperrors

    # --- Query SOCRadar API ---
    try:
        if mode == "stix":
            data = _call_indicator_details_stix(api_url, api_key, search_value)
            enrichment_text, tags = _format_stix_result(data, search_value)
        else:
            data = _call_indicator_details(api_url, api_key, search_value, include_ai)
            enrichment_text, tags = _format_full_result(data, search_value)

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else "unknown"
        if status == 401:
            misperrors["error"] = (
                "SOCRadar API authentication failed. "
                "Please check your API key. "
                "A valid Advanced Threat Intelligence API key is required. "
                "Get yours at https://platform.socradar.com → API Management"
            )
        elif status == 400:
            misperrors["error"] = f"SOCRadar API bad request for indicator: {search_value}"
        else:
            misperrors["error"] = f"SOCRadar API error (HTTP {status}): {str(e)}"
        return misperrors

    except requests.exceptions.Timeout:
        misperrors["error"] = (
            "SOCRadar API request timed out. If using AI insight mode, try disabling it for faster results."
        )
        return misperrors

    except Exception as e:
        misperrors["error"] = f"SOCRadar API query failed: {str(e)}"
        return misperrors

    # --- Return results ---
    result = {
        "types": ["text"],
        "values": [enrichment_text],
        "tags": tags,
    }

    return {"results": [result]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
