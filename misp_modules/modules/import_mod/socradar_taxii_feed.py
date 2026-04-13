"""
SOCRadar TAXII Feed Import Module for MISP
============================================
Import threat intelligence indicators from SOCRadar's TAXII 2.1 server
into MISP events with rich tagging (MITRE ATT&CK, TLP, malware families,
confidence levels, feed sources, and geo tags).

SOCRadar's TAXII server provides STIX 2.1 indicators enriched with:
  - MITRE ATT&CK technique mappings
  - Malware family classifications
  - Confidence scores (0-100)
  - SOCRadar threat scores
  - Feed source attribution
  - Geographic attribution (country tags)

How it works:
  1. If no collection UUID is provided, the module first fetches the list
     of available collections and returns them as a summary so the user
     can pick the right UUID.
  2. If a collection UUID is provided, the module fetches indicators from
     that collection and returns them as MISP attributes with full tagging.

Configuration (MISP → Server Settings → Plugin Settings → Import):
  - socradar_taxii_url:     TAXII base URL (default: https://taxii2.socradar.com)
  - socradar_api_root:      API root path (default: radar_alpha)
  - socradar_username:       TAXII username
  - socradar_password:       TAXII password
"""

import json
import re
import urllib.parse

import requests

misperrors = {"error": "Error"}

userConfig = {
    "collection_id": {
        "type": "String",
        "message": (
            "TAXII collection UUID to fetch indicators from. "
            "Leave EMPTY and type 'list' in Paste Input to see all available collections with their UUIDs."
        ),
    },
    "default_tlp": {
        "type": "String",
        "message": "Default TLP marking for imported indicators (e.g. tlp:amber). Default: tlp:amber",
    },
    "max_indicators": {
        "type": "String",
        "message": (
            "Maximum number of indicators to import per run. "
            "Default: 500. Set to 0 for unlimited (may cause timeout on large collections)."
        ),
    },
}

inputSource = ["paste"]

moduleinfo = {
    "version": "1.1",
    "author": "SOCRadar",
    "description": (
        "Import threat indicators from SOCRadar TAXII 2.1 feed "
        "with MITRE ATT&CK, malware family, confidence, and geo tagging. "
        "Leave collection_id empty and type 'list' to discover available collections."
    ),
    "module-type": ["import"],
    "name": "SOCRadar TAXII Feed Import",
    "logo": "socradar.png",
    "requirements": ["requests"],
    "features": (
        "Connect to SOCRadar TAXII 2.1 server and import enriched "
        "threat indicators into MISP. Indicators are automatically "
        "tagged with MITRE ATT&CK techniques, malware families, "
        "confidence levels, feed sources, and country information. "
        "Supports collection auto-discovery — leave collection_id "
        "empty and type 'list' to see all available collections."
    ),
    "references": [
        "https://socradar.io",
        "https://docs.socradar.io/taxii",
    ],
    "input": "SOCRadar TAXII 2.1 collection endpoint.",
    "output": "MISP attributes with rich tagging.",
}

moduleconfig = [
    "socradar_taxii_url",
    "socradar_api_root",
    "socradar_username",
    "socradar_password",
]

# ═══════════════════════════════════════════════════════════════════════════
# Known malware families
# ═══════════════════════════════════════════════════════════════════════════

KNOWN_MALWARE = {
    "redline",
    "redline stealer",
    "raccoon",
    "raccoon stealer",
    "vidar",
    "stealc",
    "risepro",
    "lumma",
    "lumma stealer",
    "meduza",
    "meduza stealer",
    "azorult",
    "aurora",
    "emotet",
    "trickbot",
    "qakbot",
    "qbot",
    "icedid",
    "bumblebee",
    "batloader",
    "pikabot",
    "smokeloader",
    "amadey",
    "systembc",
    "danabot",
    "darkgate",
    "asyncrat",
    "remcos",
    "njrat",
    "nanocore",
    "darkcomet",
    "agent tesla",
    "agenttesla",
    "formbook",
    "xworm",
    "lokibot",
    "warzone",
    "dcrat",
    "cobalt strike",
    "cobaltstrike",
    "metasploit",
    "sliver",
    "havoc",
    "brute ratel",
    "mythic",
    "mirai",
    "gafgyt",
    "mozi",
    "hajime",
    "lockbit",
    "blackcat",
    "alphv",
    "clop",
    "cl0p",
    "conti",
    "royal",
    "black basta",
    "akira",
    "rhysida",
    "play",
    "medusa ransomware",
    "8base",
    "hunters international",
    "bianlian",
    "cactus",
    "blacksuit",
    "prometei",
    "xmrig",
    "coinminer",
    "cryptonight",
    "screenconnect",
    "connectwise",
}

# ═══════════════════════════════════════════════════════════════════════════
# TAXII 2.1 client
# ═══════════════════════════════════════════════════════════════════════════


def _taxii_headers():
    return {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1",
    }


def _taxii_get(url, username, password):
    resp = requests.get(
        url,
        headers=_taxii_headers(),
        auth=(username, password),
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()


def _get_credentials(config):
    base = config.get("socradar_taxii_url", "https://taxii2.socradar.com").rstrip("/")
    api_root = config.get("socradar_api_root", "radar_alpha").strip("/")
    username = config.get("socradar_username", "")
    password = config.get("socradar_password", "")
    if not username or not password:
        raise ValueError(
            "SOCRadar TAXII username and password are required. Configure them in Plugin Settings → Import."
        )
    return base, api_root, username, password


# ═══════════════════════════════════════════════════════════════════════════
# Collection discovery
# ═══════════════════════════════════════════════════════════════════════════


def _list_collections(config):
    """Fetch available collections and return them as a text summary."""
    base, api_root, username, password = _get_credentials(config)
    url = f"{base}/{api_root}/collections/"
    data = _taxii_get(url, username, password)
    collections = data.get("collections", [])

    if not collections:
        return {
            "results": [
                {
                    "types": ["text"],
                    "values": ["No collections found on SOCRadar TAXII server."],
                }
            ]
        }

    results = []

    # Summary text
    lines = [
        f"Found {len(collections)} SOCRadar TAXII collections.",
        "",
        (
            "Copy the UUID of the collection you want and paste it into the "
            "'collection_id' field, then run the import again."
        ),
        "",
        "=" * 60,
    ]

    for i, col in enumerate(collections, 1):
        col_id = col.get("id", "")
        title = col.get("title", "Unknown")
        desc = col.get("description", "")

        lines.append("")
        lines.append(f"[{i}] {title}")
        lines.append(f"    UUID: {col_id}")
        if desc:
            lines.append(f"    Feeds: {desc[:200]}")
        lines.append(f"    Readable: {col.get('can_read', False)}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("To import: go to Populate from → SOCRadar TAXII Feed → paste the UUID into collection_id field.")

    results.append(
        {
            "types": ["text"],
            "categories": ["External analysis"],
            "values": ["\n".join(lines)],
            "comment": "SOCRadar TAXII Collection List",
        }
    )

    return {"results": results}


# ═══════════════════════════════════════════════════════════════════════════
# Parsing helpers
# ═══════════════════════════════════════════════════════════════════════════


def _extract_ioc_from_pattern(pattern):
    if not pattern:
        return None
    m = re.search(
        r"\[(\S+?):(?:value|hashes\.(?:'[^']+?'|\S+?))\s*=\s*'([^']+)'\]",
        pattern,
    )
    if not m:
        return None
    obj_type, value = m.group(1).lower(), m.group(2)
    type_map = {
        "ipv4-addr": "ip-dst",
        "ipv6-addr": "ip-dst",
        "domain-name": "domain",
        "url": "url",
        "email-addr": "email-dst",
    }
    if obj_type in type_map:
        return type_map[obj_type], value
    if obj_type == "file":
        ht_match = re.search(r"hashes\.(?:'([^']+)'|(\S+?))\s*=", pattern)
        if ht_match:
            ht = (ht_match.group(1) or ht_match.group(2)).lower()
            ht = ht.replace("-", "").replace("'", "")
            misp_ht = {
                "md5": "md5",
                "sha1": "sha1",
                "sha256": "sha256",
                "sha512": "sha512",
                "ssdeep": "ssdeep",
            }.get(ht, ht)
            return misp_ht, value
        vl = len(value)
        if vl == 32:
            return "md5", value
        elif vl == 40:
            return "sha1", value
        elif vl == 64:
            return "sha256", value
        return "md5", value
    return None


def _confidence_tag(confidence):
    if confidence is None:
        return 'confidence-level:confidence="unknown"'
    c = float(confidence)
    if c >= 80:
        return 'confidence-level:confidence="completely-confident"'
    if c >= 60:
        return 'confidence-level:confidence="usually-confident"'
    if c >= 40:
        return 'confidence-level:confidence="fairly-confident"'
    if c >= 20:
        return 'confidence-level:confidence="rarely-confident"'
    return 'confidence-level:confidence="unconfident"'


def _extract_mitre(indicator):
    techniques = set()
    for lbl in indicator.get("labels", []):
        for tid in re.findall(r"[Tt]\d{4}(?:\.\d{3})?", lbl):
            techniques.add(tid.upper())
    ext = indicator.get("extensions", {}).get("extra-info-ext", {})
    for tag in ext.get("tags", []):
        if tag.get("type") == "MITRE_ATTCK":
            for tid in re.findall(r"[Tt]\d{4}(?:\.\d{3})?", tag.get("tag", "")):
                techniques.add(tid.upper())
    return sorted(techniques)


def _extract_countries(indicator):
    countries = []
    ext = indicator.get("extensions", {}).get("extra-info-ext", {})
    for tag in ext.get("tags", []):
        if tag.get("type") == "COUNTRY" and tag.get("tag"):
            countries.append(tag["tag"].strip().lower())
    return countries


def _extract_feed_sources(indicator):
    sources = []
    top = indicator.get("threat_feed_source_name")
    if top:
        sources.append(top)
    ext = indicator.get("extensions", {}).get("extra-info-ext", {})
    for fs in ext.get("feed_source_list", []):
        name = fs.get("source_name", "")
        if name and name not in sources:
            sources.append(name)
    return sources


def _detect_malware(indicator):
    searchable = list(indicator.get("labels", []))
    desc = indicator.get("description", "")
    if desc and desc != "N/A":
        searchable.append(desc)
    name = indicator.get("name", "")
    if name:
        searchable.append(name)
    ext = indicator.get("extensions", {}).get("extra-info-ext", {})
    for tag in ext.get("tags", []):
        if tag.get("tag"):
            searchable.append(tag["tag"])
    combined = " ".join(searchable).lower()
    for family in KNOWN_MALWARE:
        if re.search(r"\b" + re.escape(family) + r"\b", combined):
            return family.title()
    return None


def _get_score(indicator):
    ext = indicator.get("extensions", {}).get("extra-info-ext", {})
    score = ext.get("score")
    return float(score) if score is not None else None


# ═══════════════════════════════════════════════════════════════════════════
# Indicator fetcher with limit
# ═══════════════════════════════════════════════════════════════════════════


def _fetch_indicators(config, collection_id, max_indicators=500):
    """Fetch indicators from a single collection with a limit."""
    base, api_root, username, password = _get_credentials(config)
    all_indicators = []
    objects_url = f"{base}/{api_root}/collections/{collection_id}/objects/"
    page = 0
    max_pages = 20

    while objects_url and page < max_pages:
        page += 1
        envelope = _taxii_get(objects_url, username, password)
        page_objects = envelope.get("objects", [])

        for obj in page_objects:
            if obj.get("type") == "indicator":
                all_indicators.append(obj)
                if max_indicators > 0 and len(all_indicators) >= max_indicators:
                    return all_indicators

        if envelope.get("more", False) and envelope.get("next"):
            base_url = f"{base}/{api_root}/collections/{collection_id}/objects/"
            objects_url = f"{base_url}?next={urllib.parse.quote(envelope['next'])}"
        else:
            objects_url = None

    return all_indicators


# ═══════════════════════════════════════════════════════════════════════════
# MISP module interface
# ═══════════════════════════════════════════════════════════════════════════


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)
    config = request.get("config", {})

    # Get user config
    collection_id = config.get("collection_id", "").strip()
    default_tlp = config.get("default_tlp", "tlp:amber").strip()
    if not default_tlp:
        default_tlp = "tlp:amber"

    max_ind_str = config.get("max_indicators", "500").strip()
    try:
        max_indicators = int(max_ind_str) if max_ind_str else 500
    except ValueError:
        max_indicators = 500

    # If no collection_id provided → list collections
    if not collection_id:
        try:
            return _list_collections(config)
        except Exception as e:
            misperrors["error"] = f"SOCRadar TAXII collection discovery failed: {str(e)}"
            return misperrors

    # Fetch indicators from the specified collection
    try:
        indicators = _fetch_indicators(config, collection_id, max_indicators)
    except Exception as e:
        misperrors["error"] = f"SOCRadar TAXII fetch failed: {str(e)}"
        return misperrors

    if not indicators:
        return {
            "results": [
                {
                    "types": ["text"],
                    "values": [
                        f"No indicators found in collection {collection_id}. "
                        "The collection may be empty or the UUID may be incorrect."
                    ],
                }
            ]
        }

    # Build MISP results
    results = []
    seen_values = set()

    for ind in indicators:
        parsed = _extract_ioc_from_pattern(ind.get("pattern", ""))
        if not parsed:
            continue

        attr_type, attr_value = parsed

        if attr_value in seen_values:
            continue
        seen_values.add(attr_value)

        # Build tags
        tags = [default_tlp, "source:SOCRadar", "type:OSINT", "socradar:feed"]

        for tid in _extract_mitre(ind):
            tags.append(f"mitre-attack:{tid}")

        conf = ind.get("confidence")
        tags.append(_confidence_tag(conf))

        score = _get_score(ind)
        if score is not None:
            tags.append(f"socradar:score={score}")

        family = _detect_malware(ind)
        if family:
            tags.append(f"malware:{family.lower()}")

        for c in _extract_countries(ind):
            tags.append(f"country:{c}")

        sources = _extract_feed_sources(ind)
        for src in sources:
            tags.append(f"feed-source:{src}")

        # Comment
        comment_parts = []
        desc = ind.get("description", "")
        if desc and desc != "N/A":
            comment_parts.append(desc[:200])
        if sources:
            comment_parts.append(f"Sources: {', '.join(sources)}")
        comment = " | ".join(comment_parts) if comment_parts else ""

        # to_ids
        ind_types = ind.get("indicator_types", [])
        to_ids = "malicious-activity" in ind_types or not ind_types

        result = {
            "types": [attr_type],
            "values": [attr_value],
            "comment": comment,
            "tags": tags,
            "to_ids": to_ids,
        }
        results.append(result)

    # Add summary as first result
    summary = f"SOCRadar TAXII Import: {len(results)} indicators imported from collection {collection_id}"
    if max_indicators > 0 and len(indicators) >= max_indicators:
        summary += f" (limited to {max_indicators}, more available)"

    results.insert(
        0,
        {
            "types": ["text"],
            "categories": ["External analysis"],
            "values": [summary],
            "comment": "SOCRadar TAXII Feed Import Summary",
        },
    )

    return {"results": results}


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup["inputSource"] = inputSource
    except NameError:
        pass
    modulesetup["format"] = "misp_standard"
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
