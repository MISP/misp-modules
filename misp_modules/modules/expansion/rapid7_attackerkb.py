"""
AttackerKB MISP Module

Author: R7 Labs
Description: Enrich CVEs via AttackerKB API and return structured MISP events.
"""

import json
import re
import logging
from typing import Any

import requests
from pymisp import MISPEvent, MISPObject

# Configure logging to stdout with standard timestamped format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,%(msecs)03d - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    force=True
)
logger = logging.getLogger(__name__)

# Constants
API_BASE_URL = "https://api.attackerkb.com/v1"
moduleconfig: list[str] = ["api_key"]
misperrors: dict[str, str] = {"error": "Unable to query AttackerKB API"}
mispattributes: dict[str, str | list[str]] = {
    "input": ["vulnerability", "comment"],
    "output": ["MISPObject"],
    "format": "misp_standard"
}
moduleinfo: dict[str, Any] = {
    "version": "48",
    "author": "R7 Labs",
    "description": "Enrich CVEs via AttackerKB and return structured MISP events. Handles rate limits, regex CVE detection, and markdown cleanup.",
    "module-type": ["expansion", "hover"],
    "name": "r7_akb",
    "requirements": ["pymisp", "requests"],
    "input": "Vulnerability attribute (CVE ID or comment containing CVE).",
    "output": "Structured MISP Objects.",
    "logo": ""
}

# Global HTTP session (stateless re-use; not an application state container)
session = requests.Session()


# ---------------------------
# HTTP / API helpers
# ---------------------------

def fetch_json(path: str, headers: dict[str, str]) -> dict[str, Any]:
    """Send GET request to the AttackerKB API and return JSON object."""
    url = f"{API_BASE_URL}/{path.lstrip('/')}"
    logger.info(f"GET {url}")
    resp = session.get(url, headers=headers)
    logger.info(f"Response status: {resp.status_code}")
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise TypeError("Expected JSON object at top level")
    return data


def get_topic_id(cve_id: str, headers: dict[str, str]) -> str | None:
    """Retrieve the topic ID for a given CVE."""
    data = fetch_json(f"topics?name={cve_id}", headers)
    topics = data.get("data", [])
    logger.info(f"Topics found for {cve_id}: {len(topics) if isinstance(topics, list) else 0}")
    if isinstance(topics, list) and topics:
        first = topics[0]
        if isinstance(first, dict):
            tid = first.get("id")
            return tid if isinstance(tid, str) else None
    return None


def get_detail(topic_id: str, headers: dict[str, str]) -> dict[str, Any]:
    """Get detailed topic data with tags and references."""
    logger.info(f"Fetching details for topic ID {topic_id}")
    data = fetch_json(f"topics/{topic_id}?expand=tags,references", headers)
    detail = data.get("data", {})
    return detail if isinstance(detail, dict) else {}


def get_assessments(topic_id: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    """Retrieve all assessments for a topic."""
    logger.info(f"Fetching assessments for topic ID {topic_id}")
    data = fetch_json(f"assessments?topicId={topic_id}", headers)
    items = data.get("data", [])
    return items if isinstance(items, list) else []


def get_contributor_username(editor_id: str, headers: dict[str, str]) -> str:
    data = fetch_json(f"contributors/{editor_id}", headers)
    user = data.get("data", {})
    if isinstance(user, dict):
        username = user.get("username")
        if isinstance(username, str):
            return username
    return f"Unknown ({editor_id})"


# ---------------------------
# Data mapping / formatting
# ---------------------------

def map_score_label(value: float | int | str | None) -> str:
    """Map numeric score to descriptive label."""
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "Unknown"
    if score <= 0:
        return "Unknown"
    for threshold, label in [(1.5, "Very Low"), (2.5, "Low"), (3.5, "Medium"), (4.5, "High")]:
        if score < threshold:
            return label
    return "Very High"


def remove_markdown(text: str) -> str:
    """Strip markdown formatting from text."""
    if not text:
        return ''
    text = re.sub(r'#+\s*', '', text)
    text = re.sub(r'(\*\*?|__|_|`)(.*?)\1', r'\2', text)
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    text = re.sub(r'!\[.*?\]\(.*?\)', '', text)
    text = re.sub(r'^>\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'^(-{3,}|_{3,}|\*{3,})$', '', text, flags=re.MULTILINE)
    text = re.sub(r'<[^>]+>', '', text)
    return text.strip()


# ---------------------------
# MISP object builders
# ---------------------------

def build_report(detail: dict[str, Any]) -> MISPObject:
    """Create attackerkb-report MISP object."""
    obj = MISPObject("attackerkb-report")
    meta = detail.get("metadata", {}) if isinstance(detail.get("metadata", {}), dict) else {}
    score_data = detail.get("score", {}) if isinstance(detail.get("score", {}), dict) else {}

    obj.add_attribute("cve-id", detail.get("name"), type="text")
    obj.add_attribute("description", detail.get("document", ""), type="text", disable_correlation=True)
    obj.add_attribute("permalink", f"https://attackerkb.com/topics/{detail.get('id')}", type="link")

    cvss_metric = meta.get("cvssMetricV31", {}) if isinstance(meta.get("cvssMetricV31", {}), dict) else {}
    cvss_data = cvss_metric.get("cvssData", {}) if isinstance(cvss_metric.get("cvssData", {}), dict) else {}
    obj.add_attribute("cvss-score", cvss_data.get("baseScore"), type="float")

    obj.add_attribute("attacker-value", map_score_label(score_data.get("attackerValue")), type="text")
    obj.add_attribute("exploitability", map_score_label(score_data.get("exploitability")), type="text")

    return obj


def build_references(detail: dict[str, Any]) -> MISPObject | None:
    """Build attackerkb-references MISP object from detail."""
    refs = detail.get("references", [])
    if not isinstance(refs, list) or not refs:
        return None
    obj = MISPObject("attackerkb-references")
    for ref in refs:
        if isinstance(ref, dict):
            url = ref.get("url")
            if isinstance(url, str) and url:
                obj.add_attribute("reference-url", url, type="link")
    return obj


def build_assessments(topic_id: str, headers: dict[str, str]) -> list[MISPObject]:
    """Create attackerkb-assessment MISP objects from assessments."""
    objs: list[MISPObject] = []
    for a in get_assessments(topic_id, headers):
        if not isinstance(a, dict):
            continue
        mo = MISPObject("attackerkb-assessment")
        editor_id = a.get("editorId")
        if isinstance(editor_id, str):
            contributor = get_contributor_username(editor_id, headers)
        else:
            contributor = "Unknown"
        mo.add_attribute("contributor", contributor, type="text")
        mo.add_attribute("attacker-value", map_score_label(a.get("score")), type="text")

        md = a.get("metadata", {})
        if not isinstance(md, dict):
            md = {}
        mo.add_attribute("exploitability", map_score_label(md.get("exploitability")), type="text")

        doc = a.get("document")
        if isinstance(doc, str) and doc:
            mo.add_attribute("notes", doc, type="text", disable_correlation=True)
        objs.append(mo)
    return objs


# ---------------------------
# Result / error helpers
# ---------------------------

def build_error_event(message: str) -> MISPEvent:
    """Construct a MISP event containing an error object."""
    event = MISPEvent()
    obj = MISPObject("attackerkb-error")
    obj.add_attribute("error", message, type="text", disable_correlation=True)
    event.add_object(**obj.to_dict())
    return event


def get_result(event: MISPEvent) -> dict[str, Any]:
    """Serialize and return the MISP event."""
    ev = json.loads(event.to_json())
    # Only return keys MISP expects in results
    return {"results": {k: ev[k] for k in ("Attribute", "Object") if ev.get(k)}}


# ---------------------------
# MISP module entrypoints
# ---------------------------

def handler(q: Any = False) -> dict[str, Any]:
    """Main handler for MISP expansion module."""
    try:
        payload = json.loads(q.decode()) if isinstance(q, (bytes, bytearray)) else q
        if not isinstance(payload, dict):
            return get_result(build_error_event("Invalid payload"))

        attribute = payload.get("attribute", {})
        attribute_value = attribute.get("value", "") if isinstance(attribute, dict) else ""
        config = payload.get("config", {})
        api_key = config.get("api_key") if isinstance(config, dict) else None

        if not attribute_value or not isinstance(api_key, str):
            return get_result(build_error_event("Missing CVE input or API key"))

        cve_matches = set(re.findall(r"CVE-\d{4}-\d{4,7}", attribute_value))
        if not cve_matches:
            return get_result(build_error_event("No valid CVE found"))

        headers: dict[str, str] = {"Authorization": f"Bearer {api_key}"}
        event = MISPEvent()

        for cve in sorted(cve_matches):
            logger.info(f"Processing CVE: {cve}")
            topic_id = get_topic_id(cve, headers)
            if not topic_id:
                logger.info(f"CVE not found in AttackerKB: {cve}")
                # Optionally, add a lightweight note object indicating a miss
                miss = MISPObject("attackerkb-miss")
                miss.add_attribute("cve-id", cve, type="text")
                miss.add_attribute("note", "CVE not found in AttackerKB", type="text", disable_correlation=True)
                event.add_object(**miss.to_dict())
                continue

            detail = get_detail(topic_id, headers)
            event.add_object(**build_report(detail).to_dict())

            ref = build_references(detail)
            if ref:
                event.add_object(**ref.to_dict())

            ra = detail.get("rapid7Analysis")
            if isinstance(ra, str) and ra:
                mo = MISPObject("attackerkb-rapid7-analysis")
                mo.add_attribute("rapid7-analysis", remove_markdown(ra), type="text", disable_correlation=True)
                event.add_object(**mo.to_dict())

            for mo in build_assessments(topic_id, headers):
                event.add_object(**mo.to_dict())

        return get_result(event)

    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        return get_result(build_error_event(str(e)))


def introspection() -> dict[str, Any]:
    """Return MISP module attributes."""
    return mispattributes


def version() -> dict[str, Any]:
    """Return MISP module version and configuration."""
    moduleinfo["config"] = moduleconfig
    return moduleinfo
