"""isMalicious MISP expansion and hover module.

Copy to misp_modules/modules/expansion/ismalicious.py, then open a PR against
MISP/misp-modules. Modules in that directory are auto-discovered.
"""

from __future__ import annotations

import json
from typing import Any

import requests

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["ip-src", "ip-dst", "hostname", "domain", "url", "domain|ip"],
    "output": ["text"],
}
moduleinfo = {
    "version": "1.0",
    "author": "isMalicious",
    "description": "Query isMalicious for IP, domain, hostname, and URL reputation.",
    "module-type": ["expansion", "hover"],
    "name": "isMalicious Lookup",
    "logo": "",
    "requirements": ["requests"],
    "features": "Returns malicious flag, risk score, categories, and source count.",
    "references": ["https://ismalicious.com/integrations/misp"],
    "input": "ip-src, ip-dst, hostname, domain, url, domain|ip",
    "output": "text attributes with score, categories, and sources",
}
moduleconfig = ["api_key", "api_url"]

DEFAULT_API_URL = "https://api.ismalicious.com"
checking_error = 'containing at least a "type" field and a "value" field'
standard_error_message = 'This module requires an "attribute" field as input'


def check_input_attribute(attribute, requirements=("type", "value")):
    return isinstance(attribute, dict) and all(
        feature in attribute for feature in requirements
    )


def check_indicator(
    query: str,
    api_key: str,
    api_url: str = DEFAULT_API_URL,
    timeout: int = 30,
) -> dict[str, Any]:
    if not query or not str(query).strip():
        raise ValueError("query is required")
    if not api_key:
        raise ValueError("api_key is required")

    response = requests.get(
        f"{api_url.rstrip('/')}/check",
        params={"query": str(query).strip(), "enrichment": "standard"},
        headers={"X-API-KEY": api_key, "Accept": "application/json"},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def _query_from_attribute(attribute: dict[str, Any]) -> str:
    value = str(attribute.get("value", ""))
    if attribute.get("type") == "domain|ip" and "|" in value:
        return value.split("|", 1)[0]
    return value


def _risk_score(payload: dict[str, Any]) -> int | None:
    raw = payload.get("riskScore")
    if isinstance(raw, dict):
        score = raw.get("score")
        return int(score) if score is not None else None
    if isinstance(raw, (int, float)):
        return int(raw)
    return None


def handler(q: bool | str = False):
    if q is False:
        return False
    request = json.loads(q) if isinstance(q, str) else q

    config = request.get("config") or {}
    api_key = config.get("api_key")
    if not api_key:
        return {"error": "isMalicious API key is missing"}

    attribute = request.get("attribute") or {}
    if not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, {checking_error}."}
    if attribute.get("type") not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    query = _query_from_attribute(attribute)
    try:
        payload = check_indicator(
            query,
            api_key=api_key,
            api_url=config.get("api_url") or DEFAULT_API_URL,
        )
    except requests.RequestException as exc:
        return {"error": f"isMalicious API request failed: {exc}"}
    except ValueError as exc:
        return {"error": str(exc)}

    malicious = bool(payload.get("malicious"))
    score = _risk_score(payload)
    categories = payload.get("categories") or payload.get("classification", {}).get(
        "primary"
    )
    sources = payload.get("sources") or []
    source_count = len(sources) if isinstance(sources, list) else sources

    summary = (
        f"malicious={malicious} score={score if score is not None else 'n/a'} "
        f"categories={categories} sources={source_count}"
    )
    return {
        "results": [{"types": "text", "values": summary}],
        "isMalicious": {
            "malicious": malicious,
            "riskScore": score,
            "categories": categories,
            "sourceCount": source_count,
        },
    }


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
