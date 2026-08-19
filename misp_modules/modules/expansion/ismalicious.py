import json

import requests
from pymisp import MISPEvent

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["ip-src", "ip-dst", "hostname", "domain", "url", "domain|ip"],
    "output": ["text"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.0",
    "author": "isMalicious",
    "description": "Query isMalicious for IP, domain, hostname, and URL reputation.",
    "module-type": ["expansion", "hover"],
    "name": "isMalicious Lookup",
    "logo": "",
    "requirements": ["An isMalicious API key."],
    "features": (
        "The module takes an IP, domain, hostname or URL attribute and queries GET /check on the isMalicious API."
        " It returns a text summary with the malicious flag, risk score, categories and source count. Hover and"
        " expansion share the same handler. The queried indicator is sent over TLS; nothing else leaves the MISP"
        " instance besides the configured API key."
    ),
    "references": ["https://ismalicious.com/integrations/misp"],
    "input": "An IP address, domain, hostname or URL.",
    "output": "Text attributes with the isMalicious reputation summary.",
}
moduleconfig = ["api_key", "api_url"]

DEFAULT_API_URL = "https://api.ismalicious.com"


def _query_from_attribute(attribute):
    value = str(attribute.get("value", "")).strip()
    if attribute.get("type") == "domain|ip" and "|" in value:
        return value.split("|", 1)[0]
    return value


def _risk_score(payload):
    raw = payload.get("riskScore")
    if isinstance(raw, dict):
        score = raw.get("score")
        return int(score) if score is not None else None
    if isinstance(raw, (int, float)):
        return int(raw)
    return None


def _categories(payload):
    categories = payload.get("categories")
    if categories:
        return categories
    classification = payload.get("classification") or {}
    return classification.get("primary")


def _source_count(payload):
    sources = payload.get("sources") or []
    return len(sources) if isinstance(sources, list) else sources


class IsMaliciousParser:
    def __init__(self):
        self.misp_event = MISPEvent()

    def parse(self, payload):
        malicious = bool(payload.get("malicious"))
        score = _risk_score(payload)
        categories = _categories(payload)
        source_count = _source_count(payload)
        summary = (
            f"malicious={malicious} score={score if score is not None else 'n/a'} "
            f"categories={categories} sources={source_count}"
        )
        self.misp_event.add_attribute(
            type="text",
            value=summary,
            comment="isMalicious reputation summary",
            disable_correlation=True,
        )

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute",) if event.get(key)}
        if not results:
            return {"error": "No results from isMalicious for this attribute."}
        return {"results": results}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an UUID."}

    attribute = request["attribute"]
    if attribute.get("type") not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}

    config = request.get("config") or {}
    api_key = str(config.get("api_key") or "").strip()
    if not api_key:
        return {"error": "An isMalicious API key is required (set api_key in the module config)."}

    query = _query_from_attribute(attribute)
    if not query:
        return {"error": "The provided attribute value is empty."}

    api_url = str(config.get("api_url") or DEFAULT_API_URL).rstrip("/")
    try:
        response = requests.get(
            f"{api_url}/check",
            params={"query": query, "enrichment": "standard"},
            headers={"User-Agent": "misp-modules", "X-API-KEY": api_key, "Accept": "application/json"},
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.exceptions.HTTPError as http_error:
        status = http_error.response.status_code if http_error.response is not None else "unknown"
        return {"error": f"isMalicious API returned HTTP status {status}."}
    except requests.exceptions.RequestException as request_error:
        return {"error": f"isMalicious API request failed: {request_error}."}
    except ValueError:
        return {"error": "isMalicious API returned an invalid JSON response."}

    parser = IsMaliciousParser()
    parser.parse(payload)
    return parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
