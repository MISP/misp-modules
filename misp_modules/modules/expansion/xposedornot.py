import json
from urllib.parse import quote

import requests
from pymisp import MISPEvent

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["email", "email-src", "email-dst", "target-email", "whois-registrant-email"],
    "output": ["text"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.0",
    "author": "XposedOrNot",
    "description": "Query the XposedOrNot API to check whether an email address appears in known data breaches.",
    "module-type": ["expansion", "hover"],
    "name": "XposedOrNot Lookup",
    "logo": "xposedornot.png",
    "requirements": ["No API key required."],
    "features": (
        "The module takes an email address as input and queries the XposedOrNot API to determine whether the"
        " address appears in known data breaches. Each exposure is returned as a text attribute holding the breach"
        " name, with the breach year, number of exposed records, affected domain, exposed data classes and password"
        " storage risk in its comment. Without any configuration the free keyless API is used (rate limits apply:"
        " 2 requests/second, 25/hour per IP); an optional commercial api_key switches to the higher-limit Plus API."
        " The queried email address is sent over TLS to xposedornot.com; nothing else leaves the MISP instance."
    ),
    "references": ["https://xposedornot.com", "https://api.xposedornot.com/docs"],
    "input": "An email address.",
    "output": "Breach exposure details for the email address, one text attribute per breach.",
}
moduleconfig = ["api_key"]

free_api_url = "https://api.xposedornot.com/v1/breach-analytics"
plus_api_url = "https://plus-api.xposedornot.com/v3/check-email"


def _normalise_free_breaches(data):
    """Map a free-API breach-analytics response to a common breach summary structure."""
    breaches = []
    exposed = data.get("ExposedBreaches") or {}
    for entry in exposed.get("breaches_details") or []:
        breaches.append(
            {
                "name": entry.get("breach"),
                "date": entry.get("xposed_date"),
                "records": entry.get("xposed_records"),
                "domain": entry.get("domain"),
                "data_classes": entry.get("xposed_data"),
                "password_risk": entry.get("password_risk"),
                "verified": entry.get("verified"),
            }
        )
    return breaches


def _normalise_plus_breaches(data):
    """Map a Plus-API detailed check-email response to a common breach summary structure."""
    breaches = []
    for entry in data.get("breaches") or []:
        breaches.append(
            {
                "name": entry.get("breach_id"),
                "date": entry.get("breached_date"),
                "records": entry.get("xposed_records"),
                "domain": entry.get("domain"),
                "data_classes": entry.get("xposed_data"),
                "password_risk": entry.get("password_risk"),
                "verified": entry.get("verified"),
            }
        )
    return breaches


def _risk_label(data):
    risk = (data.get("BreachMetrics") or {}).get("risk") or []
    if risk and isinstance(risk, list) and isinstance(risk[0], dict):
        return risk[0].get("risk_label")
    return None


def _format_records(records):
    try:
        return f"{int(records):,} records"
    except (TypeError, ValueError):
        return None


def _breach_comment(breach):
    parts = []
    if breach.get("date"):
        parts.append(f"breached: {breach['date']}")
    formatted_records = _format_records(breach.get("records"))
    if formatted_records:
        parts.append(formatted_records)
    if breach.get("domain"):
        parts.append(f"domain: {breach['domain']}")
    if breach.get("data_classes"):
        parts.append(f"exposed: {'; '.join(str(breach['data_classes']).split(';'))}")
    if breach.get("password_risk"):
        parts.append(f"password risk: {breach['password_risk']}")
    if breach.get("verified"):
        parts.append(f"verified: {breach['verified']}")
    return " | ".join(parts)


def _summary_value(breaches, risk_label):
    years = []
    for breach in breaches:
        try:
            years.append(int(str(breach.get("date"))[:4]))
        except (TypeError, ValueError):
            continue
    summary = f"Email exposed in {len(breaches)} data breach{'es' if len(breaches) != 1 else ''} (XposedOrNot)"
    if years:
        summary += f", first: {min(years)}, latest: {max(years)}"
    if risk_label:
        summary += f", risk: {risk_label}"
    return summary


class XposedOrNotParser:
    def __init__(self):
        self.misp_event = MISPEvent()

    def parse(self, breaches, risk_label):
        self.misp_event.add_attribute(
            type="text",
            value=_summary_value(breaches, risk_label),
            comment="XposedOrNot breach exposure summary",
            disable_correlation=True,
        )
        for breach in breaches:
            if not breach.get("name"):
                continue
            self.misp_event.add_attribute(
                type="text",
                value=breach["name"],
                comment=_breach_comment(breach),
                disable_correlation=True,
            )

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute",) if event.get(key)}
        if not results:
            return {"error": "No breach found on XposedOrNot for this email address."}
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

    email = str(attribute["value"]).strip().lower()
    if "@" not in email or len(email) > 254:
        return {"error": "The provided attribute value is not a valid email address."}

    config = request.get("config") or {}
    api_key = str(config.get("api_key") or "").strip()
    headers = {"User-Agent": "misp-modules"}
    try:
        if api_key:
            headers["x-api-key"] = api_key
            response = requests.get(
                f"{plus_api_url}/{quote(email, safe='')}",
                params={"detailed": "true"},
                headers=headers,
                timeout=30,
            )
        else:
            response = requests.get(free_api_url, params={"email": email}, headers=headers, timeout=30)
        if response.status_code == 404:
            return {"error": "No breach found on XposedOrNot for this email address."}
        if response.status_code == 429:
            return {
                "error": (
                    "XposedOrNot rate limit reached (keyless: 2 requests/second, 25/hour). Retry later or configure"
                    " the optional api_key to raise limits."
                )
            }
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.HTTPError as http_error:
        return {"error": f"XposedOrNot API returned HTTP status {http_error.response.status_code}."}
    except requests.exceptions.RequestException as request_error:
        return {"error": f"XposedOrNot API request failed: {request_error}."}
    except ValueError:
        return {"error": "XposedOrNot API returned an invalid JSON response."}

    breaches = _normalise_plus_breaches(data) if api_key else _normalise_free_breaches(data)
    if not breaches:
        return {"error": "No breach found on XposedOrNot for this email address."}
    parser = XposedOrNotParser()
    parser.parse(breaches, None if api_key else _risk_label(data))
    return parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
