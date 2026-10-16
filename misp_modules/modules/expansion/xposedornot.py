import json
from urllib.parse import quote

import requests
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

misperrors = {"error": "Error"}

mispattributes = {
    "input": ["email", "email-src", "email-dst", "target-email", "whois-registrant-email"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "1.1",
    "author": "XposedOrNot",
    "description": "Query the XposedOrNot API to check whether an email address appears in known data breaches.",
    "module-type": ["expansion", "hover"],
    "name": "XposedOrNot Lookup",
    "logo": "xposedornot.png",
    "requirements": ["No API key required."],
    "features": (
        "The module takes an email address as input and queries the XposedOrNot API to determine whether the"
        " address appears in known data breaches. Each exposure is returned as a breach object holding the breach"
        " name, date, number of exposed records, affected domain, exposed data classes and password storage risk."
        " Without any configuration the free keyless API is used (rate limits apply:"
        " 2 requests/second, 25/hour per IP); an optional commercial api_key switches to the higher-limit Plus API."
        " The queried email address is sent over TLS to xposedornot.com; nothing else leaves the MISP instance."
    ),
    "references": ["https://xposedornot.com", "https://api.xposedornot.com/docs"],
    "input": "An email address.",
    "output": "One breach object per data breach the email address appears in.",
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


def _breach_date(date):
    """XposedOrNot dates a breach by year. Anchor a bare year to its first day,
    which is the only way a datetime relation can carry it."""
    date = str(date or "").strip()
    if not date:
        return None
    return f"{date}-01-01" if len(date) == 4 and date.isdigit() else date


def _boolean(value):
    """XposedOrNot spells its booleans several ways; anything it does not
    recognise is left out rather than guessed at."""
    if isinstance(value, bool):
        return str(value)
    normalised = str(value or "").strip().lower()
    if normalised in ("yes", "true", "1"):
        return "True"
    if normalised in ("no", "false", "0"):
        return "False"
    return None


def _data_classes(data_classes):
    if not data_classes:
        return []
    if isinstance(data_classes, list):
        values = data_classes
    else:
        values = str(data_classes).split(";")
    return [value.strip() for value in values if value and value.strip()]


class XposedOrNotParser:
    """Every relation is typed explicitly: the breach and reputation templates
    are new enough that pymisp does not bundle them yet."""

    def __init__(self, attribute):
        self.misp_event = MISPEvent()
        self.input_attribute = MISPAttribute()
        self.input_attribute.from_dict(**attribute)
        self.misp_event.add_attribute(**self.input_attribute)

    def _add_if(self, misp_object, relation, value, attribute_type):
        if value is None or value == "":
            return
        misp_object.add_attribute(relation, **{"type": attribute_type, "value": value})

    def parse(self, breaches, risk_label):
        for breach in breaches:
            if not breach.get("name"):
                continue
            misp_object = MISPObject("breach")
            misp_object.add_attribute("name", **{"type": "text", "value": breach["name"]})
            misp_object.add_attribute("source", **{"type": "text", "value": "XposedOrNot"})
            self._add_if(misp_object, "breach-date", _breach_date(breach.get("date")), "datetime")
            self._add_if(misp_object, "pwn-count", breach.get("records"), "counter")
            self._add_if(misp_object, "domain", breach.get("domain"), "domain")
            self._add_if(misp_object, "verified", _boolean(breach.get("verified")), "boolean")
            for data_class in _data_classes(breach.get("data_classes")):
                misp_object.add_attribute("data-classes", **{"type": "text", "value": data_class})
            # password_risk is the one normalised field the breach template has
            # no relation of its own for.
            if breach.get("password_risk"):
                self._add_if(misp_object, "description", f"password storage risk: {breach['password_risk']}", "text")
            misp_object.add_reference(self.input_attribute.uuid, "related-to")
            self.misp_event.add_object(misp_object)

        if risk_label:
            # A verdict on the address itself rather than on any one breach.
            reputation = MISPObject("reputation")
            reputation.add_attribute("source", **{"type": "text", "value": "XposedOrNot"})
            reputation.add_attribute("classification", **{"type": "text", "value": risk_label})
            reputation.add_reference(self.input_attribute.uuid, "related-to")
            self.misp_event.add_object(reputation)

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        if not event.get("Object"):
            return {"error": "No breach found on XposedOrNot for this email address."}
        return {"results": {key: event[key] for key in ("Attribute", "Object") if event.get(key)}}


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
    parser = XposedOrNotParser(attribute)
    parser.parse(breaches, None if api_key else _risk_label(data))
    return parser.get_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
