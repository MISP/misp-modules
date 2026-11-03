import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address

import requests
from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {"input": ["domain", "hostname"], "format": "misp_standard"}
moduleconfig = ["email", "allow_scan", "max_age"]
moduleinfo = {
    "version": "1",
    "author": "Alexandre Dulaunoy",
    "name": "Qualys SSL Labs",
    "description": "Retrieve SSL Labs API v4 TLS assessments, endpoint grades and certificate details for a hostname.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["requests", "An email registered with SSL Labs API v4"],
    "features": (
        "Requires an organization `email` already registered with SSL Labs API v4. No registration is performed by this"
        " module. Set `allow_scan` to true before any API request is made. The analyze endpoint can start an assessment"
        " even when cached results are requested. Cached reports up to `max_age` hours old (default 24) are preferred;"
        " a cache miss can start a scan. Such assessments run on Qualys servers and can take"
        " minutes. Each invocation makes one API call and returns progress; run the module again later to retrieve the"
        " result. It never forces a restart with startNew and does not publish a report on the public results board."
        " Complete results include endpoint grades, protocols, cipher suites and weakness-test results as contextual"
        " annotations, endpoint ip-port objects and x509 certificate objects. Partial or failed endpoints are labelled"
        " and are not assigned a successful grade. Numeric test statuses are retained without interpreting"
        " unknown/error values as vulnerabilities. All enrichment has to_ids disabled."
    ),
    "references": [
        "https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md",
        "https://www.ssllabs.com/about/terms.html",
    ],
    "input": "domain, hostname MISP attribute.",
    "output": "Referenced progress/assessment annotations, endpoint ip-port objects and x509 objects.",
}
TIMEOUT = 30


class ModuleError(ValueError):
    """An error safe to display without request URLs, credentials or remote error bodies."""


def _request(q):
    request = json.loads(q)
    if not isinstance(request, dict):
        raise ModuleError("The request must be a JSON object.")
    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not all(attribute.get(k) for k in ("type", "value", "uuid")):
        raise ModuleError("An attribute containing type, value and uuid is required.")
    if attribute["type"] not in mispattributes["input"]:
        raise ModuleError("Unsupported attribute type.")
    if not isinstance(attribute["value"], str) or not attribute["value"].strip():
        raise ModuleError("The attribute value must be a nonempty string.")
    config = request.get("config", {})
    if not isinstance(config, dict):
        raise ModuleError("The config must be a JSON object.")
    event = MISPEvent()
    event.add_attribute(**attribute)
    return event, attribute, config


def _annotation(event, attribute, title, data):
    obj = MISPObject("annotation")
    obj.comment = title
    obj.add_attribute("text", value=json.dumps(data, sort_keys=True, indent=2), to_ids=False, disable_correlation=True)
    obj.add_reference(attribute["uuid"], "describes")
    event.add_object(obj)


def _results(event):
    data = json.loads(event.to_json())
    return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}


def _json(response, service, missing=False):
    if missing and response.status_code in (204, 404):
        return None
    if response.status_code != 200:
        suffix = " Retry later and respect the service's Retry-After header." if response.status_code == 429 else ""
        raise ModuleError(f"{service} returned HTTP {response.status_code}.{suffix}")
    try:
        data = response.json()
    except ValueError:
        raise ModuleError(f"{service} returned invalid JSON.") from None
    if not isinstance(data, dict):
        raise ModuleError(f"{service} returned an unexpected response.")
    if data.get("error") or data.get("errors"):
        raise ModuleError(f"{service} reported an API error.")
    return data


def handler(q=False):
    if q is False:
        return False
    try:
        event, attribute, config = _request(q)
        return _expand(event, attribute, config)
    except ModuleError as exc:
        return {"error": str(exc)}
    except requests.RequestException:
        return {"error": "The service request failed or timed out."}
    except (ValueError, TypeError, KeyError, OverflowError):
        return {"error": "Invalid request or service response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)


def _domain(value, require_dot=True):
    if not isinstance(value, str):
        raise ModuleError("A valid domain or hostname is required.")
    host = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if (
        len(host) > 253
        or (require_dot and "." not in host)
        or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split("."))
    ):
        raise ModuleError("A valid domain or hostname is required.")
    try:
        ip_address(host)
    except ValueError:
        return host
    raise ModuleError("A domain or hostname is required, not an IP address.")


def _boolean(value):
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0", ""):
        return value.lower() in ("true", "1")
    if isinstance(value, bool):
        return value
    raise ModuleError("allow_scan must be true or false.")


def _certificate(event, attribute, cert):
    if not isinstance(cert, dict):
        raise ModuleError("SSL Labs returned an invalid certificate.")
    obj = MISPObject("x509")
    obj.comment = "SSL Labs observed certificate"
    mapping = (
        ("subject", "subject"),
        ("issuerSubject", "issuer"),
        ("serialNumber", "serial-number"),
        ("sigAlg", "signature_algorithm"),
        ("sha1Hash", "x509-fingerprint-sha1"),
        ("sha256Hash", "x509-fingerprint-sha256"),
    )
    for field, relation in mapping:
        value = cert.get(field)
        if value:
            if not isinstance(value, str):
                raise ModuleError("SSL Labs returned invalid certificate details.")
            if field in ("sha1Hash", "sha256Hash"):
                size = 40 if field == "sha1Hash" else 64
                value = value.replace(":", "").lower()
                if not re.fullmatch(r"[a-f0-9]{" + str(size) + r"}", value):
                    raise ModuleError("SSL Labs returned an invalid certificate fingerprint.")
            obj.add_attribute(relation, value=value, to_ids=False)
    for field, relation in (("notBefore", "validity-not-before"), ("notAfter", "validity-not-after")):
        stamp = cert.get(field)
        if stamp is not None:
            if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
                raise ModuleError("SSL Labs returned an invalid certificate timestamp.")
            # Assessment API timestamps are milliseconds; accept seconds as well for older cached reports.
            seconds = stamp / 1000 if abs(stamp) >= 100_000_000_000 else stamp
            obj.add_attribute(relation, value=datetime.fromtimestamp(seconds, timezone.utc).isoformat(), to_ids=False)
    names = cert.get("altNames", [])
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ModuleError("SSL Labs returned invalid certificate alternative names.")
    for name in dict.fromkeys(names):
        obj.add_attribute("dns_names", value=name, to_ids=False)
    if obj.attributes:
        obj.add_reference(attribute["uuid"], "describes")
        event.add_object(obj)


def _expand(event, attribute, config):
    host = _domain(attribute["value"])
    scan = _boolean(config.get("allow_scan", False))
    if not scan:
        raise ModuleError(
            "Set allow_scan=true to permit SSL Labs assessments. The analyze endpoint can start a scan when cached"
            " results are unavailable."
        )
    email = config.get("email")
    if isinstance(email, str):
        email = email.strip()
    if not isinstance(email, str) or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ModuleError("An email already registered with SSL Labs API v4 is required.")
    age = config.get("max_age", 24)
    if age == "":
        age = 24
    if isinstance(age, bool) or not str(age).isdigit() or not 1 <= int(age) <= 720:
        raise ModuleError("max_age must be an integer between 1 and 720 hours.")
    # fromCache prefers an existing report; a cache miss can still start an assessment.
    # Never call analyze without explicit scan consent, even when requesting cached data.
    params = {"host": host, "publish": "off", "all": "done", "fromCache": "on", "maxAge": int(age)}
    response = requests.get(
        "https://api.ssllabs.com/api/v4/analyze",
        headers={"email": email},
        params=params,
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    data = _json(response, "SSL Labs")
    if _domain(data.get("host", "")) != host:
        raise ModuleError("SSL Labs returned an unexpected assessment host.")
    status = data.get("status")
    if status == "ERROR":
        raise ModuleError("SSL Labs assessment failed. Check the SSL Labs report.")
    if status not in ("DNS", "IN_PROGRESS", "READY"):
        raise ModuleError("SSL Labs returned an unknown assessment status.")
    summary = {
        "host": host,
        "status": status,
        "allow-scan": scan,
        "report": "https://www.ssllabs.com/ssltest/analyze.html?d=" + host,
    }
    for field in ("startTime", "testTime", "engineVersion", "criteriaVersion", "cacheExpiryTime", "statusMessage"):
        if field in data:
            summary[field] = data[field]
    if status != "READY":
        summary["notice"] = "Assessment is in progress. Run this module again later; no grade is final yet."
        _annotation(event, attribute, "SSL Labs assessment progress", summary)
        return _results(event)
    endpoints = data.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise ModuleError("SSL Labs returned no assessment endpoints.")
    _annotation(event, attribute, "SSL Labs assessment", summary)
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            raise ModuleError("SSL Labs returned an invalid endpoint.")
        address = str(ip_address(endpoint.get("ipAddress", "")))
        ready = str(endpoint.get("statusMessage", "")).lower() == "ready"
        details = endpoint.get("details") or {}
        if not isinstance(details, dict):
            raise ModuleError("SSL Labs returned invalid endpoint details.")
        context = {"ip": address, "status": endpoint.get("statusMessage", "Unknown"), "complete": ready}
        if ready:
            for field in ("grade", "gradeTrustIgnored", "hasWarnings", "isExceptional"):
                if field in endpoint:
                    context[field] = endpoint[field]
            for field in (
                "protocols",
                "suites",
                "heartbleed",
                "heartbeat",
                "poodle",
                "poodleTls",
                "freak",
                "logjam",
                "drownVulnerable",
                "openSslCcs",
                "vulnBeast",
                "renegSupport",
                "hstsPolicy",
                "httpForwarding",
                "certChains",
            ):
                if field in details:
                    context[field] = details[field]
        _annotation(event, attribute, "SSL Labs TLS endpoint assessment", context)
        obj = MISPObject("ip-port")
        obj.add_attribute("domain", value=host, to_ids=False)
        obj.add_attribute("ip", value=address, to_ids=False)
        obj.add_attribute("dst-port", value=443, to_ids=False)
        obj.add_reference(attribute["uuid"], "describes")
        event.add_object(obj)
    certs = data.get("certs", [])
    if not isinstance(certs, list):
        raise ModuleError("SSL Labs returned invalid certificates.")
    for cert in certs:
        _certificate(event, attribute, cert)
    return _results(event)
