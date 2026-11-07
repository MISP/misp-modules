"""Domain reputation through the Cisco Umbrella Investigate v2 API."""

import hashlib
import json
import math
import re
import time
from collections import OrderedDict
from datetime import datetime, timezone
from threading import Lock
from uuid import UUID

import idna
import requests
from pymisp import MISPEvent, MISPObject

mispattributes = {"input": ["domain", "hostname"], "format": "misp_standard"}
moduleconfig = ["api_key", "api_secret", "timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Cisco Umbrella Investigate",
    "description": "Enrich a domain with Cisco Umbrella Investigate categorization and risk scores.",
    "module-type": ["expansion", "hover"],
    "data-source": "external",
    "logo": "",
    "requirements": ["An Umbrella Investigate entitlement and an API key with investigate.investigate:read access."],
    "features": (
        "Uses the Umbrella v2 OAuth client credentials flow. Returns a referenced annotation with domain status,"
        " security/content categories, risk score and contributing features. Partial results identify failed"
        " lookups. See https://github.com/MISP/misp-modules/blob/main/documentation/expansion/cisco_umbrella.md."
    ),
    "references": [
        "https://developer.cisco.com/docs/cloud-security/umbrella-api-getting-started/",
        "https://developer.cisco.com/docs/cloud-security/umbrella-api-reference-investigate-api-overview/",
    ],
    "input": "A domain or hostname attribute with a UUID and a fully qualified DNS name.",
    "output": "The original attribute and a non-IDS annotation containing the Umbrella report.",
}
BASE_URL = "https://api.umbrella.com"
_TOKENS = OrderedDict()
_TOKEN_LOCK = Lock()


class UmbrellaError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class _BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, request):
        request.headers["Authorization"] = "Bearer " + self.token
        return request


def _request(session, method, path, timeout, **kwargs):
    try:
        with session.request(method, BASE_URL + path, timeout=timeout, allow_redirects=False, **kwargs) as response:
            if response.status_code != 200:
                raise UmbrellaError(f"HTTP {response.status_code}", response.status_code)
            data = response.json()
    except requests.RequestException:
        raise UmbrellaError("Request failed or timed out.") from None
    except ValueError:
        raise UmbrellaError("Invalid JSON response.") from None
    if not isinstance(data, dict) or "error" in data:
        raise UmbrellaError("Invalid API response.")
    return data


def _token(session, key, secret, timeout):
    # A bounded process-local cache avoids issuing a token for every hover.
    cache_key = hashlib.sha256(json.dumps([key, secret]).encode()).digest()
    with _TOKEN_LOCK:
        now = time.monotonic()
        for identity, (_, expiry) in list(_TOKENS.items()):
            if expiry <= now:
                del _TOKENS[identity]
        if cache_key in _TOKENS:
            _TOKENS.move_to_end(cache_key)
            return cache_key, _TOKENS[cache_key][0]
        data = _request(
            session,
            "POST",
            "/auth/v2/token",
            timeout,
            auth=(key, secret),
            data={"grant_type": "client_credentials"},
        )
        token, expires = data.get("access_token"), data.get("expires_in")
        if (
            not isinstance(token, str)
            or len(token) > 16384
            or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token)
            or not isinstance(data.get("token_type"), str)
            or data["token_type"].lower() != "bearer"
            or type(expires) is not int
            or expires <= 0
        ):
            raise UmbrellaError("Invalid token response.")
        lifetime = min(expires, 3600)
        _TOKENS[cache_key] = (token, now + lifetime - min(60, lifetime / 10))
        while len(_TOKENS) > 32:
            _TOKENS.popitem(last=False)
        return cache_key, token


def _invalidate(cache_key, token):
    with _TOKEN_LOCK:
        if _TOKENS.get(cache_key, (None,))[0] == token:
            _TOKENS.pop(cache_key, None)


def _settings(request):
    attribute, config = request.get("attribute"), request.get("config")
    if not isinstance(attribute, dict) or attribute.get("type") not in mispattributes["input"]:
        raise ValueError("A domain or hostname attribute is required.")
    try:
        UUID(attribute["uuid"])
        value = attribute["value"]
        if not isinstance(value, str):
            raise ValueError
        domain = idna.encode(value.strip(), uts46=True, transitional=False).decode("ascii").removesuffix(".")
        labels = domain.split(".")
        if len(domain) > 253 or len(labels) < 2 or labels[-1].isdigit():
            raise ValueError
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError("A valid attribute UUID and fully qualified DNS name are required.") from None
    if not isinstance(config, dict):
        raise ValueError("api_key and api_secret are required in config.")
    key, secret = config.get("api_key"), config.get("api_secret")
    for credential in (key, secret):
        if (
            not isinstance(credential, str)
            or not 1 <= len(credential) <= 4096
            or any(not 33 <= ord(char) <= 126 for char in credential)
        ):
            raise ValueError("api_key and api_secret must be non-empty printable ASCII credentials.")
    if ":" in key:
        raise ValueError("api_key cannot contain a colon.")
    timeout = config.get("timeout")
    if timeout is None or timeout == "":
        timeout = 20
    if isinstance(timeout, bool) or not re.fullmatch(r"[0-9]{1,3}", str(timeout)) or not 1 <= int(timeout) <= 120:
        raise ValueError("timeout must be an integer between 1 and 120 seconds.")
    return attribute, domain, key, secret, int(timeout)


def _categorization(data, domain):
    # The API's example is keyed by domain, while its response schema is flat.
    result = data.get(domain, data)
    if not isinstance(result, dict) or type(result.get("status")) is not int or result["status"] not in (-1, 0, 1):
        raise UmbrellaError("Invalid categorization response.")
    output = {
        "status": result["status"],
        "status_label": {-1: "malicious", 0: "unclassified", 1: "benign"}[result["status"]],
    }
    for field in ("security_categories", "content_categories"):
        values = result.get(field)
        if (
            not isinstance(values, list)
            or len(values) > 100
            or any(not isinstance(value, str) or not 1 <= len(value) <= 256 for value in values)
        ):
            raise UmbrellaError("Invalid categorization response.")
        output[field] = values
    return output


def _number(value):
    if type(value) not in (int, float):
        raise UmbrellaError("Invalid risk score response.")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise UmbrellaError("Invalid risk score response.")
    return value


def _risk(data, domain):
    risk = _number(data.get("risk_score"))
    indicators = data.get("indicators", [])
    if not 0 <= risk <= 100 or not isinstance(indicators, list) or len(indicators) > 100:
        raise UmbrellaError("Invalid risk score response.")
    output = []
    for item in indicators:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("indicator"), str)
            or not 1 <= len(item["indicator"]) <= 256
        ):
            raise UmbrellaError("Invalid risk score response.")
        normalized, score = _number(item.get("normalized_score")), _number(item.get("score"))
        if not 0 <= normalized <= 100:
            raise UmbrellaError("Invalid risk score response.")
        output.append({"indicator": item["indicator"], "normalized_score": normalized, "score": score})
    return {"risk_score": risk, "indicators": output}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("A JSON object is required.")
        attribute, domain, key, secret, timeout = _settings(request)
    except (ValueError, TypeError) as exc:
        return {"error": f"Cisco Umbrella: {exc}"}
    report = {
        "provider": "Cisco Umbrella Investigate",
        "domain": domain,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "errors": {},
    }
    try:
        # Request-local sessions keep headers/cookies out of other users' lookups.
        with requests.Session() as session:
            session.headers.update({"Accept": "application/json", "User-Agent": "MISP-misp-modules/cisco_umbrella"})
            cache_key, token = _token(session, key, secret, timeout)
            for name, path, parser in (
                ("categorization", f"/domains/categorization/{domain}", _categorization),
                ("risk", f"/domains/risk-score/{domain}", _risk),
            ):
                try:
                    data = _request(
                        session,
                        "GET",
                        "/investigate/v2" + path,
                        timeout,
                        # Explicit auth prevents .netrc from replacing the bearer.
                        auth=_BearerAuth(token),
                        params={"showLabels": ""} if name == "categorization" else None,
                    )
                    report[name] = parser(data, domain)
                except UmbrellaError as exc:
                    if exc.status in (400, 401):
                        _invalidate(cache_key, token)
                    report["errors"][name] = str(exc)
    except UmbrellaError as exc:
        return {"error": f"Cisco Umbrella authentication failed: {exc}"}
    if not any(name in report for name in ("categorization", "risk")):
        return {
            "error": (
                "Cisco Umbrella lookup failed: "
                + "; ".join(f"{name}: {error}" for name, error in report["errors"].items())
            )
        }
    report["status"] = "partial" if report["errors"] else "complete"
    obj = MISPObject("annotation")
    obj.comment = "Cisco Umbrella Investigate domain reputation"
    obj.add_attribute("text", value=json.dumps(report, sort_keys=True), to_ids=False, disable_correlation=True)
    obj.add_reference(attribute["uuid"], "describes")
    event = MISPEvent()
    event.add_object(obj)
    result = {"results": {"Attribute": [attribute], "Object": json.loads(event.to_json())["Object"]}}
    if report["errors"]:
        result["warnings"] = [f"Cisco Umbrella {name}: {error}" for name, error in report["errors"].items()]
    return result


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
