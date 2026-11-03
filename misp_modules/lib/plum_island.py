"""Shared read-only Discovery API v1 client and MISP evidence helpers."""

import json
import re
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit
from uuid import UUID

import requests
from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

REFERENCE = "https://github.com/D4-project/Plum-Island/blob/main/documentation/discovery.md"
COMMON_CONFIG = ["url", "username", "password", "access_token", "max_results", "max_pages", "from_ts", "to_ts"]


class PlumError(ValueError):
    """An error safe to return without exposing credentials or scan text."""


def number(config, key, default, maximum, minimum=1):
    value = config.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)) or not minimum <= int(value) <= maximum:
        raise PlumError(f"{key} must be an integer between {minimum} and {maximum}.")
    return int(value)


def domain(value):
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")
    ):
        raise PlumError("Invalid domain or hostname.")
    return value


def address(value):
    if "%" in value:
        raise PlumError("Scoped IP addresses are not supported.")
    return str(ip_address(value))


def search_query(attribute):
    kind, value = attribute["type"], attribute["value"].strip()
    if kind in ("ip-src", "ip-dst"):
        if "/" in value:
            if "%" in value:
                raise PlumError("Scoped IP addresses are not supported.")
            return "net:" + str(ip_network(value, strict=False))
        return "ip:" + address(value)
    if kind in ("domain", "hostname"):
        value = domain(value)
        field = "domain" if kind == "domain" else "fqdn"
        return f"({field}:{value} OR {field}_requested:{value})"
    algorithm = kind.removeprefix("x509-fingerprint-")
    length = {"md5": 32, "sha1": 40, "sha256": 64}[algorithm]
    value = value.replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{%d}" % length, value):
        raise PlumError("Invalid certificate fingerprint.")
    return f"x509_{algorithm}:{value}"


class Client:
    def __init__(self, config):
        value = config.get("url")
        if not isinstance(value, str) or not value.strip():
            raise PlumError("Configure the Plum Island base url.")
        self.base = value.strip().rstrip("/")
        parts = urlsplit(self.base)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.port == 0
        ):
            raise PlumError("url must be an HTTPS base URL without credentials, query or fragment.")
        self.config = config
        self.limit = number(config, "max_results", 25, 100)
        self.max_pages = number(config, "max_pages", 10, 20)
        self.dates = {
            key: number(config, key, None, 253402300799, minimum=0)
            for key in ("from_ts", "to_ts")
            if config.get(key) not in (None, "")
        }
        if len(self.dates) == 2 and self.dates["from_ts"] > self.dates["to_ts"]:
            raise PlumError("from_ts must not exceed to_ts.")
        for key in ("username", "password", "access_token"):
            if config.get(key) is not None and not isinstance(config[key], str):
                raise PlumError(f"{key} must be a string.")
        self.token = config.get("access_token") or ""
        self.can_login = bool(config.get("username") and config.get("password"))
        if not self.token and not self.can_login:
            raise PlumError("Configure username and password, or access_token (a FAB JWT, not AGENT_KEY).")

    def _post(self, path, data, token=None):
        try:
            return requests.post(
                self.base + path,
                json=data,
                headers={"Authorization": "Bearer " + token} if token else {},
                timeout=(5, 30),
                verify=True,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise PlumError("Plum Island request failed or timed out.") from None

    @staticmethod
    def _json(response):
        if response.status_code != 200:
            hint = {
                401: "Check FAB credentials or renew access_token.",
                403: "Check the account's DiscoveryApi permissions.",
                404: "Check the base URL, Discovery API installation and requested IP/hostname.",
                410: "Search continuation expired; run the enrichment again.",
                413: "Reduce max_results or narrow the date range.",
                503: "Discovery is busy or a backend is unavailable; try again later.",
            }.get(response.status_code, "Check the Plum Island service.")
            raise PlumError(f"Plum Island returned HTTP {response.status_code}. {hint}")
        try:
            result = response.json()
        except ValueError:
            raise PlumError("Plum Island returned invalid JSON.") from None
        if not isinstance(result, dict):
            raise PlumError("Plum Island returned an invalid JSON object.")
        return result

    def _login(self):
        result = self._json(
            self._post(
                "/api/v1/security/login",
                {"username": self.config["username"], "password": self.config["password"], "provider": "db"},
            )
        )
        token = result.get("access_token")
        if not isinstance(token, str) or not token or any(c.isspace() for c in token):
            raise PlumError("Plum Island login did not return an access token.")
        self.token = token

    def call(self, operation, data):
        if not self.token:
            self._login()
        response = self._post("/api/v1/discovery/" + operation, data, self.token)
        if response.status_code == 401 and self.can_login:
            self._login()
            response = self._post("/api/v1/discovery/" + operation, data, self.token)
        envelope = self._json(response)
        if type(envelope.get("api_version")) is not int or envelope["api_version"] != 1:
            raise PlumError("Plum Island Discovery API v1 is required (newer than release v0.2610.0).")
        if not isinstance(envelope.get("result"), dict):
            raise PlumError("Plum Island returned an invalid result envelope.")
        return envelope["result"]


def annotation(event, source, title, evidence):
    obj = MISPObject("annotation")
    obj.comment = title
    obj.add_attribute(
        "text", value=json.dumps(evidence, indent=2, sort_keys=True), to_ids=False, disable_correlation=True
    )
    obj.add_reference(source["uuid"], "describes")
    event.add_object(obj)


def results(event):
    data = json.loads(event.to_json())
    return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}


def run(q, inputs, expand):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise PlumError("The request must be a JSON object.")
        source = request.get("attribute")
        if not isinstance(source, dict) or not all(source.get(key) for key in ("type", "value", "uuid")):
            raise PlumError("An attribute containing type, value and uuid is required.")
        if source["type"] not in inputs:
            raise PlumError("Unsupported attribute type.")
        if not isinstance(source["value"], str) or not source["value"].strip():
            raise PlumError("The attribute value must be a nonempty string.")
        UUID(source["uuid"])
        config = request.get("config", {})
        if not isinstance(config, dict):
            raise PlumError("The config must be a JSON object.")
        client = Client(config)
        event = MISPEvent()
        event.add_attribute(**source)
        expand(event, source, client, config)
        return results(event)
    except PlumError as error:
        return {"error": str(error)}
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, OSError, PyMISPError):
        return {"error": "Invalid request or Plum Island response."}
