"""Cortex XDR IOC normalization and authenticated public API transport."""

import hashlib
import ipaddress
import json
import re
import secrets
import time
from urllib.parse import urlsplit

import idna
import requests

CONFIG = ["url", "api_key", "api_key_id", "auth_type"]
HASH_LENGTHS = {"md5": 32, "sha256": 64}
INPUT_TYPES = [*HASH_LENGTHS, "domain", "hostname", "ip-src", "ip-dst"]
API_PATH = "/public_api/v1/indicators/"
AUTH_REFERENCE = "https://cortex-docs.paloaltonetworks.com/xdr-api/make-your-first-api-call"
IOC_REFERENCE = "https://cortex-docs.paloaltonetworks.com/xdr-api/cortex-platform/iocs"


class XdrError(ValueError):
    """A message safe to display without API credentials or response bodies."""


def integer(value, name, default, maximum):
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,3}", str(value)) or not 1 <= int(value) <= maximum:
        raise XdrError(f"{name} must be an integer between 1 and {maximum}.")
    return int(value)


def boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise XdrError(f"{name} must be true, false, 1 or 0.")


def indicator(kind, value):
    if not isinstance(value, str) or not value.strip():
        raise XdrError("A non-empty indicator value is required.")
    value = value.strip()
    if kind in HASH_LENGTHS:
        if not re.fullmatch(rf"[0-9a-fA-F]{{{HASH_LENGTHS[kind]}}}", value):
            raise XdrError("Invalid hash length or hexadecimal value.")
        return "hash", value.lower()
    if kind in ("domain", "hostname"):
        value = idna.encode(value, uts46=True, transitional=False).decode("ascii").removesuffix(".")
        labels = value.split(".")
        if len(value) > 253 or len(labels) < 2 or labels[-1].isdigit():
            raise XdrError("A fully qualified DNS name is required.")
        return "domain_name", value
    if kind in ("ip-src", "ip-dst"):
        if "%" in value:
            raise XdrError("Scoped IPv6 addresses are unsupported.")
        return "ip", str(ipaddress.ip_address(value))
    raise XdrError("Unsupported indicator type.")


def remote_indicator(kind, value):
    if not isinstance(kind, str) or not isinstance(value, str):
        raise XdrError("Cortex XDR returned an invalid IOC identity.")
    kind = kind.lower()
    if kind == "hash":
        algorithm = next((name for name, length in HASH_LENGTHS.items() if len(value) == length), None)
        if algorithm is None:
            raise XdrError("Cortex XDR returned an unsupported hash.")
        return indicator(algorithm, value)
    return indicator({"domain_name": "domain", "ip": "ip-dst"}.get(kind), value)


class _Auth(requests.auth.AuthBase):
    def __init__(self, key, identifier, mode):
        self.key, self.identifier, self.mode = key, identifier, mode

    def __call__(self, request):
        request.headers["x-xdr-auth-id"] = self.identifier
        authorization = self.key
        if self.mode == "advanced":
            nonce, timestamp = secrets.token_hex(32), str(int(time.time() * 1000))
            authorization = hashlib.sha256((self.key + nonce + timestamp).encode()).hexdigest()
            request.headers.update({"x-xdr-nonce": nonce, "x-xdr-timestamp": timestamp})
        request.headers["Authorization"] = authorization
        return request


class Client:
    def __init__(self, config):
        if not isinstance(config, dict):
            raise XdrError("Cortex XDR connection configuration is required.")
        origin = config.get("url")
        if not isinstance(origin, str):
            raise XdrError("Configure the Cortex XDR HTTPS API origin in url.")
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or parsed.port == 0
            or any(ord(char) <= 32 or ord(char) == 127 for char in origin)
        ):
            raise XdrError("url must be an HTTPS API origin without credentials, a path, query or fragment.")
        key, identifier = config.get("api_key"), config.get("api_key_id")
        if not isinstance(key, str) or not 1 <= len(key) <= 8192 or any(not 33 <= ord(c) <= 126 for c in key):
            raise XdrError("A non-empty printable ASCII api_key is required.")
        if not isinstance(identifier, str) or not re.fullmatch(r"[0-9]{1,30}", identifier):
            raise XdrError("api_key_id must be a string of digits.")
        mode = config.get("auth_type") or "advanced"
        if mode not in ("standard", "advanced"):
            raise XdrError("auth_type must be standard or advanced.")
        self.origin = origin.rstrip("/")
        self.timeout = integer(config.get("timeout"), "timeout", 20, 120)
        self.auth = _Auth(key, identifier, mode)
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "User-Agent": "MISP-misp-modules/cortex_xdr"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def post(self, operation, payload):
        if operation not in ("get", "insert_jsons"):
            raise XdrError("Unsupported Cortex XDR IOC operation.")
        try:
            with self.session.post(
                self.origin + API_PATH + operation,
                auth=self.auth,
                json=payload,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.status_code != 200:
                    raise XdrError(f"Cortex XDR returned HTTP {response.status_code}.")
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > 2 * 1024 * 1024:
                        raise XdrError("Cortex XDR response exceeds 2 MiB.")
                try:
                    data = json.loads(content)
                except (ValueError, RecursionError):
                    raise XdrError("Cortex XDR returned invalid JSON.") from None
        except (requests.RequestException, OSError):
            raise XdrError(
                "Cortex XDR request failed or timed out; check remote state before retrying writes."
            ) from None
        if not isinstance(data, dict) or any(data.get(k) for k in ("err_code", "error", "errors")):
            raise XdrError("Cortex XDR returned an API error or unexpected response.")
        reply = data.get("reply", data)
        if isinstance(reply, dict) and any(reply.get(k) for k in ("err_code", "error", "errors")):
            raise XdrError("Cortex XDR returned an API error.")
        return data

    def lookup(self, kind, value, limit=20):
        body = self.post(
            "get",
            {
                "request_data": {
                    "extended_view": True,
                    "filters": [
                        {"field": "indicator", "operator": "EQ", "value": value},
                        {"field": "type", "operator": "EQ", "value": kind},
                    ],
                    "search_from": 0,
                    "search_to": limit - 1,
                }
            },
        )
        reply = body.get("reply", body)
        if not isinstance(reply, dict) or not isinstance(reply.get("objects"), list):
            raise XdrError("Cortex XDR returned an invalid IOC collection.")
        rows, count = reply["objects"], reply.get("objects_count")
        if type(count) is not int or count < len(rows) or len(rows) > limit or (count > 0 and not rows):
            raise XdrError("Cortex XDR returned an incomplete or invalid IOC count.")
        for row in rows:
            if not isinstance(row, dict) or remote_indicator(row.get("type"), row.get("indicator")) != (kind, value):
                raise XdrError("Cortex XDR returned a different IOC identity.")
            if type(row.get("rule_id")) is not int or row["rule_id"] <= 0:
                raise XdrError("Cortex XDR returned an invalid IOC rule ID.")
        return rows, count, count > len(rows) or len(rows) == limit


def metadata(row):
    """Retain documented IOC context without copying arbitrary response fields."""
    result = {key: row[key] for key in ("rule_id", "indicator", "type")}
    for field in ("severity", "comment", "reputation", "reliability"):
        value = row.get(field)
        if value is not None:
            if not isinstance(value, str) or len(value) > 4096:
                raise XdrError("Cortex XDR returned invalid IOC metadata.")
            result[field] = value
    expiry = row.get("expiration_date")
    if expiry is not None:
        if type(expiry) is not int or expiry < -1:
            raise XdrError("Cortex XDR returned an invalid IOC expiry.")
        result["expiration_date"] = expiry
    return result
