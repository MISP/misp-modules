"""Authenticated transport for the Cortex XSOAR 8 public API."""

import hashlib
import json
import re
import secrets
import time
from urllib.parse import urlsplit, urlunsplit

import requests

API_PATH = "/xsoar/public/v1"
OVERVIEW = (
    "https://cortex-docs.paloaltonetworks.com/cortex-xsoar-8-saas/troubleshoot-and-reference/reference/cortex-xsoar-api"
)
AUTH_REFERENCE = "https://cortex-docs.paloaltonetworks.com/xsoar-8-api/make-your-first-api-call"
INDICATOR_REFERENCE = "https://cortex-docs.paloaltonetworks.com/xsoar-8-api/cortex-xsoar-8.x-apis/indicators"
INCIDENT_REFERENCE = "https://cortex-docs.paloaltonetworks.com/xsoar-8-api/cortex-xsoar-8.x-apis/incidents"


class XsoarError(ValueError):
    """A diagnostic safe to return without credentials or remote error bodies."""


def boolean(value, name, default=False):
    if value is None or value == "":
        return default
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "0", "1"):
        return value.lower() in ("true", "1")
    raise XsoarError(f"{name} must be true, false, 1 or 0.")


def integer(value, name, default, maximum):
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,6}", str(value)) or not 1 <= int(value) <= maximum:
        raise XsoarError(f"{name} must be between 1 and {maximum}.")
    return int(value)


class _Auth(requests.auth.AuthBase):
    def __init__(self, key, identifier, mode):
        self.key, self.identifier, self.mode = key, identifier, mode

    def __call__(self, request):
        request.headers["x-xdr-auth-id"] = self.identifier
        request.headers.pop("x-xdr-nonce", None)
        request.headers.pop("x-xdr-timestamp", None)
        authorization = self.key
        if self.mode == "advanced":
            nonce, timestamp = secrets.token_hex(32), str(int(time.time() * 1000))
            authorization = hashlib.sha256((self.key + nonce + timestamp).encode("utf-8")).hexdigest()
            request.headers.update({"x-xdr-nonce": nonce, "x-xdr-timestamp": timestamp})
        request.headers["Authorization"] = authorization
        return request


def _invalid_constant(value):
    raise ValueError("Non-JSON numeric constant")


class Client:
    def __init__(self, config):
        if not isinstance(config, dict) or not isinstance(config.get("url"), str):
            raise XsoarError("Configure the Cortex XSOAR HTTPS API origin or /xsoar/public/v1 API root.")
        url = config["url"]
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.port == 0
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path.rstrip("/") not in ("", API_PATH)
            or any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in url)
        ):
            raise XsoarError("Use an HTTPS API origin or /xsoar/public/v1 root without credentials, query or fragment.")
        key, identifier = config.get("api_key"), config.get("api_key_id")
        if not isinstance(key, str) or not 1 <= len(key) <= 8192 or any(not 33 <= ord(char) <= 126 for char in key):
            raise XsoarError("A non-empty printable ASCII api_key is required.")
        if isinstance(identifier, bool) or not re.fullmatch(r"[0-9]{1,30}", str(identifier)) or int(identifier) <= 0:
            raise XsoarError("api_key_id must be a positive numeric key ID.")
        mode = config.get("auth_type")
        if mode in (None, ""):
            mode = "advanced"
        if mode not in ("standard", "advanced"):
            raise XsoarError("auth_type must be standard or advanced.")
        self.origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        self.timeout = integer(config.get("timeout"), "timeout", 20, 120)
        self.auth = _Auth(key, str(identifier), mode)
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "User-Agent": "MISP-misp-modules/cortex_xsoar"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def post(self, operation, payload):
        paths = {"search": "/indicators/search", "incident": "/incident"}
        if operation not in paths:
            raise XsoarError("Unsupported Cortex XSOAR API operation.")
        try:
            with self.session.post(
                self.origin + API_PATH + paths[operation],
                json=payload,
                auth=self.auth,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                # XSOAR 8 explicitly documents 200 as processed without creating
                # an incident (for example, because of a preprocessing rule).
                if operation == "incident" and response.status_code == 200:
                    return 200, None
                expected = 201 if operation == "incident" else 200
                if response.status_code != expected:
                    raise XsoarError(f"Cortex XSOAR returned HTTP {response.status_code}.")
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > 2 * 1024 * 1024:
                        raise XsoarError("Cortex XSOAR response exceeds the 2 MiB limit.")
                try:
                    body = json.loads(content, parse_constant=_invalid_constant)
                except (ValueError, RecursionError):
                    raise XsoarError("Cortex XSOAR returned invalid JSON.") from None
        except (requests.RequestException, OSError):
            raise XsoarError("Cortex XSOAR request failed or timed out.") from None
        if not isinstance(body, dict) or any(body.get(key) for key in ("error", "errors", "err_code", "errorCode")):
            raise XsoarError("Cortex XSOAR returned an API error or unexpected response.")
        return expected, body
