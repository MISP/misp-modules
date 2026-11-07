"""Small authenticated transport for the Tines Records/Cases v2 APIs."""

import json
import re
from urllib.parse import urlsplit

import requests

AUTH_REFERENCE = "https://www.tines.com/stories/docs/api/authentication/"
SEARCH_REFERENCE = "https://www.tines.com/stories/docs/api/records/search/"
CASE_REFERENCE = "https://www.tines.com/stories/docs/api/cases/create/"


class TinesError(ValueError):
    """A diagnostic safe to return without credentials or remote error bodies."""


def positive_id(value, name):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,18}", str(value)) or int(value) <= 0:
        raise TinesError(f"{name} must be a positive integer ID.")
    return int(value)


def integer(value, name, default, maximum):
    if value is None or value == "":
        return default
    value = positive_id(value, name)
    if value > maximum:
        raise TinesError(f"{name} must be between 1 and {maximum}.")
    return value


def boolean(value, name):
    if value is None or value == "":
        return False
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise TinesError(f"{name} must be true, false, 1 or 0.")


def https_url(value, allow_path=False):
    if not isinstance(value, str):
        raise TinesError("An HTTPS URL is required.")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port == 0
        or (not allow_path and parsed.path not in ("", "/"))
        or any(ord(char) <= 32 or ord(char) == 127 for char in value)
    ):
        raise TinesError("Use an HTTPS origin without credentials, a query or a fragment.")
    return value.rstrip("/")


class _TokenAuth(requests.auth.AuthBase):
    def __init__(self, key):
        self.key = key

    def __call__(self, request):
        request.headers.pop("Authorization", None)
        request.headers["X-User-Token"] = self.key
        return request


def _invalid_constant(value):
    raise ValueError("Non-JSON numeric constant")


class Client:
    def __init__(self, config):
        if not isinstance(config, dict):
            raise TinesError("Tines connection configuration is required.")
        self.origin = https_url(config.get("url"))
        key = config.get("api_key")
        if not isinstance(key, str) or not 1 <= len(key) <= 8192 or any(not 33 <= ord(char) <= 126 for char in key):
            raise TinesError("A non-empty printable ASCII api_key is required.")
        self.timeout = integer(config.get("timeout"), "timeout", 20, 120)
        self.auth = _TokenAuth(key)
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "User-Agent": "MISP-misp-modules/tines"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def post(self, path, payload):
        expected = {"/api/v2/records/search": 200, "/api/v2/cases": 201}.get(path)
        if expected is None:
            raise TinesError("Unsupported Tines API operation.")
        try:
            with self.session.post(
                self.origin + path,
                json=payload,
                auth=self.auth,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.status_code != expected:
                    suffix = " Resource missing or API key lacks access." if response.status_code == 404 else ""
                    raise TinesError(f"Tines returned HTTP {response.status_code}.{suffix}")
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > 2 * 1024 * 1024:
                        raise TinesError("Tines response exceeds the 2 MiB limit.")
                try:
                    body = json.loads(content, parse_constant=_invalid_constant)
                except (ValueError, RecursionError):
                    raise TinesError("Tines returned invalid JSON.") from None
        except (requests.RequestException, OSError):
            raise TinesError("Tines request failed or timed out; check remote state before retrying writes.") from None
        if not isinstance(body, dict) or body.get("error") or body.get("errors"):
            raise TinesError("Tines returned an API error or unexpected response.")
        return body
