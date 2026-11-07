"""Authenticated, bounded transport for the Torq public API."""

import json
import re

import requests

OVERVIEW = "https://developers.torq.io/apidocs/overview"
AUTH_REFERENCE = "https://developers.torq.io/apidocs/authentication"
LOOKUP_REFERENCE = "https://developers.torq.io/apidocs/query-observables"
CASE_REFERENCE = "https://developers.torq.io/apidocs/create-a-case"
REGIONS = {
    "us": ("https://api.torq.io/public", "https://auth.torq.io/v1/auth/token"),
    "eu": ("https://api.eu.torq.io/public", "https://auth.eu.torq.io/v1/auth/token"),
    # The overview documents JP's API base, but the authentication guide lists
    # token endpoints only for US/EU. Do not guess where to send a client secret.
    "jp": ("https://api.jp.torq.io/public", None),
}


class TorqError(ValueError):
    """A diagnostic safe to return without credentials or remote error bodies."""


def boolean(value, name, default=False):
    if value is None or value == "":
        return default
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "0", "1"):
        return value.lower() in ("true", "1")
    raise TorqError(f"{name} must be true, false, 1 or 0.")


def integer(value, name, default, maximum):
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,6}", str(value)) or not 1 <= int(value) <= maximum:
        raise TorqError(f"{name} must be between 1 and {maximum}.")
    return int(value)


def _secret(value, name):
    if not isinstance(value, str) or not 1 <= len(value) <= 8192 or any(not 33 <= ord(char) <= 126 for char in value):
        raise TorqError(f"A non-empty printable ASCII {name} is required.")
    return value


class _BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, request):
        request.headers["Authorization"] = "Bearer " + self.token
        return request


def _invalid_constant(value):
    raise ValueError("Non-JSON numeric constant")


class Client:
    def __init__(self, config):
        if not isinstance(config, dict):
            raise TorqError("Torq connection configuration is required.")
        region = config.get("region")
        if region in (None, ""):
            region = "us"
        if not isinstance(region, str) or region.lower() not in REGIONS:
            raise TorqError("region must be us, eu or jp.")
        self.region = region.lower()
        self.base, self.token_url = REGIONS[self.region]
        self.timeout = integer(config.get("timeout"), "timeout", 20, 120)
        self.token, self.credentials = None, None
        if config.get("access_token"):
            if config.get("client_id") or config.get("client_secret"):
                raise TorqError("Configure an access_token or a client_id/client_secret pair, not both.")
            self.token = _secret(config["access_token"], "access_token")
        else:
            if self.token_url is None:
                raise TorqError("JP requires an access_token; automatic token exchange is documented for US and EU.")
            client_id = _secret(config.get("client_id"), "client_id")
            if ":" in client_id:
                raise TorqError("client_id cannot contain a colon.")
            self.credentials = (client_id, _secret(config.get("client_secret"), "client_secret"))
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "User-Agent": "MISP-misp-modules/torq"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def _request(self, url, auth, **kwargs):
        try:
            with self.session.post(
                url, auth=auth, timeout=self.timeout, allow_redirects=False, stream=True, **kwargs
            ) as response:
                if response.status_code != 200:
                    raise TorqError(f"Torq returned HTTP {response.status_code}.")
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > 2 * 1024 * 1024:
                        raise TorqError("Torq response exceeds the 2 MiB limit.")
                try:
                    body = json.loads(content, parse_constant=_invalid_constant)
                except (ValueError, RecursionError):
                    raise TorqError("Torq returned invalid JSON.") from None
        except (requests.RequestException, OSError):
            raise TorqError("Torq request failed or timed out.") from None
        if not isinstance(body, dict) or body.get("error") or body.get("errors") or body.get("code"):
            raise TorqError("Torq returned an API error or unexpected response.")
        return body

    def authenticate(self):
        if self.token is None:
            body = self._request(
                self.token_url,
                requests.auth.HTTPBasicAuth(*self.credentials),
                data={"grant_type": "client_credentials"},
            )
            if (
                not isinstance(body.get("token_type"), str)
                or body["token_type"].lower() != "bearer"
                or type(body.get("expires_in")) is not int
                or body["expires_in"] <= 0
            ):
                raise TorqError("Torq returned an invalid token response.")
            self.token = _secret(body.get("access_token"), "access_token")

    def post(self, path, payload):
        if path not in ("/v1alpha/observables/query", "/v1alpha/cases"):
            raise TorqError("Unsupported Torq API operation.")
        self.authenticate()
        return self._request(self.base + path, _BearerAuth(self.token), json=payload)
