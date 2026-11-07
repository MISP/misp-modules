"""Bounded authenticated transport for Shuffle workflow and Datastore modules."""

import json
import re
from urllib.parse import unquote, urlsplit
from uuid import UUID

import requests

API_REFERENCE = "https://shuffler.io/docs/API"
SOURCE_REFERENCE = "https://github.com/Shuffle/shuffle-docs/blob/master/docs/API.md"


class ShuffleError(ValueError):
    """A diagnostic safe to return without credentials or remote error bodies."""


def uuid(value, name):
    try:
        parsed = UUID(value)
        if not parsed.int:
            raise ValueError("Empty UUID")
        return str(parsed)
    except (ValueError, TypeError, AttributeError):
        raise ShuffleError(f"{name} must be a valid non-empty UUID.") from None


def boolean(value, name, default=False):
    if value is None or value == "":
        return default
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "0", "1"):
        return value.lower() in ("true", "1")
    raise ShuffleError(f"{name} must be true, false, 1 or 0.")


def integer(value, name, default, maximum):
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,6}", str(value)) or not 1 <= int(value) <= maximum:
        raise ShuffleError(f"{name} must be between 1 and {maximum}.")
    return int(value)


def category(value):
    if (
        not isinstance(value, str)
        or len(value) > 128
        or value != value.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ShuffleError(
            "category must be a string of at most 128 characters without surrounding whitespace or controls."
        )
    value.encode("utf-8")
    return "" if value == "default" else value


class _Auth(requests.auth.AuthBase):
    def __init__(self, key, org_id):
        self.key, self.org_id = key, org_id

    def __call__(self, request):
        request.headers["Authorization"] = "Bearer " + self.key
        request.headers["Org-Id"] = self.org_id
        return request


def encode(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "utf-8"
    )


def _invalid_constant(value):
    raise ValueError("Non-JSON numeric constant")


class Client:
    def __init__(self, config):
        if not isinstance(config, dict):
            raise ShuffleError("Shuffle connection configuration is required.")
        url = config.get("url")
        if not isinstance(url, str):
            raise ShuffleError("Configure the HTTPS Shuffle API root ending in /api/v1.")
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.port == 0
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not parsed.path.rstrip("/").endswith("/api/v1")
            or any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in url)
            or any(part in (".", "..") for part in unquote(parsed.path).split("/"))
        ):
            raise ShuffleError("Use an HTTPS API root ending in /api/v1, without credentials, query or fragment.")
        key = config.get("api_key")
        if not isinstance(key, str) or not 1 <= len(key) <= 8192 or any(not 33 <= ord(char) <= 126 for char in key):
            raise ShuffleError("A non-empty printable ASCII api_key is required.")
        self.base = url.rstrip("/")
        self.org_id = uuid(config.get("org_id"), "org_id")
        self.timeout = integer(config.get("timeout"), "timeout", 20, 120)
        self.auth = _Auth(key, self.org_id)
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "User-Agent": "MISP-misp-modules/shuffle"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def _post(self, path, payload):
        try:
            with self.session.post(
                self.base + path, json=payload, auth=self.auth, timeout=self.timeout, allow_redirects=False, stream=True
            ) as response:
                if response.status_code != 200:
                    raise ShuffleError(f"Shuffle returned HTTP {response.status_code}.")
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > 2 * 1024 * 1024:
                        raise ShuffleError("Shuffle response exceeds the 2 MiB limit.")
                try:
                    body = json.loads(content, parse_constant=_invalid_constant)
                except (ValueError, RecursionError):
                    raise ShuffleError("Shuffle returned invalid JSON.") from None
        except (requests.RequestException, OSError):
            raise ShuffleError("Shuffle request failed or timed out.") from None
        if not isinstance(body, dict) or body.get("success") is not True or body.get("error") or body.get("errors"):
            raise ShuffleError("Shuffle did not confirm success; the resource may be unavailable or inaccessible.")
        return body

    def datastore(self, key, selected_category):
        return self._post(
            "/orgs/" + self.org_id + "/get_cache", {"org_id": self.org_id, "key": key, "category": selected_category}
        )

    def execute(self, workflow_id, argument):
        workflow_id = uuid(workflow_id, "workflow_id")
        return self._post("/workflows/" + workflow_id + "/execute", {"execution_argument": argument, "start": ""})
