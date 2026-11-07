"""Small transport and validation helpers for n8n modules."""

import json
import re
from urllib.parse import unquote, urlsplit

import requests

API_REFERENCE = "https://docs.n8n.io/connect/n8n-api"
AUTH_REFERENCE = "https://docs.n8n.io/connect/n8n-api/authentication"
TABLE_REFERENCE = "https://docs.n8n.io/connect/n8n-api/data-table"
WEBHOOK_REFERENCE = "https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/"


class N8nError(ValueError):
    """An error safe to return without credentials, URLs or response bodies."""


def boolean(value, name, default=False):
    if value is None or value == "":
        return default
    if isinstance(value, (bool, int)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "0", "1"):
        return value.lower() in ("true", "1")
    raise N8nError(f"{name} must be true, false, 1 or 0.")


def integer(value, name, default, maximum):
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,6}", str(value)) or not 1 <= int(value) <= maximum:
        raise N8nError(f"{name} must be between 1 and {maximum}.")
    return int(value)


def https_url(value, api=False):
    if not isinstance(value, str):
        raise N8nError("Configure an HTTPS n8n URL.")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in value)
        or any(part in (".", "..") for part in unquote(parsed.path).split("/"))
        or (api and not parsed.path.rstrip("/").endswith("/api/v1"))
        or (not api and parsed.path in ("", "/"))
    ):
        raise N8nError("Use an HTTPS URL without credentials, query or fragment; API roots must end in /api/v1.")
    return value.rstrip("/") if api else value


class HeaderAuth(requests.auth.AuthBase):
    def __init__(self, name, value):
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", name):
            raise N8nError("Configure a valid authentication header name.")
        # Authentication headers must not override HTTP routing or framing.
        if name.lower() != "authorization" and (
            not name.lower().startswith("x-") or name.lower().startswith(("x-forwarded-", "x-http-method-"))
        ):
            raise N8nError("Use Authorization or an X- authentication header.")
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 8192
            or any(not 33 <= ord(char) <= 126 and char != " " for char in value)
            or not value.strip()
        ):
            raise N8nError("Configure a non-empty printable ASCII authentication secret.")
        self.name, self.value = name, value

    def __call__(self, request):
        request.headers.pop("Authorization", None)
        request.headers.pop("X-N8N-API-KEY", None)
        request.headers[self.name] = self.value
        return request


def encode(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "utf-8"
    )


def _invalid_constant(value):
    raise ValueError("Non-JSON numeric constant")


def request(method, url, auth, timeout=20, payload=None, params=None, read_json=False, headers=None):
    """No redirects/retries. Webhook responses are discarded; API JSON is bounded."""
    try:
        with requests.Session() as session:
            session.headers.update({"Accept": "application/json", "User-Agent": "MISP-misp-modules/n8n"})
            if payload is not None:
                session.headers["Content-Type"] = "application/json"
            with session.request(
                method,
                url,
                auth=auth,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                data=payload,
                params=params,
                headers=headers,
            ) as response:
                if (read_json and response.status_code != 200) or not 200 <= response.status_code < 300:
                    raise N8nError(f"n8n returned HTTP {response.status_code}.")
                if not read_json:
                    return response.status_code
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > 2 * 1024 * 1024:
                        raise N8nError("n8n response exceeds the 2 MiB limit.")
                try:
                    body = json.loads(content, parse_constant=_invalid_constant)
                except (ValueError, RecursionError):
                    raise N8nError("n8n returned invalid JSON.") from None
                if not isinstance(body, (dict, list)) or (
                    isinstance(body, dict) and (body.get("error") or body.get("errors"))
                ):
                    raise N8nError("n8n returned an API error or unexpected response.")
                return body
    except (requests.RequestException, OSError):
        raise N8nError("n8n request failed or timed out.") from None
