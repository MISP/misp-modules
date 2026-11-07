import json
from unittest.mock import patch

import pytest
import requests

from misp_modules.lib import n8n

ORIGIN = "https://n8n.example"
SECRET = "synthetic-n8n-secret"
TABLE_ID = "AbCdEfGh12345678"


class FakeHTTP:
    """Retain requests preparation, proxy and auth handling; replace network I/O."""

    def __init__(self):
        self.calls = []
        self.replies = {}

    def send(self, adapter, request, **options):
        self.calls.append((request, options))
        path = request.path_url.split("?", 1)[0]
        reply = self.replies.get(path)
        if isinstance(reply, Exception):
            raise reply
        if reply is None:
            if path.endswith("/columns"):
                reply = [
                    {
                        "id": "col1",
                        "name": "indicator",
                        "type": "string",
                        "index": 0,
                        "dataTableId": TABLE_ID,
                        "createdAt": "2026-11-01T00:00:00Z",
                        "updatedAt": "2026-11-01T00:00:00Z",
                    }
                ]
            elif path.endswith("/rows"):
                reply = {
                    "data": [
                        {
                            "id": 1,
                            "indicator": "example.org",
                            "enabled": False,
                            "score": 0,
                            "createdAt": "2026-11-01T00:00:00Z",
                            "updatedAt": "2026-11-01T00:00:00Z",
                        }
                    ],
                    "nextCursor": None,
                }
            else:
                reply = (200, b'{"message":"Workflow was started"}')
        status, body = reply if isinstance(reply, tuple) else (200, reply)
        response = requests.Response()
        response.status_code, response.url, response.request = status, request.url, request
        response._content = body if isinstance(body, bytes) else json.dumps(body).encode()
        response._content_consumed = True
        if 300 <= status < 400:
            response.headers["Location"] = "https://unexpected.example/collect"
        return response


@pytest.fixture
def http():
    fake = FakeHTTP()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


def test_auth_does_not_use_netrc_and_preserves_tls_proxy_settings(http):
    http.replies["/api/v1/test"] = {"data": []}
    with patch("requests.sessions.get_netrc_auth", return_value=("unwanted", "password")):
        body = n8n.request("GET", ORIGIN + "/api/v1/test", n8n.HeaderAuth("X-N8N-API-KEY", SECRET), read_json=True)
    request, options = http.calls[0]
    assert body == {"data": []} and request.headers["X-N8N-API-KEY"] == SECRET
    assert "Authorization" not in request.headers and SECRET not in request.url
    assert options["verify"] and options["timeout"] == 20 and options["stream"]
    assert dict(options["proxies"]) == requests.utils.get_environ_proxies(ORIGIN)


@pytest.mark.parametrize("name", ["Authorization", "X-MISP-Token"])
def test_webhook_auth_is_separate_from_public_api_auth(http, name):
    n8n.request("POST", ORIGIN + "/webhook/misp", n8n.HeaderAuth(name, SECRET), payload=b"{}")
    request = http.calls[0][0]
    assert request.headers[name] == SECRET and "X-N8N-API-KEY" not in request.headers
    assert request.headers["Content-Type"] == "application/json"


@pytest.mark.parametrize(
    "name,value",
    [
        ("Host", SECRET),
        ("Cookie", SECRET),
        ("X-Forwarded-Host", SECRET),
        ("X-HTTP-Method-Override", SECRET),
        ("X-Bad\n", SECRET),
        ("X-Test", ""),
        ("X-Test", "bad\r\nsecret"),
        ("X-Test", "ß"),
        ("X-Test", " "),
    ],
)
def test_invalid_auth_headers_fail_without_network(http, name, value):
    with pytest.raises(n8n.N8nError):
        n8n.HeaderAuth(name, value)
    assert not http.calls


@pytest.mark.parametrize(
    "url",
    [
        "http://n8n.example/webhook/misp",
        "https://user:password@n8n.example/webhook/misp",
        "https://n8n.example/webhook/misp?secret=x",
        "https://n8n.example/webhook/misp#x",
        "https://n8n.example:0/webhook/misp",
        "https://n8n.example/webhook/../misp",
        "https://n8n.example/webhook/%2e%2e/misp",
        "https://n8n.example/webhook/misp\n",
        "https://n8n.example\\other.example/webhook/misp",
    ],
)
def test_invalid_urls(url):
    with pytest.raises(ValueError):
        n8n.https_url(url)


def test_base_paths_and_custom_webhook_endpoints():
    assert n8n.https_url(ORIGIN + "/automation/api/v1/", api=True) == ORIGIN + "/automation/api/v1"
    assert n8n.https_url(ORIGIN + "/custom-hooks/misp/") == ORIGIN + "/custom-hooks/misp/"
    with pytest.raises(n8n.N8nError):
        n8n.https_url(ORIGIN + "/api/v2", api=True)


@pytest.mark.parametrize("status", [302, 400, 401, 403, 404, 429, 500])
def test_http_errors_are_not_retried_redirected_or_echoed(http, status):
    http.replies["/api/v1/test"] = (status, {"error": SECRET})
    with pytest.raises(n8n.N8nError) as error:
        n8n.request("GET", ORIGIN + "/api/v1/test", n8n.HeaderAuth("X-N8N-API-KEY", SECRET), read_json=True)
    assert str(status) in str(error.value) and SECRET not in str(error.value) and len(http.calls) == 1


@pytest.mark.parametrize(
    "reply",
    [
        b"bad-json",
        b'{"data": NaN}',
        {"errors": [SECRET]},
        (200, None),
        requests.Timeout(SECRET),
        b" " * (2 * 1024 * 1024 + 1),
    ],
)
def test_malformed_oversized_and_network_responses_are_safe(http, reply):
    http.replies["/api/v1/test"] = reply
    with pytest.raises(n8n.N8nError) as error:
        n8n.request("GET", ORIGIN + "/api/v1/test", n8n.HeaderAuth("X-N8N-API-KEY", SECRET), read_json=True)
    assert SECRET not in str(error.value)


def test_sessions_and_responses_are_closed(http):
    with (
        patch.object(requests.Session, "close") as session_close,
        patch.object(requests.Response, "close") as response_close,
    ):
        n8n.request("POST", ORIGIN + "/webhook/misp", n8n.HeaderAuth("X-MISP-Token", SECRET), payload=b"{}")
    assert session_close.call_count == response_close.call_count == 1
