import hashlib
import json
from unittest.mock import patch

import pytest
import requests

from misp_modules.lib import cortex_xsoar as xsoar

CONFIG = {
    "url": "https://api-xsoar.example",
    "api_key": "synthetic-xsoar-key",
    "api_key_id": "2841",
    "auth_type": "standard",
}


class FakeAPI:
    """Real requests preparation/authentication with synthetic API responses."""

    def __init__(self):
        self.calls, self.replies = [], {}
        self.rows = [
            {
                "id": "indicator-1",
                "value": "example.org",
                "indicator_type": "Domain",
                "score": 0,
                "expirationStatus": "active",
                "isDetectable": False,
                "CustomFields": {"known": False},
            }
        ]

    def send(self, adapter, request, **options):
        self.calls.append((request, options))
        operation = "search" if request.url.endswith("/indicators/search") else "incident"
        reply = self.replies.get(operation)
        if isinstance(reply, Exception):
            raise reply
        if reply is None:
            if operation == "search":
                reply = {"iocObjects": self.rows, "total": len(self.rows), "accountErrors": [], "totalAccounts": 1}
            else:
                payload = json.loads(request.body)
                reply = (201, {"id": "12345", "status": 0, "investigationId": "", **payload})
        status, body = reply if isinstance(reply, tuple) else (200, reply)
        response = requests.Response()
        response.status_code, response.url, response.request = status, request.url, request
        response._content = body if isinstance(body, bytes) else json.dumps(body).encode()
        response._content_consumed = True
        if 300 <= status < 400:
            response.headers["Location"] = "https://unexpected.example/collect"
        return response


@pytest.fixture
def api():
    fake = FakeAPI()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


def test_standard_key_uses_xsoar_route_and_raw_authorization_without_netrc(api):
    with patch("requests.sessions.get_netrc_auth", return_value=("wrong", "wrong")):
        with xsoar.Client({**CONFIG, "timeout": "7"}) as client:
            status, body = client.post("search", {"query": 'value:"example.org"', "size": 20})
    request, options = api.calls[0]
    assert request.url == CONFIG["url"] + "/xsoar/public/v1/indicators/search" and request.method == "POST"
    assert request.headers["Authorization"] == CONFIG["api_key"] and request.headers["x-xdr-auth-id"] == "2841"
    assert "x-xdr-nonce" not in request.headers and "x-xdr-timestamp" not in request.headers
    assert options["timeout"] == 7 and options["verify"] and options["stream"]
    assert dict(options["proxies"]) == requests.utils.get_environ_proxies(request.url)
    assert status == 200 and body["total"] == 1 and CONFIG["api_key"] not in request.url


def test_advanced_key_hash_matches_official_concatenation_and_refreshes_nonce(api):
    with (
        patch.object(xsoar.secrets, "token_hex", side_effect=["a" * 64, "b" * 64]),
        patch.object(xsoar.time, "time", return_value=1700000000.125),
    ):
        with xsoar.Client({**CONFIG, "auth_type": "advanced"}) as client:
            client.post("search", {})
            client.post("search", {})
    for (request, _), nonce in zip(api.calls, ("a" * 64, "b" * 64)):
        stamp = "1700000000125"
        assert request.headers["x-xdr-nonce"] == nonce and request.headers["x-xdr-timestamp"] == stamp
        assert (
            request.headers["Authorization"] == hashlib.sha256((CONFIG["api_key"] + nonce + stamp).encode()).hexdigest()
        )
        assert CONFIG["api_key"] not in str(request.headers)


def test_advanced_is_default_and_copied_full_api_root_is_accepted(api):
    config = {**CONFIG, "url": CONFIG["url"] + "/xsoar/public/v1/"}
    del config["auth_type"]
    with xsoar.Client(config) as client:
        client.post("search", {})
    assert api.calls[0][0].url == CONFIG["url"] + "/xsoar/public/v1/indicators/search"
    assert "x-xdr-nonce" in api.calls[0][0].headers


@pytest.mark.parametrize(
    "updates",
    [
        {"url": "http://api-xsoar.example"},
        {"url": "https://u:p@api-xsoar.example"},
        {"url": "https://api-xsoar.example/public_api/v1"},
        {"url": "https://api-xsoar.example?secret=x"},
        {"url": "https://api-xsoar.example#x"},
        {"url": "https://api-xsoar.example:0"},
        {"url": "https://api-xsoar.example\n"},
        {"api_key": ""},
        {"api_key": "bad\n"},
        {"api_key_id": True},
        {"api_key_id": 0},
        {"api_key_id": "bad"},
        {"auth_type": "bearer"},
        {"auth_type": False},
        {"timeout": 0},
        {"timeout": 121},
    ],
)
def test_invalid_config_makes_no_request(api, updates):
    with pytest.raises(ValueError):
        xsoar.Client({**CONFIG, **updates})
    assert not api.calls


@pytest.mark.parametrize("status", [302, 400, 401, 403, 404, 429, 500])
def test_api_errors_are_not_retried_redirected_or_echoed(api, status):
    api.replies["search"] = (status, {"error": CONFIG["api_key"]})
    with pytest.raises(xsoar.XsoarError) as error:
        with xsoar.Client(CONFIG) as client:
            client.post("search", {})
    assert str(status) in str(error.value) and CONFIG["api_key"] not in str(error.value) and len(api.calls) == 1


@pytest.mark.parametrize(
    "reply",
    [
        b"bad-json",
        (200, []),
        b'{"total":NaN}',
        {"errors": [CONFIG["api_key"]]},
        requests.Timeout(CONFIG["api_key"]),
        pytest.param(b" " * (2 * 1024 * 1024 + 1), id="oversized-response"),
    ],
)
def test_invalid_and_network_responses_are_safe(api, reply):
    api.replies["search"] = reply
    with pytest.raises(xsoar.XsoarError) as error:
        with xsoar.Client(CONFIG) as client:
            client.post("search", {})
    assert CONFIG["api_key"] not in str(error.value)


@pytest.mark.parametrize("body", [b"", b"not-json", b'{"id":"unexpected"}'])
def test_http_200_incident_response_is_not_creation_even_with_a_body(api, body):
    api.replies["incident"] = (200, body)
    with xsoar.Client(CONFIG) as client:
        assert client.post("incident", {"name": "synthetic"}) == (200, None)
    assert len(api.calls) == 1


def test_incident_created_response_is_http_201_and_flat(api):
    with xsoar.Client(CONFIG) as client:
        status, body = client.post("incident", {"name": "synthetic"})
    assert status == 201 and body["id"] == "12345" and body["name"] == "synthetic"
    assert api.calls[0][0].url.endswith("/xsoar/public/v1/incident")


def test_cleanup_and_unsupported_operation(api):
    with (
        patch.object(requests.Session, "close") as close_session,
        patch.object(requests.Response, "close") as close_response,
    ):
        with xsoar.Client(CONFIG) as client:
            client.post("search", {})
    assert close_session.call_count == close_response.call_count == 1
    api.calls.clear()
    with pytest.raises(xsoar.XsoarError):
        with xsoar.Client(CONFIG) as client:
            client.post("https://unexpected.example/collect", {})
    assert not api.calls
