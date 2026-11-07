import json
from unittest.mock import patch

import pytest
import requests

from misp_modules.lib import tines

CONFIG = {"url": "https://tenant.tines.example", "api_key": "synthetic-tines-key"}


class FakeAPI:
    """Use requests' real preparation/authentication and replace only network I/O."""

    def __init__(self):
        self.calls = []
        self.replies = {}

    def send(self, adapter, request, **kwargs):
        self.calls.append((request, kwargs))
        path = request.url.removeprefix(CONFIG["url"])
        reply = self.replies.get(path)
        if isinstance(reply, Exception):
            raise reply
        if reply is None:
            payload = json.loads(request.body)
            if path == "/api/v2/records/search":
                reply = {
                    "data": [
                        {
                            "id": 555,
                            "fields": {
                                "indicator": payload["filter"]["value"],
                                "enabled": False,
                                "payload": {"expandable": True, "href": "https://unexpected.example/artifact"},
                            },
                            "relationships": {"record_type": {"id": payload["record_type_id"]}, "parent_record": None},
                            "created_at": "2026-07-02T00:00:00Z",
                        }
                    ],
                    "field_ids": {"indicator": payload["filter"]["field_id"], "enabled": 102, "payload": 103},
                    "page": {"total": 1},
                    "applied": {"filter": payload["filter"], "sort": []},
                }
            elif path == "/api/v2/cases":
                reply = (
                    201,
                    {
                        "case_id": 12,
                        "name": payload["name"],
                        "team": {"id": payload["team_id"]},
                        "status": payload["status"],
                        "priority": payload["priority"],
                        "metadata": payload["metadata"],
                        "url": CONFIG["url"] + f'/team/{payload["team_id"]}/cases/12',
                    },
                )
            else:
                raise AssertionError("Unexpected URL: " + request.url)
        status, data = reply if isinstance(reply, tuple) else (200, reply)
        response = requests.Response()
        response.status_code, response.url, response.request = status, request.url, request
        response._content = data if isinstance(data, bytes) else json.dumps(data).encode()
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


def search_body():
    return {
        "record_type_id": 42,
        "filter": {"field_id": 101, "operator": "EQUAL", "value": "example.org"},
        "include_total": True,
        "limit": 20,
    }


def test_documented_token_authentication_preserves_tls_and_proxy_configuration(api):
    with patch("requests.sessions.get_netrc_auth", return_value=("wrong", "wrong")):
        with tines.Client({**CONFIG, "timeout": "7"}) as client:
            response = client.post("/api/v2/records/search", search_body())
    request, options = api.calls[0]
    assert request.url == CONFIG["url"] + "/api/v2/records/search" and request.method == "POST"
    assert request.headers["X-User-Token"] == CONFIG["api_key"] and "Authorization" not in request.headers
    assert request.headers["Content-Type"] == "application/json" and json.loads(request.body) == search_body()
    assert options["timeout"] == 7 and options["verify"] and options["stream"]
    assert dict(options["proxies"]) == requests.utils.get_environ_proxies(CONFIG["url"])
    assert CONFIG["api_key"] not in request.url and response["data"][0]["id"] == 555


@pytest.mark.parametrize(
    "config",
    [
        {"url": "http://example.org"},
        {"url": "https://u:p@example.org"},
        {"url": "https://example.org/path"},
        {"url": "https://example.org?x=y"},
        {"url": "https://example.org#fragment"},
        {"url": "https://example.org:0"},
        {"url": "https://example.org\n"},
        {"api_key": "bad\n"},
        {"api_key": ""},
        {"timeout": 0},
        {"timeout": True},
        {"timeout": 121},
    ],
)
def test_invalid_connections_do_not_make_requests(api, config):
    with pytest.raises(ValueError):
        with tines.Client({**CONFIG, **config}) as client:
            client.post("/api/v2/records/search", search_body())
    assert not api.calls


@pytest.mark.parametrize("status", [302, 400, 401, 403, 404, 429, 500])
def test_errors_never_redirect_retry_or_echo_remote_details(api, status):
    api.replies["/api/v2/records/search"] = (status, {"error": CONFIG["api_key"]})
    with pytest.raises(tines.TinesError) as error:
        with tines.Client(CONFIG) as client:
            client.post("/api/v2/records/search", search_body())
    assert str(status) in str(error.value) and CONFIG["api_key"] not in str(error.value)
    if status == 404:
        assert "lacks access" in str(error.value)
    assert len(api.calls) == 1


@pytest.mark.parametrize(
    "reply",
    [b"bad JSON", (200, []), {"errors": [CONFIG["api_key"]]}, b'{"data": NaN}', requests.Timeout(CONFIG["api_key"])],
)
def test_invalid_api_responses_and_network_errors_are_sanitized(api, reply):
    api.replies["/api/v2/records/search"] = reply
    with pytest.raises(tines.TinesError) as error:
        with tines.Client(CONFIG) as client:
            client.post("/api/v2/records/search", search_body())
    assert CONFIG["api_key"] not in str(error.value)


def test_response_size_limit_and_resource_cleanup(api):
    api.replies["/api/v2/records/search"] = b" " * (2 * 1024 * 1024 + 1)
    with (
        patch.object(requests.Session, "close") as close_session,
        patch.object(requests.Response, "close") as close_response,
    ):
        with pytest.raises(tines.TinesError):
            with tines.Client(CONFIG) as client:
                client.post("/api/v2/records/search", search_body())
    assert close_session.call_count == close_response.call_count == 1


def test_unsupported_operations_cannot_send_credentials_elsewhere(api):
    with pytest.raises(tines.TinesError):
        with tines.Client(CONFIG) as client:
            client.post("https://unexpected.example/collect", {})
    assert not api.calls
