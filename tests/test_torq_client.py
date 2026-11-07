import base64
import json
from unittest.mock import patch
from urllib.parse import parse_qs

import pytest
import requests

from misp_modules.lib import torq

CONFIG = {"region": "us", "client_id": "synthetic-client", "client_secret": "synthetic-secret"}
TOKEN = "synthetic-access-token"


class FakeAPI:
    """Use requests preparation/authentication and replace only network I/O."""

    def __init__(self):
        self.calls, self.replies = [], {}

    def send(self, adapter, request, **options):
        self.calls.append((request, options))
        path = request.path_url
        reply = self.replies.get(path)
        if isinstance(reply, Exception):
            raise reply
        if reply is None:
            if path == "/v1/auth/token":
                reply = {"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600}
            elif path == "/public/v1alpha/observables/query":
                payload = json.loads(request.body)
                type_id = payload["filter"]["types"][0]["id"]
                field = {
                    "TYPE_ID_HOSTNAME": "hostname",
                    "TYPE_ID_IP_ADDRESS": "ip",
                    "TYPE_ID_FILE_HASH": "file_hash",
                    "TYPE_ID_EMAIL_ADDRESS": "email_address",
                    "TYPE_ID_URL": "url",
                    "TYPE_ID_FILE_NAME": "file_name",
                }[type_id]
                reply = {
                    "observables": [
                        {
                            "id": 28,
                            "type": {"id": type_id},
                            "value": {field: payload["filter"]["search"]},
                            "reputation": {"id": "SCORE_SUSPICIOUS_OR_RISKY"},
                            "associated_cases_count": 0,
                            "enrichment": {"known": False},
                            "threat_intel": {"detection": {"detected_count": 0}},
                        }
                    ]
                }
            elif path == "/public/v1alpha/cases":
                payload = json.loads(request.body)
                reply = {"case": {"id": 28, "pretty_id": "#28", **payload}}
            else:
                raise AssertionError("Unexpected URL: " + request.url)
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


def payload():
    return {"filter": {"types": [{"id": "TYPE_ID_HOSTNAME"}], "search": "example.org"}, "page_size": 20}


@pytest.mark.parametrize("region", ["us", "eu"])
def test_documented_oauth_and_regional_public_paths_preserve_tls_and_proxies(api, region):
    with patch("requests.sessions.get_netrc_auth", return_value=("wrong", "wrong")):
        with torq.Client({**CONFIG, "region": region, "timeout": "7"}) as client:
            result = client.post("/v1alpha/observables/query", payload())
    token, query = [call[0] for call in api.calls]
    assert token.url == torq.REGIONS[region][1] and token.method == "POST"
    assert token.headers["Authorization"] == "Basic " + base64.b64encode(b"synthetic-client:synthetic-secret").decode()
    assert token.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert parse_qs(token.body) == {"grant_type": ["client_credentials"]}
    assert query.url == torq.REGIONS[region][0] + "/v1alpha/observables/query"
    assert query.headers["Authorization"] == "Bearer " + TOKEN and json.loads(query.body) == payload()
    assert result["observables"][0]["id"] == 28 and CONFIG["client_secret"] not in query.body.decode()
    for request, options in api.calls:
        assert options["timeout"] == 7 and options["verify"] and options["stream"]
        assert dict(options["proxies"]) == requests.utils.get_environ_proxies(request.url)
        assert CONFIG["client_secret"] not in request.url and TOKEN not in request.url


@pytest.mark.parametrize("region", ["us", "eu", "jp"])
def test_existing_token_avoids_oauth_and_uses_correct_workspace_region(api, region):
    with torq.Client({"region": region, "access_token": TOKEN}) as client:
        client.post("/v1alpha/observables/query", payload())
    assert len(api.calls) == 1 and api.calls[0][0].url.startswith(torq.REGIONS[region][0] + "/")
    assert api.calls[0][0].headers["Authorization"] == "Bearer " + TOKEN


@pytest.mark.parametrize(
    "updates",
    [
        {"region": "invalid"},
        {"region": []},
        {"region": "jp"},
        {"client_id": "a:b"},
        {"client_id": ""},
        {"client_secret": "bad\n"},
        {"access_token": TOKEN},
        {"timeout": 0},
        {"timeout": True},
        {"timeout": 121},
    ],
)
def test_bad_configuration_is_rejected_without_network(api, updates):
    with pytest.raises(torq.TorqError):
        torq.Client({**CONFIG, **updates})
    assert not api.calls


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"access_token": "bad\n", "token_type": "Bearer", "expires_in": 3600},
        {"access_token": TOKEN, "token_type": "Basic", "expires_in": 3600},
        {"access_token": TOKEN, "token_type": "Bearer", "expires_in": True},
        {"access_token": TOKEN, "token_type": "Bearer", "expires_in": 0},
    ],
)
def test_bad_token_reply_cannot_reach_public_api(api, body):
    api.replies["/v1/auth/token"] = body
    with pytest.raises(torq.TorqError):
        with torq.Client(CONFIG) as client:
            client.post("/v1alpha/observables/query", payload())
    assert len(api.calls) == 1


@pytest.mark.parametrize("status", [302, 400, 401, 403, 404, 429, 500])
def test_api_errors_never_retry_redirect_or_echo_secrets(api, status):
    api.replies["/public/v1alpha/observables/query"] = (status, {"message": TOKEN})
    with pytest.raises(torq.TorqError) as error:
        with torq.Client({"access_token": TOKEN}) as client:
            client.post("/v1alpha/observables/query", payload())
    assert str(status) in str(error.value) and TOKEN not in str(error.value) and len(api.calls) == 1


@pytest.mark.parametrize(
    "reply",
    [
        b"bad-json",
        (200, []),
        b'{"observables": NaN}',
        {"errors": [TOKEN]},
        {"code": 7, "message": TOKEN},
        requests.Timeout(TOKEN),
        b" " * (2 * 1024 * 1024 + 1),
    ],
)
def test_malformed_oversized_and_network_errors_are_safe(api, reply):
    api.replies["/public/v1alpha/observables/query"] = reply
    with pytest.raises(torq.TorqError) as error:
        with torq.Client({"access_token": TOKEN}) as client:
            client.post("/v1alpha/observables/query", payload())
    assert TOKEN not in str(error.value)


def test_request_local_token_and_resource_cleanup(api):
    with (
        patch.object(requests.Session, "close") as close_session,
        patch.object(requests.Response, "close") as close_response,
    ):
        with torq.Client(CONFIG) as client:
            client.authenticate()
            client.post("/v1alpha/observables/query", payload())
    assert len(api.calls) == 2 and close_session.call_count == 1 and close_response.call_count == 2


def test_unsupported_path_cannot_send_any_credentials(api):
    with pytest.raises(torq.TorqError):
        with torq.Client(CONFIG) as client:
            client.post("https://unexpected.example/collect", {})
    assert not api.calls
