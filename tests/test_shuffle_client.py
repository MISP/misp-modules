import json
from unittest.mock import patch

import pytest
import requests

from misp_modules.lib import shuffle

ORG_ID = "2e7b6a08-b63b-4fc2-bd70-718091509db1"
WORKFLOW_ID = "8f3c6a10-f5ca-432c-aef9-c5e038166c45"
EXECUTION_ID = "6e58639e-a24f-4af8-b62b-d6fcc2bc10f4"
CONFIG = {"url": "https://shuffle.example/api/v1", "api_key": "synthetic-shuffle-key", "org_id": ORG_ID}
EXECUTION_SECRET = "synthetic-execution-authorization"
DATASTORE_SECRET = "synthetic-public-authorization"


class FakeAPI:
    """Keep requests preparation/authentication; replace only HTTP adapter I/O."""

    def __init__(self):
        self.calls, self.replies = [], {}

    def send(self, adapter, request, **options):
        self.calls.append((request, options))
        operation = "get_cache" if request.url.endswith("/get_cache") else "execute"
        reply = self.replies.get(operation)
        if isinstance(reply, Exception):
            raise reply
        if reply is None:
            if operation == "get_cache":
                payload = json.loads(request.body)
                reply = {
                    "success": True,
                    "key": payload["key"],
                    "category": payload["category"],
                    "org_id": "",
                    "value": {"active": False, "score": 0, "label": "synthetic"},
                    "created": 1761114186,
                    "edited": 1761114186,
                    "changed": False,
                    "encrypted": False,
                    "workflow_id": WORKFLOW_ID,
                    "authorization": EXECUTION_SECRET,
                    "public_authorization": DATASTORE_SECRET,
                    "execution_id": EXECUTION_ID,
                }
            else:
                reply = {"success": True, "execution_id": EXECUTION_ID, "authorization": EXECUTION_SECRET}
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


def test_documented_bearer_tenant_auth_preserves_tls_and_proxy_settings(api):
    with patch("requests.sessions.get_netrc_auth", return_value=("wrong", "wrong")):
        with shuffle.Client({**CONFIG, "timeout": "7"}) as client:
            result = client.datastore("example.org", "misp")
    request, options = api.calls[0]
    assert request.url == CONFIG["url"] + "/orgs/" + ORG_ID + "/get_cache" and request.method == "POST"
    assert request.headers["Authorization"] == "Bearer " + CONFIG["api_key"] and request.headers["Org-Id"] == ORG_ID
    assert request.headers["Content-Type"] == "application/json"
    assert json.loads(request.body) == {"org_id": ORG_ID, "key": "example.org", "category": "misp"}
    assert options["timeout"] == 7 and options["verify"] and options["stream"]
    assert dict(options["proxies"]) == requests.utils.get_environ_proxies(request.url)
    assert CONFIG["api_key"] not in request.url and result["success"] is True


def test_execution_uses_json_string_argument_and_default_start(api):
    argument = '{"Event":{"uuid":"synthetic"}}'
    with shuffle.Client(CONFIG) as client:
        result = client.execute(WORKFLOW_ID, argument)
    request = api.calls[0][0]
    assert request.url == CONFIG["url"] + "/workflows/" + WORKFLOW_ID + "/execute"
    assert json.loads(request.body) == {"execution_argument": argument, "start": ""}
    assert result["execution_id"] == EXECUTION_ID


def test_self_hosted_subpath_and_region_hosts_are_preserved(api):
    with shuffle.Client({**CONFIG, "url": "https://shuffle.example/automation/api/v1/"}) as client:
        client.datastore("example.org", "misp")
    assert api.calls[0][0].url == "https://shuffle.example/automation/api/v1/orgs/" + ORG_ID + "/get_cache"


@pytest.mark.parametrize(
    "updates",
    [
        {"url": "http://shuffle.example/api/v1"},
        {"url": "https://u:p@shuffle.example/api/v1"},
        {"url": "https://shuffle.example/api/v1?key=x"},
        {"url": "https://shuffle.example/api/v1#x"},
        {"url": "https://shuffle.example/api/v2"},
        {"url": "https://shuffle.example:0/api/v1"},
        {"url": "https://shuffle.example/../api/v1"},
        {"url": "https://shuffle.example/%2e%2e/api/v1"},
        {"url": "https://shuffle.example\\other.example/api/v1"},
        {"url": "https://shuffle.example/api/v1\n"},
        {"api_key": ""},
        {"api_key": "bad\n"},
        {"org_id": "../other"},
        {"org_id": None},
        {"org_id": "0" * 32},
        {"timeout": True},
        {"timeout": 0},
        {"timeout": 121},
    ],
)
def test_invalid_configuration_makes_no_request(api, updates):
    with pytest.raises(ValueError):
        shuffle.Client({**CONFIG, **updates})
    assert not api.calls


@pytest.mark.parametrize("status", [302, 400, 401, 403, 404, 429, 500])
def test_http_errors_never_redirect_retry_or_echo_credentials(api, status):
    api.replies["get_cache"] = (status, {"reason": CONFIG["api_key"]})
    with pytest.raises(shuffle.ShuffleError) as error:
        with shuffle.Client(CONFIG) as client:
            client.datastore("example.org", "misp")
    assert str(status) in str(error.value) and CONFIG["api_key"] not in str(error.value) and len(api.calls) == 1


@pytest.mark.parametrize(
    "reply",
    [
        b"bad-json",
        b'{"success": true, "value": NaN}',
        (200, []),
        {},
        {"success": False, "reason": CONFIG["api_key"]},
        {"success": 1},
        {"success": True, "errors": [CONFIG["api_key"]]},
        requests.Timeout(CONFIG["api_key"]),
        pytest.param(b" " * (2 * 1024 * 1024 + 1), id="oversized-response"),
    ],
)
def test_malformed_unconfirmed_and_network_responses_are_safe(api, reply):
    api.replies["get_cache"] = reply
    with pytest.raises(shuffle.ShuffleError) as error:
        with shuffle.Client(CONFIG) as client:
            client.datastore("example.org", "misp")
    assert CONFIG["api_key"] not in str(error.value)


def test_sessions_and_responses_are_closed(api):
    with (
        patch.object(requests.Session, "close") as session_close,
        patch.object(requests.Response, "close") as response_close,
    ):
        with shuffle.Client(CONFIG) as client:
            client.datastore("example.org", "misp")
    assert session_close.call_count == response_close.call_count == 1


def test_path_injection_cannot_send_credentials_elsewhere(api):
    with pytest.raises(shuffle.ShuffleError):
        with shuffle.Client(CONFIG) as client:
            client.execute("https://unexpected.example/collect", "{}")
    assert not api.calls
