import hashlib
import json
from unittest.mock import patch

import pytest
import requests

from misp_modules.lib import cortex_xdr as shared

CONFIG = {"url": "https://api-tenant.example", "api_key": "synthetic-key", "api_key_id": "17", "auth_type": "advanced"}
DIGEST = "a" * 64


class FakeAPI:
    """Real requests preparation, synthetic Cortex XDR responses."""

    def __init__(self, rows=None):
        self.rows = rows
        self.calls = []
        self.replies = {}

    def send(self, adapter, request, **kwargs):
        self.calls.append((request, kwargs))
        operation = request.url.rsplit("/", 1)[-1]
        if operation not in ("get", "insert_jsons"):
            raise AssertionError("Unexpected endpoint")
        reply = self.replies.get(operation)
        if isinstance(reply, list):
            reply = reply.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if reply is None:
            if operation == "get":
                filters = json.loads(request.body)["request_data"]["filters"]
                rows = (
                    self.rows
                    if self.rows is not None
                    else [
                        {
                            "rule_id": 99,
                            "indicator": filters[0]["value"],
                            "type": filters[1]["value"],
                            "severity": "SEV_030_MEDIUM",
                            "expiration_date": 0,
                        }
                    ]
                )
                reply = {"reply": {"objects": rows, "objects_count": len(rows)}}
            else:
                reply = {"reply": {"success": True, "validation_errors": []}}
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


@pytest.mark.parametrize("mode", ["standard", "advanced"])
def test_documented_authentication_and_lookup_filters(api, mode):
    with (
        patch.object(shared.secrets, "token_hex", return_value="b" * 64),
        patch.object(shared.time, "time", return_value=1700000000.125),
    ):
        with shared.Client({**CONFIG, "auth_type": mode, "timeout": "7"}) as client:
            rows, count, truncated = client.lookup("hash", DIGEST, limit=3)
    request, options = api.calls[0]
    assert request.url == CONFIG["url"] + "/public_api/v1/indicators/get"
    assert request.headers["x-xdr-auth-id"] == "17"
    if mode == "standard":
        assert request.headers["Authorization"] == CONFIG["api_key"]
        assert "x-xdr-nonce" not in request.headers
    else:
        assert request.headers["x-xdr-nonce"] == "b" * 64
        assert request.headers["x-xdr-timestamp"] == "1700000000125"
        assert (
            request.headers["Authorization"]
            == hashlib.sha256((CONFIG["api_key"] + "b" * 64 + "1700000000125").encode()).hexdigest()
        )
    assert json.loads(request.body) == {
        "request_data": {
            "extended_view": True,
            "search_from": 0,
            "search_to": 2,
            "filters": [
                {"field": "indicator", "operator": "EQ", "value": DIGEST},
                {"field": "type", "operator": "EQ", "value": "hash"},
            ],
        }
    }
    assert count == 1 and len(rows) == 1 and truncated is False
    assert options["timeout"] == 7 and options["stream"] and options["verify"]
    assert CONFIG["api_key"] not in request.url


def test_advanced_auth_is_fresh_per_request_and_not_replaced_by_netrc(api):
    with patch("requests.sessions.get_netrc_auth", return_value=("wrong", "wrong")):
        with shared.Client(CONFIG) as client:
            client.lookup("hash", DIGEST)
            client.lookup("hash", DIGEST)
    first, second = [call[0] for call in api.calls]
    assert first.headers["x-xdr-nonce"] != second.headers["x-xdr-nonce"]
    assert first.headers["Authorization"] != second.headers["Authorization"]
    assert dict(api.calls[0][1]["proxies"]) == requests.utils.get_environ_proxies(CONFIG["url"])


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("md5", "A" * 32, ("hash", "a" * 32)),
        ("sha256", "A" * 64, ("hash", DIGEST)),
        ("domain", "faß.de", ("domain_name", "xn--fa-hia.de")),
        ("hostname", "BÜCHER.test.", ("domain_name", "xn--bcher-kva.test")),
        ("domain", "fass.de", ("domain_name", "fass.de")),
        ("ip-src", "192.0.2.1", ("ip", "192.0.2.1")),
        ("ip-dst", "2001:0DB8::1", ("ip", "2001:db8::1")),
    ],
)
def test_observable_normalization(kind, value, expected):
    assert shared.indicator(kind, value) == expected


@pytest.mark.parametrize(
    "kind,value",
    [
        ("sha1", "a" * 40),
        ("md5", "bad"),
        ("sha256", "g" * 64),
        ("domain", "127.0.0.1"),
        ("domain", "http://example.org"),
        ("domain", "*.example.org"),
        ("domain", "ab\u200dcd.example"),
        ("domain", "localhost"),
        ("ip-dst", "192.0.2.0/24"),
        ("ip-dst", "192.0.2.1:80"),
        ("ip-src", "fe80::1%eth0"),
        ("url", "https://example.org"),
        ("domain", None),
    ],
)
def test_invalid_observables_are_not_broadened(kind, value):
    with pytest.raises(ValueError):
        shared.indicator(kind, value)


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
        {"api_key_id": "bad"},
        {"api_key_id": 17},
        {"auth_type": "unknown"},
        {"timeout": 0},
    ],
)
def test_invalid_connections_do_not_make_requests(api, config):
    with pytest.raises(ValueError):
        with shared.Client({**CONFIG, **config}) as client:
            client.lookup("hash", DIGEST)
    assert not api.calls


@pytest.mark.parametrize("status", [302, 400, 401, 402, 403, 429, 500])
def test_http_errors_do_not_redirect_retry_or_echo_credentials(api, status):
    api.replies["get"] = (status, {"err_msg": CONFIG["api_key"]})
    with pytest.raises(shared.XdrError) as error:
        with shared.Client(CONFIG) as client:
            client.lookup("hash", DIGEST)
    assert str(status) in str(error.value) and CONFIG["api_key"] not in str(error.value)
    assert len(api.calls) == 1


@pytest.mark.parametrize(
    "body",
    [
        b"bad JSON",
        (200, []),
        {"err_code": 403},
        {"reply": {"err_code": 500}},
        {"reply": True},
        {"reply": {"objects": []}},
        {"reply": {"objects": [], "objects_count": 1}},
        {"objects": [], "objects_count": False},
        {"objects": [None], "objects_count": 1},
        {"objects": [{"rule_id": 1, "type": "hash", "indicator": "b" * 64}], "objects_count": 1},
        {"objects": [{"rule_id": True, "type": "hash", "indicator": DIGEST}], "objects_count": 1},
        requests.Timeout("synthetic-key"),
    ],
)
def test_errors_and_incomplete_or_mismatched_records_fail_closed(api, body):
    api.replies["get"] = body
    with pytest.raises(shared.XdrError) as error:
        with shared.Client(CONFIG) as client:
            client.lookup("hash", DIGEST)
    assert CONFIG["api_key"] not in str(error.value)


def test_flat_response_and_explicit_empty_lookup(api):
    api.replies["get"] = {"objects": [], "objects_count": 0, "objects_type": "ioc"}
    with shared.Client(CONFIG) as client:
        assert client.lookup("hash", DIGEST) == ([], 0, False)


def test_limit_reports_incomplete_results(api):
    api.replies["get"] = {
        "reply": {"objects": [{"rule_id": 1, "type": "hash", "indicator": DIGEST}], "objects_count": 2}
    }
    with shared.Client(CONFIG) as client:
        assert client.lookup("hash", DIGEST, 1)[2] is True


def test_response_size_and_resource_cleanup(api):
    api.replies["get"] = b" " * (2 * 1024 * 1024 + 1)
    with (
        patch.object(requests.Session, "close") as close_session,
        patch.object(requests.Response, "close") as close_response,
    ):
        with pytest.raises(shared.XdrError):
            with shared.Client(CONFIG) as client:
                client.lookup("hash", DIGEST)
    assert close_session.call_count == close_response.call_count == 1


@pytest.mark.parametrize("expiry", [-1, 0, 1900000000000])
def test_native_expiration_values_preserve_non_expiring_sentinel(expiry):
    row = {"rule_id": 1, "type": "hash", "indicator": DIGEST, "expiration_date": expiry}
    assert shared.metadata(row)["expiration_date"] == expiry


@pytest.mark.parametrize("expiry", [-2, -100, True, "-1", 1.5])
def test_invalid_expiry_values_are_rejected(expiry):
    with pytest.raises(shared.XdrError):
        shared.metadata({"rule_id": 1, "type": "hash", "indicator": DIGEST, "expiration_date": expiry})
