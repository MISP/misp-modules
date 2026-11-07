import base64
import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.parse import urlsplit

import pytest
import requests
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.expansion import cisco_umbrella as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
KEY, SECRET, TOKEN = "synthetic-key", "synthetic-secret", "synthetic-token"
CATEGORY = {"status": -1, "security_categories": ["Malware"], "content_categories": ["Business Services"]}
RISK = {"risk_score": 91.5, "indicators": [{"indicator": "Lexical", "normalized_score": 52, "score": 0.525}]}


def query(value="example.org", kind="domain", **config):
    return {
        "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "Original context"},
        "config": {"api_key": KEY, "api_secret": SECRET, **config},
    }


def report(result):
    assert "error" not in result, result
    obj = result["results"]["Object"][0]
    assert obj["name"] == "annotation"
    assert obj["ObjectReference"][0]["referenced_uuid"] == UUID
    assert obj["ObjectReference"][0]["relationship_type"] == "describes"
    attr = obj["Attribute"][0]
    assert attr["to_ids"] is False and attr["disable_correlation"] is True
    event = MISPEvent()
    event.from_dict(info="Synthetic Umbrella lookup", **result["results"])
    assert event.objects[0].name == "annotation"
    return json.loads(attr["value"])


class FakeAPI:
    """Keep requests' real preparation/authentication; replace only network I/O."""

    def __init__(self):
        self.calls = []
        self.replies = {}
        self.lock = threading.Lock()

    def send(self, adapter, request, **kwargs):
        path = urlsplit(request.url).path
        with self.lock:
            self.calls.append((request, kwargs))
            reply = self.replies.get(path)
            if isinstance(reply, list):
                reply = reply.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if reply is None:
            if path == "/auth/v2/token":
                reply = {"token_type": "bearer", "access_token": TOKEN, "expires_in": 3600}
            elif path.startswith("/investigate/v2/domains/categorization/"):
                reply = {path.rsplit("/", 1)[1]: CATEGORY}
            elif path.startswith("/investigate/v2/domains/risk-score/"):
                reply = RISK
            else:
                raise AssertionError("Unexpected endpoint: " + request.url)
        status, data = reply if isinstance(reply, tuple) else (200, reply)
        response = requests.Response()
        response.request, response.url, response.status_code = request, request.url, status
        response._content = data if isinstance(data, bytes) else json.dumps(data).encode()
        response.headers["Content-Type"] = "application/json"
        if 300 <= status < 400:
            response.headers["Location"] = "https://unexpected.example/collect"
        return response


@pytest.fixture(autouse=True)
def clear_tokens():
    module._TOKENS.clear()
    yield
    module._TOKENS.clear()


@pytest.fixture
def api():
    fake = FakeAPI()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


@pytest.mark.parametrize(
    "kind,value,domain",
    [
        ("domain", "EXAMPLE.org.", "example.org"),
        ("hostname", "BÜCHER.test", "xn--bcher-kva.test"),
        ("domain", "faß.de", "xn--fa-hia.de"),
        ("hostname", "FAẞ.DE.", "xn--fa-hia.de"),
        ("domain", "xn--fa-hia.de", "xn--fa-hia.de"),
        ("domain", "fass.de", "fass.de"),
        ("domain", "οδός.gr", "xn--pxavk3b.gr"),
        ("hostname", "ｅｘａｍｐｌｅ。org", "example.org"),
        ("domain", "EXAMPLE.org。", "example.org"),
    ],
)
def test_documented_oauth_and_domain_endpoints(api, kind, value, domain):
    request = query(value, kind, timeout="7")
    original = copy.deepcopy(request)
    result = module.handler(json.dumps(request))
    parsed = report(result)
    assert result["results"]["Attribute"] == [original["attribute"]]
    assert request == original
    assert parsed["domain"] == domain and parsed["status"] == "complete" and parsed["errors"] == {}
    assert parsed["categorization"] == {**CATEGORY, "status_label": "malicious"}
    assert parsed["risk"] == RISK and parsed["retrieved_at"].endswith("+00:00")
    assert len(api.calls) == 3
    auth, categories, risk = [call[0] for call in api.calls]
    assert auth.method == "POST" and auth.url == "https://api.umbrella.com/auth/v2/token"
    assert auth.headers["Authorization"] == "Basic " + base64.b64encode(f"{KEY}:{SECRET}".encode()).decode()
    assert auth.body == "grant_type=client_credentials"
    assert auth.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert categories.method == risk.method == "GET"
    assert categories.url == f"https://api.umbrella.com/investigate/v2/domains/categorization/{domain}?showLabels="
    assert risk.url == f"https://api.umbrella.com/investigate/v2/domains/risk-score/{domain}"
    assert categories.headers["Authorization"] == risk.headers["Authorization"] == "Bearer " + TOKEN
    assert all(kwargs["timeout"] == 7 and kwargs["verify"] for _, kwargs in api.calls)
    assert all(KEY not in call.url and SECRET not in call.url for call, _ in api.calls)


@pytest.mark.parametrize("status,label", [(-1, "malicious"), (0, "unclassified"), (1, "benign")])
def test_flat_schema_and_status_zero_are_preserved(api, status, label):
    api.replies["/investigate/v2/domains/categorization/example.org"] = {**CATEGORY, "status": status}
    api.replies["/investigate/v2/domains/risk-score/example.org"] = {"risk_score": 0}
    data = report(module.handler(json.dumps(query())))
    assert data["categorization"]["status_label"] == label
    assert data["categorization"]["status"] == status and data["risk"]["risk_score"] == 0


@pytest.mark.parametrize("endpoint", ["categorization", "risk-score"])
@pytest.mark.parametrize("status", [302, 400, 401, 403, 404, 429, 500])
def test_one_lookup_failure_keeps_other_result_and_identifies_failure(api, endpoint, status):
    api.replies[f"/investigate/v2/domains/{endpoint}/example.org"] = (status, {"message": SECRET})
    result = module.handler(json.dumps(query()))
    data = report(result)
    name = "risk" if endpoint == "risk-score" else endpoint
    assert data["status"] == "partial" and data["errors"] == {name: f"HTTP {status}"}
    assert name not in data and result["warnings"]
    assert len(api.calls) == 3  # No redirects or implicit retries.
    assert SECRET not in json.dumps(result) and TOKEN not in json.dumps(result)


def test_total_failure_is_error_instead_of_benign_result(api):
    for endpoint in ("categorization", "risk-score"):
        api.replies[f"/investigate/v2/domains/{endpoint}/example.org"] = (429, {"message": TOKEN})
    result = module.handler(json.dumps(query()))
    assert "error" in result and "results" not in result
    assert "429" in result["error"] and TOKEN not in result["error"]


@pytest.mark.parametrize(
    "reply",
    [
        (401, {"error": SECRET}),
        (302, {}),
        b"invalid JSON",
        {},
        {"access_token": ""},
        {"access_token": "bad\r\nheader", "token_type": "bearer", "expires_in": 3600},
        {"access_token": TOKEN, "token_type": "basic", "expires_in": 3600},
        *(
            {"access_token": TOKEN, "token_type": "bearer", "expires_in": value}
            for value in [None, 0, -1, True, "3600"]
        ),
        requests.Timeout(SECRET),
    ],
)
def test_auth_failures_stop_before_investigate_and_do_not_leak_secrets(api, reply):
    api.replies["/auth/v2/token"] = reply
    result = module.handler(json.dumps(query()))
    assert "error" in result and "results" not in result
    assert len(api.calls) == 1 and not module._TOKENS
    assert all(value not in json.dumps(result) for value in [KEY, SECRET, TOKEN])


@pytest.mark.parametrize(
    "reply",
    [
        b"<html>bad gateway</html>",
        [],
        {"error": SECRET},
        {"wrong.example": CATEGORY},
        {"status": True},
        {**CATEGORY, "status": 3},
        {**CATEGORY, "security_categories": None},
        {**CATEGORY, "content_categories": [None]},
        {**CATEGORY, "security_categories": ["x" * 257]},
        requests.ConnectionError(TOKEN),
    ],
)
def test_malformed_categorization_is_not_a_verdict(api, reply):
    # An explicit tuple distinguishes an array body from a sequence of replies.
    api.replies["/investigate/v2/domains/categorization/example.org"] = (
        reply if isinstance(reply, Exception) else (200, reply)
    )
    data = report(module.handler(json.dumps(query())))
    assert data["status"] == "partial" and "categorization" not in data
    assert "categorization" in data["errors"]
    assert SECRET not in json.dumps(data) and TOKEN not in json.dumps(data)


@pytest.mark.parametrize(
    "reply",
    [
        {},
        {"risk_score": True},
        {"risk_score": None},
        {"risk_score": -1},
        {"risk_score": 101},
        {"risk_score": float("nan")},
        {"risk_score": float("inf")},
        {"risk_score": 10**400},
        {**RISK, "indicators": None},
        {**RISK, "indicators": [{}]},
        {**RISK, "indicators": [{"indicator": "Lexical", "normalized_score": 101, "score": 1}]},
        {**RISK, "indicators": [{"indicator": "Lexical", "normalized_score": 1, "score": None}]},
    ],
)
def test_malformed_risk_does_not_become_zero_or_a_complete_report(api, reply):
    api.replies["/investigate/v2/domains/risk-score/example.org"] = reply
    data = report(module.handler(json.dumps(query())))
    assert data["status"] == "partial" and "risk" not in data and "risk" in data["errors"]


def test_only_documented_fields_are_retained(api):
    api.replies["/investigate/v2/domains/categorization/example.org"] = {**CATEGORY, "debug": SECRET}
    api.replies["/investigate/v2/domains/risk-score/example.org"] = {**RISK, "debug": TOKEN}
    assert all(value not in json.dumps(module.handler(json.dumps(query()))) for value in (SECRET, TOKEN))


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost",
        "127.0.0.1",
        "::1",
        "http://example.org",
        "*.example.org",
        "example.org/path",
        "example.org?x=1",
        "example.org..",
        "bad_.org",
        "x\n.org",
        "-bad.org",
        "bad-.org",
        "a" * 64 + ".org",
        None,
        [],
        "\ud800.org",
        "ab\u200ccd.example",
        "ab\u200dcd.example",
        "xn--.org",
    ],
)
def test_invalid_names_never_make_requests(api, value):
    assert "error" in module.handler(json.dumps(query(value)))
    assert not api.calls


@pytest.mark.parametrize(
    "config",
    [
        {"api_key": ""},
        {"api_secret": None},
        {"api_key": []},
        {"api_secret": "bad\n"},
        {"api_key": "key:extra"},
        {"timeout": 0},
        {"timeout": True},
        {"timeout": "nan"},
        {"timeout": 121},
        {"timeout": 1.5},
    ],
)
def test_invalid_settings_never_make_requests(api, config):
    assert "error" in module.handler(json.dumps(query(**config)))
    assert not api.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}', '{"config": []}'])
def test_invalid_envelope(api, raw):
    assert "error" in module.handler(raw) and not api.calls


@pytest.mark.parametrize("field,value", [("type", "ip-src"), ("uuid", "bad"), ("uuid", None), ("uuid", 12)])
def test_invalid_attribute(api, field, value):
    request = query()
    request["attribute"][field] = value
    assert "error" in module.handler(json.dumps(request)) and not api.calls


def test_cache_reuses_tokens_until_nearly_expired_and_isolates_credentials(api):
    api.replies["/auth/v2/token"] = [
        {"token_type": "bearer", "access_token": token, "expires_in": 3600}
        for token in (TOKEN, "other-token", "refreshed-token")
    ]
    with patch.object(module.time, "monotonic", return_value=100):
        report(module.handler(json.dumps(query())))
        report(module.handler(json.dumps(query())))
        report(module.handler(json.dumps(query(api_secret="other-secret"))))
    assert sum(call.url.endswith("/token") for call, _ in api.calls) == 2
    assert [call.headers["Authorization"] for call, _ in api.calls if call.method == "GET"] == [
        "Bearer " + token for token in (TOKEN, TOKEN, TOKEN, TOKEN, "other-token", "other-token")
    ]
    assert len(module._TOKENS) == 2
    assert all(isinstance(identity, bytes) and len(identity) == 32 for identity in module._TOKENS)
    with patch.object(module.time, "monotonic", return_value=3640):
        report(module.handler(json.dumps(query())))
    assert sum(call.url.endswith("/token") for call, _ in api.calls) == 3


def test_concurrent_hover_lookups_share_one_token(api):
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(module.handler, [json.dumps(query())] * 4))
    assert all(report(result)["status"] == "complete" for result in results)
    assert sum(call.url.endswith("/token") for call, _ in api.calls) == 1


def test_rejected_cached_token_is_evicted_without_retrying(api):
    report(module.handler(json.dumps(query())))
    api.replies["/investigate/v2/domains/risk-score/example.org"] = (400, {"error": "invalid_request"})
    assert report(module.handler(json.dumps(query())))["status"] == "partial"
    assert not module._TOKENS and len(api.calls) == 5
    api.replies.clear()
    report(module.handler(json.dumps(query())))
    assert sum(call.url.endswith("/token") for call, _ in api.calls) == 2


def test_cache_is_bounded(api):
    for index in range(33):
        report(module.handler(json.dumps(query(api_key=f"key-{index}"))))
    assert len(module._TOKENS) == 32


def test_explicit_bearer_auth_overrides_netrc_while_preserving_proxy_settings(api):
    expected_proxies = requests.utils.get_environ_proxies(module.BASE_URL)
    with patch("requests.sessions.get_netrc_auth", return_value=("wrong-user", "wrong-password")):
        report(module.handler(json.dumps(query())))
    assert api.calls[1][0].headers["Authorization"] == "Bearer " + TOKEN
    assert dict(api.calls[1][1]["proxies"]) == expected_proxies


def test_sessions_and_responses_are_closed(api):
    real_close = requests.Session.close
    closed = []

    def close(session):
        closed.append(session)
        real_close(session)

    with patch.object(requests.Session, "close", close), patch.object(requests.Response, "close") as close_response:
        report(module.handler(json.dumps(query())))
    assert len(closed) == 1 and close_response.call_count == 3


def test_discovery_does_not_change_metadata():
    assert module.handler(False) is False
    assert module.introspection() == {"input": ["domain", "hostname"], "format": "misp_standard"}
    first = module.version()
    first["name"] = "changed"
    assert module.version()["name"] == "Cisco Umbrella Investigate"
    assert module.version()["config"] == ["api_key", "api_secret", "timeout"]


class TestUmbrellaHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"cisco_umbrella": module, "type:cisco_umbrella": "expansion"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        fake = FakeAPI()
        descriptor = json.loads(self.fetch("/modules").body)[0]
        assert descriptor["name"] == "cisco_umbrella"
        assert descriptor["mispattributes"]["input"] == ["domain", "hostname"]
        with patch.object(
            requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
        ):
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": "cisco_umbrella", **query()}),
            )
        assert response.code == 200 and report(json.loads(response.body))["status"] == "complete"
