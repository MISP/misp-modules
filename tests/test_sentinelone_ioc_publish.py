import copy
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.action_mod import sentinelone_ioc_publish as publish

SCOPE_ID = "225494730938493804"


def attribute(kind="domain", value="example.org", **metadata):
    return {"type": kind, "value": value, "to_ids": True, "uuid": "attribute-1", **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"uuid": "event-1", "Attribute": attributes or [], "Object": objects or [], **metadata}


def run(data=None, **params):
    return publish.handler(
        json.dumps(
            {
                "data": event([attribute()]) if data is None else data,
                "params": {"scope": "account", "scope_id": SCOPE_ID, **params},
            }
        )
    )


def response(records=None, status=200, **body):
    records = [] if records is None else records
    result = MagicMock(spec=requests.Response)
    result.status_code = status
    result.json.return_value = {
        "data": records,
        "errors": None,
        "pagination": {"totalItems": len(records), "nextCursor": None},
        **body,
    }
    return result


def existing(**metadata):
    item = run(dry_run=True)["data"]["items"][0]["payload"]["data"][0]
    return {**item, "uuid": "ioc-1", "scope": "account", "scopeId": SCOPE_ID, **metadata}


@pytest.fixture
def client(monkeypatch):
    session = MagicMock(spec=requests.Session)
    session.headers = {}

    def request(method, endpoint, **kwargs):
        if method == "GET":
            return response()
        body = kwargs["json"]
        scope = "account" if "accountIds" in body["filter"] else "site"
        return response([{**body["data"][0], "uuid": "ioc-1", "scope": scope, "scopeId": SCOPE_ID}])

    session.request.side_effect = request
    constructor = MagicMock(return_value=session)
    monkeypatch.setattr(publish.requests, "Session", constructor)
    monkeypatch.setenv("SENTINELONE_URL", "https://console.example")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "test-token")
    session.constructor = constructor
    return session


@pytest.mark.parametrize("scope,key", [("account", "accountIds"), ("site", "siteIds")])
def test_publish_uses_scoped_v21_contract_and_checked_acknowledgement(client, scope, key):
    before = datetime.now(timezone.utc)
    result = run(scope=scope)
    assert result["data"]["created"] == 1 and result["data"]["success"] is True
    assert result["result_key"] == "sentinelone_ioc_publish"
    assert client.headers["Authorization"] == "ApiToken test-token"
    lookup, create = client.request.call_args_list
    assert lookup.args == ("GET", "https://console.example" + publish.API_PATH)
    assert lookup.kwargs["params"][key] == SCOPE_ID
    assert lookup.kwargs["params"]["tenant"] == "false"
    assert create.args[0] == "POST"
    assert create.kwargs["allow_redirects"] is False and create.kwargs["verify"] is True
    assert create.kwargs["timeout"] == 15
    body = create.kwargs["json"]
    assert body["filter"] == {key: [SCOPE_ID], "tenant": False}
    item = body["data"][0]
    assert item["type"] == "DNS" and item["method"] == "EQUALS"
    assert item["severity"] == 4 and item["externalId"] == lookup.kwargs["params"]["externalId"]
    expiry = datetime.fromisoformat(item["validUntil"].replace("Z", "+00:00"))
    assert before + timedelta(days=14, seconds=-1) <= expiry <= datetime.now(timezone.utc) + timedelta(days=14)
    client.close.assert_called_once()


@pytest.mark.parametrize("scope_id", [SCOPE_ID, [SCOPE_ID]])
def test_existing_owned_record_is_reported_without_mutation(client, scope_id):
    client.request.side_effect = lambda *args, **kwargs: response([existing(scopeId=scope_id)])
    result = run()
    assert result["data"]["existing"] == 1 and result["data"]["created"] == 0
    assert client.request.call_count == 1 and client.request.call_args.args[0] == "GET"


@pytest.mark.parametrize(
    "metadata",
    [
        {"source": "foreign"},
        {"externalId": "foreign"},
        {"type": "IPV4"},
        {"value": "other.example"},
        {"method": "CONTAINS"},
        {"scope": "global"},
        {"scopeId": "225494730938493805"},
        {"scopeId": [SCOPE_ID, "225494730938493805"]},
        {"uuid": ""},
        {"validUntil": "2020-01-01T00:00:00Z"},
        {"validUntil": None},
        {"validUntil": "not-a-date"},
    ],
)
def test_foreign_mismatched_or_expired_records_are_not_changed(client, metadata):
    client.request.side_effect = lambda *args, **kwargs: response([existing(**metadata)])
    result = run()
    assert result["data"]["failed"] == 1 and "error" in result
    assert client.request.call_count == 1
    client.close.assert_called_once()


@pytest.mark.parametrize(
    "body",
    [
        response([{}], pagination={"totalItems": 2}),
        response([], pagination={"totalItems": 1}),
        response([], pagination={"totalItems": 0, "nextCursor": "more"}),
        response([], pagination={"totalItems": False}),
        response([], pagination=None),
        response([{}, {}]),
    ],
)
def test_lookup_must_be_complete_and_unambiguous_before_writing(client, body):
    client.request.side_effect = None
    client.request.return_value = body
    assert run()["data"]["failed"] == 1
    assert client.request.call_count == 1


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("domain", "EXAMPLE.org.", [("DNS", "example.org")]),
        ("hostname", "bücher.example", [("DNS", "xn--bcher-kva.example")]),
        ("url", "https://example.org:8443/a?b=c", [("URL", "https://example.org:8443/a?b=c")]),
        ("md5", "A" * 32, [("MD5", "a" * 32)]),
        ("sha1", "A" * 40, [("SHA1", "a" * 40)]),
        ("sha256", "A" * 64, [("SHA256", "a" * 64)]),
        ("ip-src", "192.0.2.1", [("IPV4", "192.0.2.1")]),
        ("ip-dst", "2001:0DB8:0000::1", [("IPV6", "2001:db8::1")]),
        ("domain|ip", "example.org|192.0.2.1", [("DNS", "example.org"), ("IPV4", "192.0.2.1")]),
        ("filename|md5", "a|b.exe|" + "a" * 32, [("MD5", "a" * 32)]),
        ("filename|sha1", "a.exe|" + "a" * 40, [("SHA1", "a" * 40)]),
        ("filename|sha256", "a.exe|" + "a" * 64, [("SHA256", "a" * 64)]),
        ("malware-sample", "a.exe|" + "a" * 32, [("MD5", "a" * 32)]),
    ],
)
def test_supported_types_are_normalized(client, kind, value, expected):
    result = run(event([attribute(kind, value)]))
    assert [(item["type"], item["value"]) for item in result["data"]["items"]] == expected
    assert result["data"]["created"] == len(expected)


def test_deduplication_provenance_and_legacy_object_shapes(client):
    obj = {"uuid": "object-1", "name": "domain-ip", "Attribute": [attribute("ip-dst", "192.0.2.1")]}
    data = [
        {"Event": event([attribute(), attribute(uuid="attribute-2")], [obj])},
        {"Event": {"uuid": "event-2"}, "Attribute": [attribute()]},
    ]
    original = copy.deepcopy(data)
    result = run(data)
    assert result["data"]["created"] == 2
    assert len(result["data"]["items"][0]["sources"]) == 3
    assert result["data"]["items"][1]["sources"][0]["object"] == "object-1"
    assert data == original


def test_external_ids_are_stable_for_observable_and_different_across_scope_and_source():
    first = run(dry_run=True)["data"]["items"][0]["externalId"]
    assert run(event([attribute(uuid="different")]), dry_run=True)["data"]["items"][0]["externalId"] == first
    assert run(dry_run=True, scope="site")["data"]["items"][0]["externalId"] != first
    assert run(dry_run=True, source="other")["data"]["items"][0]["externalId"] != first


@pytest.mark.parametrize(
    "template,relation,value", [("file", "sha1", "a" * 40), ("domain-ip", "domain", "example.org")]
)
def test_existing_misp_object_templates_suffice(client, template, relation, value):
    obj = MISPObject(template, strict=True)
    obj.add_attribute(relation, value=value, to_ids=True)
    obj._validate()
    result = run(event(objects=[json.loads(obj.to_json())]))
    assert result["data"]["created"] == 1
    assert result["data"]["items"][0]["sources"][0]["object"] == obj.uuid


def test_dry_run_has_no_credentials_or_network(client, monkeypatch):
    monkeypatch.delenv("SENTINELONE_URL")
    monkeypatch.delenv("SENTINELONE_API_TOKEN")
    result = run(dry_run="true")
    assert result["data"]["planned"] == 1
    client.constructor.assert_not_called()
    assert "Authorization" not in json.dumps(result)


def test_deleted_context_and_unsupported_port_constraints_are_excluded(client):
    data = [
        event(
            [attribute(to_ids="false"), attribute(deleted="1"), attribute("ip-dst|port", "192.0.2.1|443")],
            [{"deleted": True, "Attribute": [attribute()]}],
        ),
        event([attribute()], deleted=True),
    ]
    result = run(data)
    assert result["data"]["skipped"] == {"deleted or non-IDS": 2, "unsupported": 1}
    client.constructor.assert_not_called()


@pytest.mark.parametrize(
    "kind,value",
    [
        ("domain", "bad'name.example"),
        ("domain", "a..example"),
        ("ip-src", "192.0.2.0/24"),
        ("ip-dst", "fe80::1%eth0"),
        ("domain|ip", "example.org|not-ip"),
        ("md5", "bad"),
        ("sha1", "g" * 40),
        ("url", "example.org"),
        ("url", "https://example.org:bad/"),
        ("domain", None),
        ("domain", ""),
        *[(kind, value) for kind, value in publish.EMPTY_FILE_HASHES.items()],
    ],
)
def test_malformed_or_provider_rejected_values_are_skipped_without_network(client, kind, value):
    assert run(event([attribute(kind, value)]))["data"]["skipped"] == {"malformed": 1}
    client.constructor.assert_not_called()


@pytest.mark.parametrize(
    "params",
    [
        {"scope": "global"},
        {"scope": None},
        {"scope_id": "123"},
        {"scope_id": int(SCOPE_ID)},
        {"scope_id": SCOPE_ID + "," + SCOPE_ID},
        {"source": "bad'source"},
        {"source": False},
        {"severity": 8},
        {"severity": True},
        {"expiration_days": 181},
        {"expiration_days": 0},
        {"expiration_days": 1.5},
        {"dry_run": "maybe"},
    ],
)
def test_settings_validation_precedes_network(client, params):
    assert "error" in run(**params)
    client.constructor.assert_not_called()


def test_expiry_respects_provider_type_limits_before_network(client):
    assert "error" in run(event([attribute("ip-dst", "192.0.2.1")]), expiration_days=31)
    client.constructor.assert_not_called()
    assert run(event([attribute("ip-dst", "192.0.2.1")]), expiration_days=30)["data"]["created"] == 1
    assert run(expiration_days=180)["data"]["created"] == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://console.example",
        "https://:password@console.example",
        "https://@console.example",
        "https://console.example/path",
        "https://console.example/?q=x",
        "https://console.example/#x",
        "https://console.example:bad",
        "",
    ],
)
def test_bad_console_origins_do_not_send_tokens_or_echo_credentials(client, monkeypatch, url):
    monkeypatch.setenv("SENTINELONE_URL", url)
    result = run()
    assert "error" in result and "password" not in json.dumps(result)
    client.constructor.assert_not_called()


def test_missing_credentials_and_malformed_requests_fail_without_network(client, monkeypatch):
    monkeypatch.delenv("SENTINELONE_API_TOKEN")
    assert "error" in run()
    for payload in (
        [],
        {"params": []},
        {"data": None},
        {"data": {"Event": "bad"}},
        {"data": event([attribute()]), "filteredItems": []},
    ):
        base = {"params": {"scope": "account", "scope_id": SCOPE_ID}}
        assert "error" in publish.handler(json.dumps({**base, **payload} if isinstance(payload, dict) else payload))
    assert publish.handler() is False
    assert "error" in publish.handler("invalid JSON")
    client.constructor.assert_not_called()


def test_limit_is_checked_before_network(client):
    assert "error" in run(event([attribute(value=f"host{index}.example") for index in range(101)]))
    client.constructor.assert_not_called()


@pytest.mark.parametrize("status", [301, 302, 401, 403, 429, 500])
def test_http_errors_or_redirects_never_write_or_expose_provider_errors(client, status):
    client.request.side_effect = None
    client.request.return_value = response(status=status, errors=[{"detail": "test-token"}])
    result = run()
    assert result["data"]["failed"] == 1 and "error" in result
    assert "test-token" not in json.dumps(result)
    assert client.request.call_count == 1
    client.close.assert_called_once()


@pytest.mark.parametrize(
    "bad", [response(errors=[{}]), response(warnings=[{}]), response(records={}), response(pagination=None)]
)
def test_malformed_success_responses_are_not_treated_as_empty_lookups(client, bad):
    client.request.side_effect = None
    client.request.return_value = bad
    assert run()["data"]["failed"] == 1
    assert client.request.call_count == 1


def test_unacknowledged_write_reports_unknown_outcome_without_retry(client):
    client.request.side_effect = [response(), response([{}])]
    result = run()
    assert result["data"]["failed"] == 1 and result["data"]["created"] == 0
    assert "unknown" in result["data"]["items"][0]["error"]
    assert client.request.call_count == 2


def test_partial_success_and_timeout_preserve_outcomes_without_echoing_secrets(client):
    good = {**existing(), "uuid": "created-1"}
    client.request.side_effect = [response(), response([good]), requests.Timeout("test-token")]
    result = run(event([attribute(), attribute(value="other.example")]))
    assert result["data"]["created"] == 1 and result["data"]["failed"] == 1
    assert result["data"]["success"] is False and "error" in result
    assert "test-token" not in json.dumps(result)


def test_time_budget_is_rechecked_after_lookup(client, monkeypatch):
    values = iter([0, 0, publish.DEADLINE_SECONDS + 1])
    monkeypatch.setattr(publish.time, "monotonic", lambda: next(values))
    assert run()["data"]["failed"] == 1
    assert client.request.call_count == 1


def test_real_requests_transport_prepares_expected_wire_contract(monkeypatch):
    calls = []

    def send(self, request, **kwargs):
        calls.append((request, kwargs))
        if request.method == "GET":
            data = {"data": [], "pagination": {"totalItems": 0, "nextCursor": None}}
            assert parse_qs(urlsplit(request.url).query)["siteIds"] == [SCOPE_ID]
        else:
            payload = json.loads(request.body)
            assert payload["filter"] == {"siteIds": [SCOPE_ID], "tenant": False}
            data = {"data": [{**payload["data"][0], "uuid": "ioc-1", "scope": "site", "scopeId": SCOPE_ID}]}
        result = requests.Response()
        result.status_code = 200
        result.headers["Content-Type"] = "application/json"
        result._content = json.dumps(data).encode()
        result.request = request
        result.url = request.url
        return result

    monkeypatch.setenv("SENTINELONE_URL", "https://console.example")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "test-token")
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    assert run(scope="site")["data"]["created"] == 1
    assert [request.method for request, _ in calls] == ["GET", "POST"]
    assert all(request.headers["Authorization"] == "ApiToken test-token" for request, _ in calls)


class TestSentinelOnePublishHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous = service.MODULES_HANDLERS.copy()
        self.cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {"sentinelone_ioc_publish": publish, "type:sentinelone_ioc_publish": "action_mod"}
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_dry_run(self):
        descriptor = json.loads(self.fetch("/modules").body)[0]
        assert descriptor["name"] == "sentinelone_ioc_publish"
        assert descriptor["meta"]["config"]["blocking"] is True
        result = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(
                {
                    "module": "sentinelone_ioc_publish",
                    "data": event([attribute()]),
                    "params": {"scope": "site", "scope_id": SCOPE_ID, "dry_run": True},
                }
            ),
        )
        assert result.code == 200 and json.loads(result.body)["data"]["planned"] == 1
