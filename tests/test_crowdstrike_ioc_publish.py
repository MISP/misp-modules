import copy
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import requests
from falconpy import IOC
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.action_mod import crowdstrike_ioc_publish as publish

GROUP = "a" * 32


def attribute(kind="domain", value="example.org", **metadata):
    return {"type": kind, "value": value, "to_ids": True, "uuid": "attribute-1", **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"uuid": "event-1", "Attribute": attributes or [], "Object": objects or [], **metadata}


def response(resources=None, status=200, **body):
    return {"status_code": status, "body": {"resources": resources or [], "errors": [], **body}}


def run(data=None, **params):
    return publish.handler(
        json.dumps(
            {"data": data if data is not None else event([attribute()]), "params": {"host_groups": GROUP, **params}}
        )
    )


@pytest.fixture
def client(monkeypatch):
    fake = MagicMock(spec=IOC)
    fake.indicator_combined_v1.return_value = response()
    fake.indicator_create_v1.return_value = response([{"id": "falcon-1"}])
    fake.indicator_update_v1.return_value = response([{"id": "falcon-1"}])
    constructor = MagicMock(return_value=fake)
    monkeypatch.setattr(publish, "IOC", constructor)
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "test-client")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "test-secret")
    fake.constructor = constructor
    return fake


def owned(**metadata):
    return {
        "id": "falcon-1",
        "type": "domain",
        "value": "example.org",
        "source": "misp-modules",
        "tags": [publish.OWNER_TAG],
        **metadata,
    }


def test_create_uses_sdk_contract_explicit_scope_and_expiration(client):
    before = datetime.now(timezone.utc)
    result = run()
    assert result["data"]["created"] == 1
    assert result["result_key"] == "crowdstrike_ioc_publish"
    client.constructor.assert_called_once_with(
        client_id="test-client",
        client_secret="test-secret",
        base_url="https://api.crowdstrike.com",
        timeout=15,
        ssl_verify=True,
    )
    client.indicator_combined_v1.assert_called_once_with(
        filter="type:'domain'+value:'example.org'", limit=2, from_parent=False
    )
    kwargs = client.indicator_create_v1.call_args.kwargs
    assert kwargs["ignore_warnings"] is False and kwargs["retrodetects"] is False
    item = kwargs["body"]["indicators"][0]
    assert item["applied_globally"] is False and item["host_groups"] == [GROUP]
    assert item["platforms"] == ["linux", "mac", "windows"]
    assert item["action"] == "detect" and item["severity"] == "MEDIUM"
    assert item["tags"] == [publish.OWNER_TAG]
    expiration = datetime.fromisoformat(item["expiration"].replace("Z", "+00:00"))
    assert before + timedelta(days=30, seconds=-1) <= expiration <= datetime.now(timezone.utc) + timedelta(days=30)
    assert "event-1/attribute-1" in item["description"]


def test_update_requires_ownership_keeps_manual_tags_and_does_not_create(client):
    client.indicator_combined_v1.return_value = response([owned(tags=[publish.OWNER_TAG, "manual-tag"])])
    result = run(expiration_days="7", severity="high", platforms="windows")
    assert result["data"]["updated"] == 1
    client.indicator_create_v1.assert_not_called()
    item = client.indicator_update_v1.call_args.kwargs["body"]["indicators"][0]
    assert item["id"] == "falcon-1" and item["tags"] == ["manual-tag", publish.OWNER_TAG]
    assert "type" not in item and "value" not in item
    assert item["severity"] == "HIGH" and item["platforms"] == ["windows"]


@pytest.mark.parametrize(
    "record",
    [
        owned(source="manual"),
        owned(tags=[]),
        owned(tags="bad"),
        owned(value="unexpected.example"),
        owned(id=""),
        owned(from_parent=True),
    ],
)
def test_foreign_or_unidentified_records_are_never_modified(client, record):
    client.indicator_combined_v1.return_value = response([record])
    result = run()
    assert result["data"]["failed"] == 1 and "error" in result
    client.indicator_update_v1.assert_not_called()
    client.indicator_create_v1.assert_not_called()


@pytest.mark.parametrize(
    "body", [response([owned(), owned(id="other")]), response([owned()], meta={"pagination": {"total": 2}})]
)
def test_ambiguous_lookup_does_not_write(client, body):
    client.indicator_combined_v1.return_value = body
    assert run()["data"]["failed"] == 1
    client.indicator_update_v1.assert_not_called()
    client.indicator_create_v1.assert_not_called()


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("md5", "A" * 32, [("md5", "a" * 32)]),
        ("sha256", "A" * 64, [("sha256", "a" * 64)]),
        ("domain", "EXAMPLE.org.", [("domain", "example.org")]),
        ("hostname", "host.example.org", [("domain", "host.example.org")]),
        ("domain", "bücher.example", [("domain", "xn--bcher-kva.example")]),
        ("ip-src", "192.0.2.1", [("ipv4", "192.0.2.1")]),
        ("ip-dst", "2001:0DB8:0000::1", [("ipv6", "2001:db8::1")]),
        ("domain|ip", "example.org|192.0.2.1", [("domain", "example.org"), ("ipv4", "192.0.2.1")]),
        ("filename|md5", "a|b.exe|" + "a" * 32, [("md5", "a" * 32)]),
        ("filename|sha256", "a.exe|" + "a" * 64, [("sha256", "a" * 64)]),
        ("malware-sample", "a.exe|" + "a" * 32, [("md5", "a" * 32)]),
    ],
)
def test_supported_types_are_normalized_before_publishing(client, kind, value, expected):
    result = run(event([attribute(kind, value)]))
    assert [(item["type"], item["value"]) for item in result["data"]["items"]] == expected
    assert result["data"]["created"] == len(expected)


def test_events_objects_legacy_input_deduplication_and_provenance(client):
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


@pytest.mark.parametrize(
    "template,relation,value", [("file", "sha256", "a" * 64), ("domain-ip", "domain", "example.org")]
)
def test_existing_object_templates_suffice(client, template, relation, value):
    obj = MISPObject(template, strict=True)
    obj.add_attribute(relation, value=value, to_ids=True)
    obj._validate()
    result = run(event(objects=[json.loads(obj.to_json())]))
    assert result["data"]["created"] == 1
    assert result["data"]["items"][0]["sources"][0]["object"] == obj.uuid


def test_dry_run_avoids_credentials_and_network_and_shows_global_scope(client, monkeypatch):
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_ID")
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_SECRET")
    result = run(dry_run="true", host_groups="", apply_globally="true", source="MISP production")
    client.constructor.assert_not_called()
    assert result["data"]["planned"] == 1
    item = result["data"]["items"][0]["payload"]
    assert item["source"] == "MISP production" and item["host_groups"] == [] and item["applied_globally"] is True


@pytest.mark.parametrize("flag", [False, 0, "false", "0", None, ""])
def test_false_flags_do_not_enable_dry_run_or_global_scope(client, flag):
    assert run(dry_run=flag, apply_globally=flag)["data"]["created"] == 1
    assert client.indicator_create_v1.call_args.kwargs["body"]["indicators"][0]["applied_globally"] is False


def test_context_deleted_and_unsupported_attributes_never_publish(client):
    data = [
        event(
            [
                attribute(to_ids="false"),
                attribute(deleted="1"),
                attribute("sha1", "a" * 40),
                attribute("url", "https://example.org"),
                attribute("ip-dst|port", "192.0.2.1|443"),
            ],
            [{"deleted": True, "Attribute": [attribute()]}],
        ),
        event([attribute()], deleted=True),
    ]
    result = run(data)
    assert result["data"]["created"] == 0
    assert result["data"]["skipped"] == {"deleted or non-IDS": 2, "unsupported": 3}
    client.constructor.assert_not_called()


@pytest.mark.parametrize(
    "kind,value",
    [
        ("md5", "bad"),
        ("sha256", "g" * 64),
        ("ip-src", "192.0.2.0/24"),
        ("ip-dst", "fe80::1%eth0"),
        ("domain", "bad'value.example"),
        ("domain", "a+b.example"),
        ("domain", "-bad.example"),
        ("domain|ip", "example.org|not-ip"),
        ("domain", None),
        ("filename|md5", "a.exe"),
        ("domain", ""),
    ],
)
def test_malformed_indicators_are_reported_and_never_sent(client, kind, value):
    assert run(event([attribute(kind, value)]))["data"]["skipped"] == {"malformed": 1}
    client.constructor.assert_not_called()


@pytest.mark.parametrize("kind", ["domain", "hostname", "domain|ip"])
@pytest.mark.parametrize("length", [200, 201, 253])
def test_falcon_domain_length_boundary(client, kind, length):
    # All labels are within DNS's 63-character limit, including beyond Falcon's limit.
    domain = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * (length - 192)])
    assert len(domain) == length
    value = domain + "|192.0.2.1" if kind == "domain|ip" else domain
    result = run(event([attribute(kind, value)]))
    if length > 200:
        assert result["data"]["skipped"] == {"malformed": 1}
        assert result["data"]["created"] == 0
        client.constructor.assert_not_called()
    else:
        assert result["data"]["created"] == (2 if kind == "domain|ip" else 1)


@pytest.mark.parametrize("kind", ["domain", "hostname", "domain|ip"])
def test_falcon_domain_limit_applies_after_idna_encoding(client, kind):
    domain = ".".join(["ü" * 20] * 8)
    assert len(domain) <= 200 < len(domain.encode("idna")) <= 253
    value = domain + "|192.0.2.1" if kind == "domain|ip" else domain
    result = run(event([attribute(kind, value)]))
    assert result["data"]["skipped"] == {"malformed": 1}
    client.constructor.assert_not_called()


def test_overlong_domain_does_not_cause_partial_publication_failure(client):
    domain = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 9])
    result = run(event([attribute(value=domain), attribute()]))
    assert result["data"]["success"] is True
    assert result["data"]["skipped"] == {"malformed": 1}
    assert result["data"]["created"] == 1
    client.indicator_combined_v1.assert_called_once_with(
        filter="type:'domain'+value:'example.org'", limit=2, from_parent=False
    )


def test_prevent_is_only_allowed_for_hashes(client):
    assert "error" in run(action="prevent")
    client.constructor.assert_not_called()
    assert run(event([attribute("sha256", "a" * 64)]), action="prevent")["data"]["created"] == 1


@pytest.mark.parametrize(
    "params",
    [
        {"host_groups": "", "apply_globally": False},
        {"apply_globally": "true"},
        {"region": "https://other.example"},
        {"source": "bad'source"},
        {"action": "allow"},
        {"severity": "unknown"},
        {"platforms": "android"},
        {"platforms": []},
        {"region": []},
        {"source": False},
        {"host_groups": "not-a-group"},
        {"expiration_days": 0},
        {"expiration_days": 366},
        {"expiration_days": True},
        {"expiration_days": 1.5},
        {"dry_run": "maybe"},
    ],
)
def test_invalid_settings_fail_before_network(client, params):
    assert "error" in run(**params)
    client.constructor.assert_not_called()


@pytest.mark.parametrize("data", [None, [1], {"Event": "bad"}, {"Attribute": {}}])
def test_invalid_data_fails_before_network(client, data):
    assert "error" in publish.handler(json.dumps({"params": {"host_groups": GROUP}, "data": data}))
    client.constructor.assert_not_called()


def test_unsupported_workflow_filters_fail_before_network(client):
    assert "error" in publish.handler(json.dumps({"data": event([attribute()]), "filteredItems": []}))
    assert publish.handler() is False
    assert "error" in publish.handler("invalid JSON")
    client.constructor.assert_not_called()


def test_limit_is_enforced_before_network(client):
    assert "error" in run(event([attribute(value=f"host{number}.example") for number in range(101)]))
    client.constructor.assert_not_called()


def test_missing_credentials_do_not_leak_values(client, monkeypatch):
    monkeypatch.delenv("CROWDSTRIKE_CLIENT_SECRET")
    result = run()
    assert "error" in result and "test-client" not in json.dumps(result)
    client.constructor.assert_not_called()


@pytest.mark.parametrize(
    "bad_response",
    [
        None,
        {},
        response(status=401),
        response(status=429),
        response(errors=[{"message": "test-secret"}]),
        response(warnings=[{"message": "test-secret"}]),
        {"status_code": 200, "body": {}},
    ],
)
def test_lookup_failures_never_write_or_expose_provider_errors(client, bad_response):
    client.indicator_combined_v1.return_value = bad_response
    result = run()
    assert result["data"]["failed"] == 1 and "error" in result
    assert "test-secret" not in json.dumps(result)
    client.indicator_create_v1.assert_not_called()


@pytest.mark.parametrize(
    "bad_response",
    [
        response(status=500),
        response(),
        response(errors=[{"message": "rejected"}]),
        response([{}, {}]),
        response([{"other": "bad"}]),
    ],
)
def test_unacknowledged_writes_never_count_as_success(client, bad_response):
    client.indicator_create_v1.return_value = bad_response
    result = run()
    assert result["data"]["failed"] == 1 and result["data"]["created"] == 0 and "error" in result
    assert client.indicator_create_v1.call_count == 1


def test_partial_failure_reports_previous_success_and_continues(client):
    client.indicator_create_v1.side_effect = [
        response([{"id": "one"}]),
        response(status=429),
        response([{"id": "three"}]),
    ]
    result = run(event([attribute(value=value) for value in ("one.example", "two.example", "three.example")]))
    assert result["data"]["created"] == 2 and result["data"]["failed"] == 1
    assert result["data"]["success"] is False and "Publication may be partial" in result["error"]


def test_request_exception_is_sanitized_and_not_retried(client):
    client.indicator_create_v1.side_effect = RuntimeError("test-secret")
    result = run()
    assert result["data"]["failed"] == 1 and "test-secret" not in json.dumps(result)
    assert "unknown" in result["data"]["items"][0]["error"]
    assert client.indicator_create_v1.call_count == 1


def test_time_budget_prevents_unattempted_writes(client, monkeypatch):
    values = iter([0, publish.DEADLINE_SECONDS + 1])
    monkeypatch.setattr(publish.time, "monotonic", lambda: next(values))
    assert run()["data"]["failed"] == 1
    client.indicator_combined_v1.assert_not_called()


def test_time_budget_is_rechecked_after_lookup(client, monkeypatch):
    values = iter([0, 0, publish.DEADLINE_SECONDS + 1])
    monkeypatch.setattr(publish.time, "monotonic", lambda: next(values))
    assert run()["data"]["failed"] == 1
    client.indicator_combined_v1.assert_called_once()
    client.indicator_create_v1.assert_not_called()


@pytest.mark.parametrize("updating", [False, True], ids=["create", "update"])
def test_real_falconpy_client_serializes_supported_http_contract(monkeypatch, updating):
    calls = []

    def fake_request(self, method, url, **kwargs):
        calls.append((method.upper(), url, kwargs))
        if url.endswith("/oauth2/token"):
            body = {"access_token": "test-token", "expires_in": 1800, "token_type": "bearer"}
        elif "/iocs/combined/indicator/v1" in url:
            body = response([owned()] if updating else [], meta={"pagination": {"total": int(updating)}})["body"]
        elif url.endswith("/iocs/entities/indicators/v1"):
            body = response([{"id": "falcon-1"}])["body"]
        else:
            raise AssertionError("Unexpected SDK endpoint")
        result = requests.Response()
        result.status_code = 200
        result.headers["Content-Type"] = "application/json"
        result._content = json.dumps(body).encode()
        result.url = url
        return result

    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "a" * 32)
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "b" * 40)
    monkeypatch.setattr(requests.sessions.Session, "request", fake_request)
    result = run()
    assert result["data"]["updated" if updating else "created"] == 1, result
    writes = [(method, url, kwargs) for method, url, kwargs in calls if "/iocs/entities/indicators/v1" in url]
    assert len(writes) == 1 and writes[0][0] == ("PATCH" if updating else "POST")
    assert writes[0][2]["json"]["indicators"][0]["id" if updating else "value"] == (
        "falcon-1" if updating else "example.org"
    )
    assert writes[0][2]["timeout"] == 15


class TestCrowdStrikePublishHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous = service.MODULES_HANDLERS.copy()
        self.cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {"crowdstrike_ioc_publish": publish, "type:crowdstrike_ioc_publish": "action_mod"}
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
        assert descriptor["type"] == "action_mod" and descriptor["meta"]["config"]["blocking"] is True
        assert descriptor["meta"]["config"]["support_filters"] is False
        result = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(
                {
                    "module": "crowdstrike_ioc_publish",
                    "data": event([attribute()]),
                    "params": {"dry_run": True, "host_groups": GROUP},
                }
            ),
        )
        assert result.code == 200 and json.loads(result.body)["data"]["planned"] == 1
