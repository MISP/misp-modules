import copy
import json
from unittest.mock import patch

import pytest
import requests
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.action_mod import cortex_xdr_ioc_publish as module
from tests.test_cortex_xdr_client import CONFIG, DIGEST, FakeAPI

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
EVENT_UUID = "f1ef0409-c80a-4012-b401-b7d1050f4ed4"
OBJECT_UUID = "1f89db24-a128-4d49-8a81-cd6e53325bc8"


def attribute(kind="sha256", value=DIGEST, **kwargs):
    return {"type": kind, "value": value, "uuid": UUID, "to_ids": True, **kwargs}


def query(data=None, **params):
    return {
        "data": {"Event": {"uuid": EVENT_UUID, "Attribute": [attribute()]}} if data is None else data,
        "params": params,
    }


def handle(request):
    return module.handler(json.dumps(request))


@pytest.fixture
def api(monkeypatch):
    for key, value in CONFIG.items():
        monkeypatch.setenv("CORTEX_XDR_" + key.upper(), value)
    fake = FakeAPI(rows=[])
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


def test_default_preview_needs_no_credentials_or_network(api, monkeypatch):
    for key in CONFIG:
        monkeypatch.delenv("CORTEX_XDR_" + key.upper())
    result = handle(query())
    assert "error" not in result and result["result_key"] == "cortex_xdr_ioc_publish"
    data = result["data"]
    assert data["success"] and data["dry_run"] and data["planned"] == 1
    payload = data["items"][0]["payload"]
    assert payload["type"] == "HASH" and payload["indicator"] == DIGEST
    assert payload["severity"] == "MEDIUM" and payload["reputation"] == "SUSPICIOUS"
    assert UUID in payload["comment"] and not api.calls


@pytest.mark.parametrize("days", [7, 30, 90, 180])
def test_upload_uses_native_json_validation_and_expiry(api, days):
    with patch.object(module.time, "time", return_value=1700000000):
        result = handle(query(dry_run=False, expiration_days=str(days), severity="HIGH", reputation="BAD"))
    assert "error" not in result and result["data"]["uploaded"] == 1
    assert [call.url.rsplit("/", 1)[-1] for call, _ in api.calls] == ["get", "insert_jsons"]
    body = json.loads(api.calls[1][0].body)
    assert body["validate"] is True and len(body["request_data"]) == 1
    assert body["request_data"][0]["expiration_date"] == (1700000000 + days * 86400) * 1000
    assert body["request_data"][0]["severity"] == "HIGH" and body["request_data"][0]["reputation"] == "BAD"
    assert "rule_id" not in body["request_data"][0]


@pytest.mark.parametrize("expiry", [-1, 1])
def test_existing_foreign_or_expired_rules_are_not_updated(api, expiry):
    api.rows = [
        {"rule_id": 7, "type": "HASH", "indicator": DIGEST, "comment": "foreign namespace", "expiration_date": expiry}
    ]
    result = handle(query(dry_run=False))
    assert "error" not in result and result["data"]["existing"] == 1
    assert result["data"]["uploaded"] == 0 and len(api.calls) == 1
    assert result["data"]["items"][0]["rules"][0]["expiration_date"] == expiry


@pytest.mark.parametrize(
    "kind,value,xdr_type,canonical",
    [
        ("md5", "a" * 32, "HASH", "a" * 32),
        ("domain", "faß.de", "DOMAIN_NAME", "xn--fa-hia.de"),
        ("hostname", "BÜCHER.test.", "DOMAIN_NAME", "xn--bcher-kva.test"),
        ("ip-src", "192.0.2.1", "IP", "192.0.2.1"),
        ("ip-dst", "2001:0DB8::1", "IP", "2001:db8::1"),
    ],
)
def test_observable_payload_mappings(api, kind, value, xdr_type, canonical):
    payload = handle(query({"Attribute": [attribute(kind, value)]}))["data"]["items"][0]["payload"]
    assert payload["type"] == xdr_type and payload["indicator"] == canonical and not api.calls


@pytest.mark.parametrize("shape", ["standard", "bare", "legacy", "list"])
def test_event_objects_deduplication_and_provenance(api, shape):
    top = attribute(comment="DO_NOT_RETAIN", data="DO_NOT_RETAIN")
    obj = {"uuid": OBJECT_UUID, "Attribute": [attribute(uuid="1db7775d-6b1e-4b86-a547-acf9f2be74a8")]}
    event = {"uuid": EVENT_UUID, "info": "DO_NOT_RETAIN", "Attribute": [top], "Object": [obj]}
    data = {"Event": event} if shape == "standard" else event
    if shape == "legacy":
        data = {"Event": {"uuid": EVENT_UUID}, "Attribute": [top], "Object": [obj]}
    elif shape == "list":
        data = [{"Event": event}]
    before = copy.deepcopy(data)
    result = handle(query(data))
    assert result["data"]["planned"] == 1 and len(result["data"]["items"][0]["sources"]) == 2
    assert data == before and "DO_NOT_RETAIN" not in json.dumps(result)
    assert any(ref.get("object_uuid") == OBJECT_UUID for ref in result["data"]["items"][0]["sources"])


def test_excluded_and_malformed_attributes(api):
    data = {
        "uuid": EVENT_UUID,
        "Attribute": [
            attribute(to_ids=False),
            attribute(deleted=True),
            attribute("url", "https://example.org"),
            attribute("sha256", "bad"),
        ],
        "Object": [{"deleted": True, "Attribute": [attribute()]}, {"Attribute": [attribute("domain", "example.org")]}],
    }
    result = handle(query(data))
    assert result["data"]["planned"] == 1
    assert result["data"]["skipped"] == {
        "deleted_container": 1,
        "deleted_or_non_ids": 2,
        "unsupported": 1,
        "malformed": 1,
    }


def test_deleted_events_and_empty_selection_are_no_ops(api):
    assert handle(query({"deleted": True, "Attribute": [attribute()]}))["data"]["planned"] == 0
    assert handle(query({"Attribute": []}, dry_run=False))["data"]["uploaded"] == 0
    assert not api.calls


def test_restricted_values_are_not_broadened(api):
    data = {
        "Attribute": [
            attribute("ip-src", "192.0.2.0/24"),
            attribute("domain", "*.example.org"),
            attribute("ip-dst|port", "192.0.2.1|443"),
            attribute("filename|sha256", "sample|" + DIGEST),
        ]
    }
    result = handle(query(data, dry_run=False))
    assert result["data"]["skipped"] == {"malformed": 2, "unsupported": 2} and not api.calls


@pytest.mark.parametrize(
    "reply",
    [
        {"reply": True},
        {"reply": False},
        {"reply": {"success": False}},
        {"reply": {"success": True, "validation_errors": [{"indicator": DIGEST, "error": CONFIG["api_key"]}]}},
        {"reply": {"success": True, "validation_errors": "bad"}},
        (500, {}),
        requests.Timeout(CONFIG["api_key"]),
    ],
)
def test_upload_failures_are_not_reported_as_success(api, reply):
    api.replies["insert_jsons"] = reply
    result = handle(query(dry_run=False))
    assert "error" in result and not result["data"]["success"] and result["data"]["failed"] == 1
    assert result["data"]["uploaded"] == 0 and len(api.calls) == 2
    assert CONFIG["api_key"] not in json.dumps(result)


def test_partial_success_stops_after_uncertain_upload(api):
    api.replies["insert_jsons"] = [{"reply": {"success": True}}, requests.Timeout(CONFIG["api_key"])]
    result = handle(query({"Attribute": [attribute(value=char * 64) for char in ("a", "b", "c")]}, dry_run=False))
    assert "error" in result and result["data"]["uploaded"] == 1 and result["data"]["failed"] == 1
    assert result["data"]["not_attempted"] == 1
    assert [item["status"] for item in result["data"]["items"]] == ["uploaded", "failed", "not_attempted"]
    assert len(api.calls) == 4


def test_incomplete_lookup_prevents_writes(api):
    api.replies["get"] = {"reply": {"objects": [], "objects_count": 1}}
    assert "error" in handle(query(dry_run=False)) and len(api.calls) == 1


def test_live_publication_requires_server_credentials(api, monkeypatch):
    monkeypatch.delenv("CORTEX_XDR_API_KEY")
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["not_attempted"] == 1 and not api.calls
    assert "error" in handle(query(dry_run=False, url="https://unexpected.example"))


def test_input_limit_fails_before_any_network(api):
    data = {"Attribute": [attribute("domain", f"host-{i}.example.org") for i in range(51)]}
    assert "error" in handle(query(data, dry_run=False)) and not api.calls


@pytest.mark.parametrize(
    "params",
    [
        {"source": "bad\n"},
        {"severity": "bad"},
        {"reputation": "GOOD"},
        {"expiration_days": 8},
        {"expiration_days": True},
        {"dry_run": "perhaps"},
        {"api_key": "untrusted"},
    ],
)
def test_invalid_parameters(api, params):
    assert "error" in handle(query(**params)) and not api.calls


@pytest.mark.parametrize("data", [None, [], {"Event": []}, {"Attribute": None}, {"Object": [{}], "Attribute": [None]}])
def test_input_containers(api, data):
    result = handle({"data": data})
    if data == []:
        assert result["data"]["planned"] == 0
    else:
        assert "error" in result
    assert not api.calls


@pytest.mark.parametrize("field", ["filteredItems", "matchingData"])
def test_workflow_filters_are_rejected(api, field):
    assert "error" in handle({**query(), field: []}) and not api.calls


def test_deadline_marks_items_unattempted(api):
    with patch.object(module.time, "monotonic", side_effect=[0, 121]):
        result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["not_attempted"] == 1 and not api.calls


def test_deadline_reached_during_lookup_prevents_upload_and_later_items(api):
    data = {"Attribute": [attribute(value=char * 64) for char in ("a", "b")]}
    with patch.object(module.time, "monotonic", side_effect=[0, 119, 121]):
        result = handle(query(data, dry_run=False))
    assert "error" in result and result["data"]["not_attempted"] == 2
    assert result["data"]["uploaded"] == result["data"]["failed"] == 0
    assert len(api.calls) == 1 and api.calls[0][0].url.endswith("/get")
    assert all(item["status"] == "not_attempted" for item in result["data"]["items"])


def test_session_closed_after_failure(api):
    api.replies["get"] = (403, {})
    with patch.object(requests.Session, "close") as close:
        assert "error" in handle(query(dry_run=False))
    assert close.call_count == 1


def test_discovery_contract():
    assert module.handler(False) is False and module.introspection() == {} and module.returns == "data"
    config = module.version()["config"]
    assert config["expect_misp_core_format"] and not config["support_filters"]
    assert config["params"]["dry_run"]["value"] == "true"


class TestXdrPublishHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"cortex_xdr_ioc_publish": module, "type:cortex_xdr_ioc_publish": "action_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_preview(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "cortex_xdr_ioc_publish"
        with patch.object(requests.adapters.HTTPAdapter, "send", side_effect=AssertionError("Preview must not send")):
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": "cortex_xdr_ioc_publish", **query()}),
            )
        assert response.code == 200 and json.loads(response.body)["data"]["planned"] == 1


def test_sha1_is_unsupported_for_native_xdr_ioc_rules(api):
    result = handle(query({"Attribute": [attribute("sha1", "a" * 40)]}, dry_run=False))
    assert result["data"]["skipped"] == {"unsupported": 1}
    assert result["data"]["uploaded"] == 0 and not api.calls
