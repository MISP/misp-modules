import copy
import json
from unittest.mock import patch

import pytest
import requests
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.action_mod import tines_case_create as module
from tests.test_tines_client import CONFIG, FakeAPI

EVENT_UUID = "f1ef0409-c80a-4012-b401-b7d1050f4ed4"


def event():
    return {
        "uuid": EVENT_UUID,
        "info": "Secret title <@user-123>",
        "Tag": [{"name": "tlp:amber"}],
        "Attribute": [
            {"type": "domain", "value": "sensitive.example", "to_ids": "1", "deleted": "0"},
            {"type": "attachment", "value": "secret.bin", "data": "c2VjcmV0", "to_ids": "0"},
            {"type": "text", "value": "deleted", "deleted": True, "to_ids": True},
        ],
        "Object": [
            {"name": "file", "Attribute": [{"type": "sha256", "value": "a" * 64, "to_ids": True}]},
            {"name": "deleted", "deleted": "1", "Attribute": [{"to_ids": True}]},
        ],
    }


def query(data=None, **params):
    return {"data": {"Event": event()} if data is None else data, "params": {"team_id": "7", **params}}


def handle(request):
    return module.handler(json.dumps(request))


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("TINES_URL", CONFIG["url"])
    monkeypatch.setenv("TINES_API_KEY", CONFIG["api_key"])
    monkeypatch.delenv("TINES_MISP_URL", raising=False)
    fake = FakeAPI()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


@pytest.mark.parametrize("dry_run", [True, "true", "1", None, ""])
def test_preview_is_credential_free_and_sends_no_event_contents(api, monkeypatch, dry_run):
    monkeypatch.delenv("TINES_URL")
    monkeypatch.delenv("TINES_API_KEY")
    request = query(dry_run=dry_run)
    original = copy.deepcopy(request)
    result = handle(request)
    assert "error" not in result and not api.calls and request == original
    assert result["result_key"] == "tines_case_create"
    data = result["data"]
    assert data["success"] and data["dry_run"] and data["status"] == "planned"
    assert data["payload"]["metadata"] == {
        "misp_source": "misp-modules",
        "misp_event_uuid": EVENT_UUID,
        "misp_attribute_count": 3,
        "misp_object_count": 1,
        "misp_ids_attribute_count": 2,
    }
    assert data["payload"]["name"] == "MISP event " + EVENT_UUID
    for secret in ("sensitive.example", "Secret title", "<@user-123>", "secret.bin", "c2VjcmV0", "tlp:amber", "a" * 64):
        assert secret not in json.dumps(result)


def test_default_is_preview(api):
    assert handle(query())["data"]["dry_run"] is True and not api.calls


@pytest.mark.parametrize("priority", ["INFO", "low", "Medium", "high", "critical"])
def test_documented_v2_create_with_exactly_one_authenticated_write(api, priority):
    result = handle(query(dry_run="false", priority=priority, name_prefix="SOC"))
    assert "error" not in result, result
    data = result["data"]
    assert data["success"] and data["status"] == "created" and data["case_id"] == 12 and data["team_id"] == 7
    assert data["url"] == CONFIG["url"] + "/team/7/cases/12" and data["priority"] == priority.lower()
    assert len(api.calls) == 1
    request, options = api.calls[0]
    assert request.url == CONFIG["url"] + "/api/v2/cases" and request.method == "POST"
    assert request.headers["X-User-Token"] == CONFIG["api_key"] and options["verify"]
    body = json.loads(request.body)
    assert set(body) == {"team_id", "name", "description", "priority", "status", "metadata"}
    assert body["team_id"] == 7 and body["name"] == "SOC " + EVENT_UUID
    assert body["status"] == "OPEN" and body["priority"] == priority.lower()
    assert body["metadata"]["misp_event_uuid"] == EVENT_UUID


def test_source_link_and_connection_come_only_from_server_environment(api, monkeypatch):
    monkeypatch.setenv("TINES_MISP_URL", "https://misp.example/subpath/")
    request = query(dry_run=False, url="https://unexpected.example", api_key="wrong", misp_url="https://wrong.example")
    request["config"] = {"url": "https://unexpected.example", "api_key": "wrong"}
    result = handle(request)
    assert "error" not in result and api.calls[0][0].url.startswith(CONFIG["url"])
    assert result["data"]["misp_event_url"] == "https://misp.example/subpath/events/view/" + EVENT_UUID
    body = json.loads(api.calls[0][0].body)
    assert body["metadata"]["misp_event_url"] == result["data"]["misp_event_url"]


@pytest.mark.parametrize("shape", ["bare", "list", "legacy"])
def test_core_workflow_event_envelopes(api, shape):
    data = event()
    if shape == "list":
        data = [{"Event": data}]
    elif shape == "legacy":
        data = {"Event": {"uuid": EVENT_UUID}, "Attribute": data["Attribute"], "Object": data["Object"]}
    result = handle(query(data))
    assert "error" not in result and result["data"]["misp_attribute_count"] == 3


def acknowledgement(**updates):
    planned = handle(query())["data"]["payload"]
    return {
        "case_id": 12,
        "name": planned["name"],
        "team": {"id": 7},
        "priority": "MEDIUM",
        "status": "OPEN",
        "metadata": planned["metadata"],
        **updates,
    }


@pytest.mark.parametrize(
    "updates",
    [
        {"case_id": True},
        {"case_id": 0},
        {"case_id": None},
        {"team": None},
        {"team": {"id": 8}},
        {"team": {"id": True}},
        {"name": "unrelated"},
        {"status": "CLOSED"},
        {"status": None},
        {"priority": "high"},
        {"priority": None},
        {"metadata": None},
        {"metadata": {"misp_event_uuid": EVENT_UUID}},
        {"metadata": {"misp_event_uuid": "wrong", "misp_source": "misp-modules"}},
    ],
)
def test_unconfirmed_or_mismatched_creation_is_uncertain_without_retry(api, updates):
    api.replies["/api/v2/cases"] = (201, acknowledgement(**updates))
    result = handle(query(dry_run=False))
    assert "error" in result and "Check Tines before retrying" in result["error"]
    assert result["data"]["status"] == "uncertain" and not result["data"]["success"] and len(api.calls) == 1


def test_provider_links_are_not_followed_or_trusted(api):
    api.replies["/api/v2/cases"] = (201, acknowledgement(url="https://unexpected.example/collect"))
    result = handle(query(dry_run=False))
    assert "error" not in result and result["data"]["url"] == CONFIG["url"] + "/team/7/cases/12" and len(api.calls) == 1


@pytest.mark.parametrize(
    "reply",
    [
        (200, {}),
        (302, {}),
        (401, {}),
        (404, {}),
        (429, {}),
        (500, {}),
        (201, b"bad-json"),
        (201, {"errors": ["synthetic-secret"]}),
        requests.Timeout("synthetic-secret"),
    ],
)
def test_failed_or_ambiguous_write_never_retries_or_returns_provider_secrets(api, reply):
    api.replies["/api/v2/cases"] = reply
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "uncertain" and len(api.calls) == 1
    assert "synthetic-secret" not in json.dumps(result) and CONFIG["api_key"] not in json.dumps(result)


@pytest.mark.parametrize(
    "params",
    [
        {"team_id": None},
        {"team_id": True},
        {"team_id": 0},
        {"priority": "urgent"},
        {"priority": []},
        {"dry_run": "maybe"},
        {"name_prefix": "<@user-123>"},
        {"name_prefix": "x" * 65},
        {"name_prefix": " "},
    ],
)
def test_invalid_settings_make_no_request(api, params):
    assert "error" in handle(query(**{"dry_run": False, **params})) and not api.calls


@pytest.mark.parametrize(
    "data",
    [
        [],
        [{"Event": event()}, {"Event": event()}],
        {"Event": []},
        {"Event": {"uuid": "bad"}},
        {"Event": {"uuid": EVENT_UUID, "deleted": "1"}},
        {"uuid": EVENT_UUID, "Attribute": {}},
        {"uuid": EVENT_UUID, "Object": [None]},
        {"uuid": EVENT_UUID, "Attribute": [{"to_ids": "wrong"}]},
    ],
)
def test_invalid_selected_data_makes_no_write(api, data):
    assert "error" in handle(query(data, dry_run=False)) and not api.calls


def test_missing_credentials_is_not_attempted(api, monkeypatch):
    monkeypatch.delenv("TINES_API_KEY")
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "not_attempted" and not api.calls


def test_invalid_optional_source_origin_fails_before_write(api, monkeypatch):
    monkeypatch.setenv("TINES_MISP_URL", "https://user:password@misp.example")
    assert "error" in handle(query(dry_run=False)) and not api.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"params": []}', '{"filters": [1]}'])
def test_invalid_envelope(api, raw):
    assert "error" in module.handler(raw) and not api.calls


def test_discovery_contract():
    assert module.handler(False) is False and module.returns == "data" and module.introspection() == {}
    assert module.version()["config"]["expect_misp_core_format"] is True


class TestTinesCaseHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"tines_case_create": module, "type:tines_case_create": "action"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "tines_case_create"
        response = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "tines_case_create", **query()}),
        )
        result = json.loads(response.body)
        assert (
            response.code == 200
            and result["data"]["status"] == "planned"
            and result["result_key"] == "tines_case_create"
        )
