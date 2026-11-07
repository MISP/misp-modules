import copy
import json
from unittest.mock import patch

import pytest
import requests
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.action_mod import torq_case_create as module
from tests.test_torq_client import CONFIG, TOKEN, FakeAPI

EVENT_UUID = "f1ef0409-c80a-4012-b401-b7d1050f4ed4"
CASE_PATH = "/public/v1alpha/cases"
EMAIL = "analyst@example.org"


def event():
    return {
        "uuid": EVENT_UUID,
        "info": "Sensitive event title <@user-123>",
        "Tag": [{"name": "tlp:amber"}],
        "Attribute": [
            {"type": "domain", "value": "sensitive.example", "to_ids": "1", "deleted": "0"},
            {"type": "attachment", "value": "secret.bin", "data": "binary-secret", "to_ids": "0"},
            {"type": "text", "value": "deleted", "deleted": "1", "to_ids": True},
        ],
        "Object": [
            {"name": "file", "Attribute": [{"type": "sha256", "value": "a" * 64, "to_ids": True}]},
            {"name": "deleted", "deleted": True, "Attribute": [{"to_ids": True}]},
        ],
    }


def query(data=None, **params):
    return {"data": {"Event": event()} if data is None else data, "params": {"reporter_email": EMAIL, **params}}


def handle(request):
    return module.handler(json.dumps(request))


@pytest.fixture
def api(monkeypatch):
    for key, value in CONFIG.items():
        monkeypatch.setenv("TORQ_" + key.upper(), value)
    for key in ("TORQ_ACCESS_TOKEN", "TORQ_MISP_URL", "TORQ_TIMEOUT"):
        monkeypatch.delenv(key, raising=False)
    fake = FakeAPI()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


@pytest.mark.parametrize("dry_run", [True, "true", "1", None, ""])
def test_preview_needs_no_credentials_and_sends_only_event_reference_and_counts(api, monkeypatch, dry_run):
    for key in CONFIG:
        monkeypatch.delenv("TORQ_" + key.upper())
    request = query(dry_run=dry_run)
    original = copy.deepcopy(request)
    result = handle(request)
    assert "error" not in result and not api.calls and request == original
    data = result["data"]
    assert result["result_key"] == "torq_case_create" and data["success"] and data["dry_run"]
    assert (
        data["status"] == "planned" and data["attributes"] == 3 and data["objects"] == 1 and data["ids_attributes"] == 2
    )
    body = data["payload"]
    assert body["title"] == "MISP event " + EVENT_UUID and body["reporter"] == {"user": {"email": EMAIL}}
    assert body["state"] == {"value": "new"} and body["severity"] == {"value": "medium"}
    assert body["tags"] == ["misp", "misp-event:" + EVENT_UUID] and EVENT_UUID in body["description"]
    for secret in (
        "sensitive.example",
        "Sensitive event title",
        "<@user-123>",
        "secret.bin",
        "binary-secret",
        "tlp:amber",
        "a" * 64,
    ):
        assert secret not in json.dumps(result)


def test_default_is_preview(api):
    assert handle(query())["data"]["dry_run"] is True and not api.calls


@pytest.mark.parametrize("severity", ["informational", "LOW", "medium", "High", "critical"])
def test_documented_case_body_oauth_and_single_write(api, severity):
    result = handle(query(dry_run="false", severity=severity, title_prefix="SOC"))
    assert "error" not in result, result
    data = result["data"]
    assert data["success"] and data["status"] == "created" and data["case_id"] == 28 and data["pretty_id"] == "#28"
    assert data["state"] == "new" and data["severity"] == severity.lower() and data["region"] == "us"
    assert [call.path_url for call, _ in api.calls] == ["/v1/auth/token", CASE_PATH]
    request = api.calls[1][0]
    assert request.url == "https://api.torq.io" + CASE_PATH and request.headers["Authorization"] == "Bearer " + TOKEN
    body = json.loads(request.body)
    assert set(body) == {"title", "description", "state", "severity", "reporter", "tags"}
    assert body["title"] == "SOC " + EVENT_UUID and body["severity"] == {"value": severity.lower()}
    assert body["reporter"] == {"user": {"email": EMAIL}}


def test_connection_is_server_only_and_optional_misp_subpath_is_preserved(api, monkeypatch):
    monkeypatch.setenv("TORQ_REGION", "eu")
    monkeypatch.setenv("TORQ_MISP_URL", "https://misp.example/subpath/")
    request = query(dry_run=False, region="jp", client_secret="wrong")
    request["config"] = {"access_token": "wrong", "region": "jp"}
    result = handle(request)
    assert "error" not in result and result["data"]["region"] == "eu"
    assert api.calls[0][0].url == "https://auth.eu.torq.io/v1/auth/token"
    assert "https://misp.example/subpath/events/view/" + EVENT_UUID in json.loads(api.calls[1][0].body)["description"]


def test_existing_token_supports_jp_without_guessing_auth_endpoint(api, monkeypatch):
    monkeypatch.setenv("TORQ_REGION", "jp")
    monkeypatch.setenv("TORQ_ACCESS_TOKEN", TOKEN)
    monkeypatch.delenv("TORQ_CLIENT_ID")
    monkeypatch.delenv("TORQ_CLIENT_SECRET")
    result = handle(query(dry_run=False))
    assert "error" not in result and len(api.calls) == 1
    assert api.calls[0][0].url == "https://api.jp.torq.io" + CASE_PATH


@pytest.mark.parametrize("shape", ["bare", "list", "legacy"])
def test_core_workflow_shapes(api, shape):
    data = event()
    if shape == "list":
        data = [{"Event": data}]
    elif shape == "legacy":
        data = {"Event": {"uuid": EVENT_UUID}, "Attribute": data["Attribute"], "Object": data["Object"]}
    assert handle(query(data))["data"]["attributes"] == 3


def acknowledgement(**updates):
    payload = handle(query())["data"]["payload"]
    return {"case": {"id": 28, **payload, **updates}}


@pytest.mark.parametrize(
    "updates",
    [
        {"id": True},
        {"id": 0},
        {"title": "unrelated"},
        {"description": "wrong event"},
        {"state": None},
        {"state": {"value": "closed"}},
        {"severity": {"value": "high"}},
        {"severity": None},
        {"reporter": None},
        {"reporter": {"user": {"email": "other@example.org"}}},
        {"tags": []},
        {"tags": [{}]},
    ],
)
def test_unconfirmed_case_is_uncertain_without_retry(api, updates):
    api.replies[CASE_PATH] = acknowledgement(**updates)
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "uncertain" and not result["data"]["success"]
    assert "before retrying" in result["error"] and len(api.calls) == 2


@pytest.mark.parametrize(
    "reply",
    [
        (201, {}),
        (302, {}),
        (401, {}),
        (403, {}),
        (404, {}),
        (429, {}),
        (500, {}),
        b"bad-json",
        {"code": 7, "message": CONFIG["client_secret"]},
        requests.Timeout(TOKEN),
    ],
)
def test_case_errors_do_not_retry_or_return_secrets(api, reply):
    api.replies[CASE_PATH] = reply
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "uncertain" and len(api.calls) == 2
    assert TOKEN not in json.dumps(result) and CONFIG["client_secret"] not in json.dumps(result)


def test_failed_authentication_cannot_attempt_case_creation(api):
    api.replies["/v1/auth/token"] = (401, {"error": CONFIG["client_secret"]})
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "not_attempted" and len(api.calls) == 1


@pytest.mark.parametrize("key", ["filteredItems", "matchingData"])
@pytest.mark.parametrize("selection", [None, [], {}])
def test_extracted_data_never_falls_back_to_broader_event(api, key, selection):
    request = query(dry_run=False)
    request[key] = selection
    assert "error" in handle(request) and not api.calls


@pytest.mark.parametrize(
    "params",
    [
        {"reporter_email": None},
        {"reporter_email": "bad"},
        {"reporter_email": "a@."},
        {"reporter_email": "a@example.org\n"},
        {"severity": "urgent"},
        {"severity": []},
        {"title_prefix": "<@user-123>"},
        {"title_prefix": "x" * 65},
        {"dry_run": "maybe"},
    ],
)
def test_invalid_parameters_prevent_network(api, params):
    assert "error" in handle(query(**{"dry_run": False, **params})) and not api.calls


@pytest.mark.parametrize(
    "data",
    [
        [],
        [{"Event": event()}, {"Event": event()}],
        {"Event": []},
        {"uuid": "bad"},
        {"uuid": EVENT_UUID, "deleted": "1"},
        {"uuid": EVENT_UUID, "Attribute": {}},
        {"uuid": EVENT_UUID, "Object": [None]},
        {"uuid": EVENT_UUID, "Attribute": [{"to_ids": "wrong"}]},
    ],
)
def test_invalid_selected_event_prevents_write(api, data):
    assert "error" in handle(query(data, dry_run=False)) and not api.calls


def test_missing_credentials_is_not_attempted(api, monkeypatch):
    monkeypatch.delenv("TORQ_CLIENT_SECRET")
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "not_attempted" and not api.calls


def test_bad_source_url_prevents_write(api, monkeypatch):
    monkeypatch.setenv("TORQ_MISP_URL", "https://user:secret@misp.example")
    assert "error" in handle(query(dry_run=False)) and not api.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"params": []}', '{"filters": [1]}'])
def test_invalid_envelope(api, raw):
    assert "error" in module.handler(raw) and not api.calls


def test_discovery_contract():
    assert module.handler(False) is False and module.returns == "data" and module.introspection() == {}
    assert module.version()["config"]["expect_misp_core_format"]


class TestTorqCaseHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"torq_case_create": module, "type:torq_case_create": "action"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "torq_case_create"
        response = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "torq_case_create", **query()}),
        )
        assert response.code == 200 and json.loads(response.body)["data"]["status"] == "planned"
