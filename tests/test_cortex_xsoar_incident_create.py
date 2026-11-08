import copy
import json
from unittest.mock import patch

import pytest
import requests
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.action_mod import cortex_xsoar_incident_create as module
from tests.test_cortex_xsoar_client import CONFIG, FakeAPI

EVENT_UUID = "f1ef0409-c80a-4012-b401-b7d1050f4ed4"


def event():
    return {
        "id": "99",
        "uuid": EVENT_UUID,
        "info": "Sensitive title",
        "Tag": [{"name": "tlp:amber"}],
        "Attribute": [
            {"type": "domain", "value": "sensitive.example", "to_ids": "1", "deleted": "0"},
            {"type": "attachment", "value": "secret.bin", "data": "binary-secret", "to_ids": "0"},
            {"type": "text", "value": "deleted", "deleted": "1", "to_ids": True},
        ],
        "Object": [
            {"name": "file", "Attribute": [{"type": "sha256", "value": "a" * 64, "to_ids": True}]},
            {"deleted": True, "Attribute": [{"to_ids": True}]},
        ],
    }


def query(data=None, **params):
    return {"data": {"Event": event()} if data is None else data, "params": params}


def handle(request):
    return module.handler(json.dumps(request))


@pytest.fixture
def api(monkeypatch):
    for key, value in CONFIG.items():
        monkeypatch.setenv("CORTEX_XSOAR_" + key.upper(), value)
    monkeypatch.delenv("CORTEX_XSOAR_TIMEOUT", raising=False)
    monkeypatch.delenv("CORTEX_XSOAR_MISP_URL", raising=False)
    fake = FakeAPI()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


@pytest.mark.parametrize("dry_run", [True, "true", "1", None, ""])
def test_preview_is_credential_free_metadata_only_and_does_not_request_updates(api, monkeypatch, dry_run):
    for key in CONFIG:
        monkeypatch.delenv("CORTEX_XSOAR_" + key.upper())
    request = query(dry_run=dry_run, id="existing-incident", version=1)
    original = copy.deepcopy(request)
    result = handle(request)
    assert "error" not in result and request == original and not api.calls
    data = result["data"]
    assert data["success"] and data["dry_run"] and data["status"] == "planned"
    assert data["attributes"] == 3 and data["objects"] == 1 and data["ids_attributes"] == 2
    body = data["payload"]
    assert set(body) == {"name", "details", "type", "severity", "labels", "createInvestigation"}
    assert body["name"] == "MISP event " + EVENT_UUID and body["type"] == "Unclassified"
    assert body["severity"] == 2 and body["createInvestigation"] is False
    assert {"type": "misp_event_uuid", "value": EVENT_UUID} in body["labels"]
    for secret in (
        "Sensitive title",
        "sensitive.example",
        "secret.bin",
        "binary-secret",
        "tlp:amber",
        "a" * 64,
        "existing-incident",
    ):
        assert secret not in json.dumps(result)


def test_default_is_preview(api):
    assert handle(query())["data"]["dry_run"] is True and not api.calls


@pytest.mark.parametrize("severity", [0, 0.5, 1, "2", "3", 4])
def test_created_incident_requires_201_flat_response_and_source_label(api, severity):
    result = handle(query(dry_run=False, severity=severity, incident_type="Phishing", name_prefix="SOC"))
    assert "error" not in result, result
    data = result["data"]
    assert data["success"] and data["status"] == "created" and data["incident_id"] == "12345"
    assert data["severity"] == float(severity) and data["incident_type"] == "Phishing"
    assert len(api.calls) == 1 and api.calls[0][0].url == CONFIG["url"] + "/xsoar/public/v1/incident"
    body = json.loads(api.calls[0][0].body)
    assert body["name"] == "SOC " + EVENT_UUID and body["createInvestigation"] is False
    assert body["severity"] == float(severity) and "id" not in body and "version" not in body


def test_investigation_is_explicit_opt_in(api):
    result = handle(query(dry_run=False, create_investigation="true"))
    assert "error" not in result and result["data"]["create_investigation"] is True
    assert json.loads(api.calls[0][0].body)["createInvestigation"] is True


def test_connection_settings_are_server_only_and_misp_subpath_is_preserved(api, monkeypatch):
    monkeypatch.setenv("CORTEX_XSOAR_MISP_URL", "https://misp.example/subpath/")
    request = query(dry_run=False, url="https://unexpected.example", api_key="wrong")
    request["config"] = {"url": "https://unexpected.example", "api_key": "wrong"}
    result = handle(request)
    assert "error" not in result and api.calls[0][0].url.startswith(CONFIG["url"] + "/")
    body = json.loads(api.calls[0][0].body)
    assert "https://misp.example/subpath/events/view/" + EVENT_UUID in body["details"]


@pytest.mark.parametrize("body", [b"", b"not-json", b'{"id":"unexpected"}'])
def test_processed_but_not_created_http_200_is_not_reported_as_creation_or_uncertainty(api, body):
    api.replies["incident"] = (200, body)
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["success"] is False and result["data"]["status"] == "not_created"
    assert "incident_id" not in result["data"] and "preprocessing" in result["error"] and len(api.calls) == 1


def acknowledgement(**updates):
    payload = handle(query())["data"]["payload"]
    return 201, {"id": "12345", **payload, **updates}


def test_tenant_mappings_are_reported_as_actual_fields_with_warning(api):
    api.replies["incident"] = acknowledgement(name="Mapped name", type="Mapped type", severity=3)
    result = handle(query(dry_run=False))
    assert "error" not in result and result["data"]["status"] == "created" and result["warnings"]
    assert result["data"]["name"] == "Mapped name" and result["data"]["severity"] == 3


@pytest.mark.parametrize(
    "updates",
    [
        {"id": None},
        {"id": True},
        {"id": ""},
        {"name": ""},
        {"type": None},
        {"severity": "2"},
        {"severity": True},
        {"severity": 5},
        {"labels": None},
        {"labels": []},
        {"labels": [{"type": "misp_event_uuid", "value": "other-event"}]},
    ],
)
def test_unconfirmed_or_malformed_creation_is_uncertain_without_retry(api, updates):
    api.replies["incident"] = acknowledgement(**updates)
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "uncertain" and not result["data"]["success"]
    assert "before retrying" in result["error"] and len(api.calls) == 1


@pytest.mark.parametrize(
    "reply",
    [
        (302, {}),
        (400, {}),
        (401, {}),
        (403, {}),
        (404, {}),
        (429, {}),
        (500, {}),
        (201, b"bad-json"),
        requests.Timeout(CONFIG["api_key"]),
    ],
)
def test_write_failures_do_not_retry_or_expose_secrets(api, reply):
    api.replies["incident"] = reply
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "uncertain" and len(api.calls) == 1
    assert CONFIG["api_key"] not in json.dumps(result)


@pytest.mark.parametrize("key", ["filteredItems", "matchingData"])
@pytest.mark.parametrize("selected", [None, [], {}])
def test_extracted_data_never_falls_back_to_unfiltered_event(api, key, selected):
    request = query(dry_run=False)
    request[key] = selected
    assert "error" in handle(request) and not api.calls


@pytest.mark.parametrize("shape", ["bare", "list", "legacy"])
def test_core_format_envelopes(api, shape):
    data = event()
    if shape == "list":
        data = [{"Event": data}]
    elif shape == "legacy":
        data = {"Event": {"uuid": EVENT_UUID}, "Attribute": data["Attribute"], "Object": data["Object"]}
    assert handle(query(data))["data"]["attributes"] == 3


@pytest.mark.parametrize(
    "params",
    [
        {"severity": True},
        {"severity": "NaN"},
        {"severity": "inf"},
        {"severity": -1},
        {"severity": 5},
        {"incident_type": ""},
        {"incident_type": "bad\n"},
        {"name_prefix": "<@user-123>"},
        {"dry_run": "maybe"},
        {"create_investigation": "maybe"},
    ],
)
def test_invalid_params_prevent_network(api, params):
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
def test_invalid_selection_prevents_write(api, data):
    assert "error" in handle(query(data, dry_run=False)) and not api.calls


def test_missing_credentials_is_not_attempted(api, monkeypatch):
    monkeypatch.delenv("CORTEX_XSOAR_API_KEY")
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "not_attempted" and not api.calls


def test_invalid_optional_source_url_prevents_write(api, monkeypatch):
    monkeypatch.setenv("CORTEX_XSOAR_MISP_URL", "https://user:secret@misp.example")
    assert "error" in handle(query(dry_run=False)) and not api.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"params": []}', '{"filters": [1]}'])
def test_invalid_envelope(api, raw):
    assert "error" in module.handler(raw) and not api.calls


def test_discovery_contract():
    assert module.handler(False) is False and module.returns == "data" and module.introspection() == {}
    assert module.version()["config"]["expect_misp_core_format"]


class TestXsoarIncidentHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {"cortex_xsoar_incident_create": module, "type:cortex_xsoar_incident_create": "action"}
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "cortex_xsoar_incident_create"
        response = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "cortex_xsoar_incident_create", **query()}),
        )
        assert response.code == 200 and json.loads(response.body)["data"]["status"] == "planned"
