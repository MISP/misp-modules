import copy
import hashlib
import json
from unittest.mock import patch

import pytest
import requests
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.action_mod import shuffle_workflow_execute as module
from tests.test_shuffle_client import CONFIG, EXECUTION_ID, EXECUTION_SECRET, ORG_ID, WORKFLOW_ID, FakeAPI

EVENT_UUID = "f1ef0409-c80a-4012-b401-b7d1050f4ed4"
ATTR_UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
OBJ_UUID = "1f89db24-a128-4d49-8a81-cd6e53325bc8"


def attribute(**updates):
    return {"uuid": ATTR_UUID, "type": "domain", "value": "faß.de", "to_ids": "1", "deleted": "0", **updates}


def event():
    return {
        "uuid": EVENT_UUID,
        "info": "Selected MISP event",
        "Attribute": [
            attribute(),
            attribute(type="attachment", data="binary-secret"),
            attribute(deleted="1"),
            attribute(type="text", value="context", to_ids="0"),
        ],
        "Object": [
            {"uuid": OBJ_UUID, "name": "domain-ip", "Attribute": [attribute(object_relation="domain")]},
            {"uuid": OBJ_UUID, "deleted": True, "Attribute": [attribute()]},
        ],
    }


def query(data=None, **params):
    return {"data": {"Event": event()} if data is None else data, "params": {"workflow_id": WORKFLOW_ID, **params}}


def handle(request):
    return module.handler(json.dumps(request))


@pytest.fixture
def api(monkeypatch):
    for key, value in CONFIG.items():
        monkeypatch.setenv("SHUFFLE_" + key.upper(), value)
    monkeypatch.delenv("SHUFFLE_TIMEOUT", raising=False)
    fake = FakeAPI()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


@pytest.mark.parametrize("dry_run", [True, "true", "1", None, ""])
def test_preview_is_credential_free_and_preserves_selection(api, monkeypatch, dry_run):
    for key in CONFIG:
        monkeypatch.delenv("SHUFFLE_" + key.upper())
    request = query(dry_run=dry_run)
    original = copy.deepcopy(request)
    result = handle(request)
    assert "error" not in result and request == original and not api.calls
    data = result["data"]
    assert result["result_key"] == "shuffle_workflow_execute" and data["dry_run"] and data["status"] == "planned"
    assert data["attributes"] == 3 and data["objects"] == 1 and not data["execution_complete"]
    assert data["skipped"] == {"binary_attribute": 1, "deleted_attribute": 1, "deleted_object": 1}
    assert set(data["payload"]) == {"execution_argument", "start"} and data["payload"]["start"] == ""
    argument = data["payload"]["execution_argument"]
    assert isinstance(argument, str) and hashlib.sha256(argument.encode()).hexdigest() == data["payload_sha256"]
    payload = json.loads(argument)
    assert payload["source"] == "misp-modules" and payload["version"] == 1 and payload["Event"]["uuid"] == EVENT_UUID
    assert payload["Event"]["Attribute"][0]["value"] == "faß.de" and payload["Event"]["Attribute"][0]["to_ids"] is True
    assert payload["Event"]["Attribute"][1]["to_ids"] is False
    assert "binary-secret" not in json.dumps(result) and EXECUTION_SECRET not in json.dumps(result)


def test_default_is_preview(api):
    assert handle(query())["data"]["dry_run"] is True and not api.calls


def test_native_execution_request_and_acknowledgement_never_expose_run_authorization(api):
    preview = handle(query(to_ids_only=True))["data"]["payload"]
    result = handle(query(dry_run="false", to_ids_only="true"))
    assert "error" not in result, result
    data = result["data"]
    assert data["success"] and data["status"] == "submitted" and data["execution_id"] == EXECUTION_ID
    assert data["workflow_id"] == WORKFLOW_ID and data["org_id"] == ORG_ID and data["attributes"] == 2
    assert not data["execution_complete"] and len(api.calls) == 1
    request = api.calls[0][0]
    assert request.url == CONFIG["url"] + "/workflows/" + WORKFLOW_ID + "/execute" and request.method == "POST"
    assert request.headers["Authorization"] == "Bearer " + CONFIG["api_key"] and request.headers["Org-Id"] == ORG_ID
    assert json.loads(request.body) == preview
    assert EXECUTION_SECRET not in json.dumps(result) and CONFIG["api_key"] not in json.dumps(result)


def test_connection_and_tenant_are_server_only(api):
    request = query(dry_run=False, url="https://unexpected.example/api/v1", api_key="wrong", org_id=EVENT_UUID)
    request["config"] = {"url": "https://unexpected.example/api/v1", "api_key": "wrong", "org_id": EVENT_UUID}
    result = handle(request)
    assert "error" not in result and result["data"]["org_id"] == ORG_ID
    assert api.calls[0][0].url.startswith(CONFIG["url"] + "/") and api.calls[0][0].headers["Org-Id"] == ORG_ID


@pytest.mark.parametrize("shape", ["bare", "list", "legacy"])
def test_workflow_core_format_envelopes(api, shape):
    data = event()
    if shape == "list":
        data = [{"Event": data}]
    elif shape == "legacy":
        data = {"Event": {"uuid": EVENT_UUID}, "Attribute": data["Attribute"], "Object": data["Object"]}
    assert handle(query(data))["data"]["attributes"] == 3


@pytest.mark.parametrize("key", ["filteredItems", "matchingData"])
@pytest.mark.parametrize("selected", [None, [], {}])
@pytest.mark.parametrize("dry_run", [True, False])
def test_extracted_data_never_falls_back_to_unfiltered_event(api, key, selected, dry_run):
    request = query(dry_run=dry_run)
    request[key] = selected
    result = handle(request)
    assert "error" in result and "data" not in result and not api.calls


@pytest.mark.parametrize(
    "body",
    [
        {"success": True},
        {"success": True, "execution_id": "bad"},
        {"success": True, "execution_id": "0" * 32},
        {"success": True, "execution_id": True},
        {"success": True, "execution_id": EXECUTION_ID, "workflow_id": EVENT_UUID},
        {"success": False, "reason": EXECUTION_SECRET},
    ],
)
def test_unconfirmed_execution_is_uncertain_without_retry(api, body):
    api.replies["execute"] = body
    result = handle(query(dry_run=False))
    assert "error" in result and not result["data"]["success"] and result["data"]["status"] == "uncertain"
    assert "before retrying" in result["error"] and EXECUTION_SECRET not in json.dumps(result) and len(api.calls) == 1


def test_matching_workflow_acknowledgement_is_accepted(api):
    api.replies["execute"] = {
        "success": True,
        "execution_id": EXECUTION_ID,
        "workflow_id": WORKFLOW_ID,
        "authorization": EXECUTION_SECRET,
        "workflow": {"secret": EXECUTION_SECRET},
    }
    result = handle(query(dry_run=False))
    assert result["data"]["status"] == "submitted" and EXECUTION_SECRET not in json.dumps(result)


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
        b"bad-json",
        requests.Timeout(CONFIG["api_key"]),
    ],
)
def test_http_and_network_failures_are_uncertain_without_reruns(api, reply):
    api.replies["execute"] = reply
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "uncertain" and len(api.calls) == 1
    assert CONFIG["api_key"] not in json.dumps(result)


@pytest.mark.parametrize(
    "params",
    [
        {"workflow_id": None},
        {"workflow_id": "../other"},
        {"workflow_id": True},
        {"dry_run": "maybe"},
        {"to_ids_only": "maybe"},
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
        {"uuid": EVENT_UUID, "Attribute": [attribute(uuid="bad")]},
        {"uuid": EVENT_UUID, "Attribute": [attribute(value="\ud800")]},
        {"uuid": EVENT_UUID, "Attribute": [attribute(value=None)]},
        {"uuid": EVENT_UUID, "Attribute": [attribute(to_ids="wrong")]},
    ],
)
def test_invalid_selected_data_makes_no_request(api, data):
    assert "error" in handle(query(data, dry_run=False)) and not api.calls


@pytest.mark.parametrize(
    "data",
    [
        {"uuid": EVENT_UUID, "Attribute": [attribute()] * 1001},
        {"uuid": EVENT_UUID, "Attribute": [attribute(value="x" * (1024 * 1024))]},
    ],
)
def test_payload_limits_are_checked_before_execution(api, data):
    assert "error" in handle(query(data, dry_run=False)) and not api.calls


def test_missing_credentials_is_not_attempted(api, monkeypatch):
    monkeypatch.delenv("SHUFFLE_API_KEY")
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "not_attempted" and not api.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"params": []}', '{"filters": [1]}'])
def test_invalid_envelope(api, raw):
    assert "error" in module.handler(raw) and not api.calls


def test_discovery_contract():
    assert module.handler(False) is False and module.returns == "data" and module.introspection() == {}
    assert module.version()["config"]["expect_misp_core_format"]


class TestShuffleExecuteHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"shuffle_workflow_execute": module, "type:shuffle_workflow_execute": "action"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "shuffle_workflow_execute"
        response = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "shuffle_workflow_execute", **query()}),
        )
        assert response.code == 200 and json.loads(response.body)["data"]["status"] == "planned"
