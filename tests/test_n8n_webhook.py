import copy
import hashlib
import json
from unittest.mock import patch

import pytest
import requests
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.action_mod import n8n_webhook as module
from tests.test_n8n_client import ORIGIN, SECRET, FakeHTTP

EVENT_UUID = "f1ef0409-c80a-4012-b401-b7d1050f4ed4"
ATTR_UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
OBJ_UUID = "1f89db24-a128-4d49-8a81-cd6e53325bc8"


def attribute(**updates):
    return {"uuid": ATTR_UUID, "type": "domain", "value": "example.org", "to_ids": "1", "deleted": "0", **updates}


def event():
    return {
        "uuid": EVENT_UUID,
        "info": "Selected MISP event",
        "Attribute": [
            attribute(),
            attribute(type="attachment", data="binary-secret"),
            attribute(deleted="1"),
            attribute(to_ids="0", type="text", value="context"),
        ],
        "Object": [
            {"uuid": OBJ_UUID, "name": "domain-ip", "Attribute": [attribute(object_relation="domain")]},
            {"uuid": OBJ_UUID, "deleted": True, "Attribute": [attribute()]},
        ],
    }


def query(data=None, **params):
    return {"data": {"Event": event()} if data is None else data, "params": params}


def handle(request):
    return module.handler(json.dumps(request))


@pytest.fixture
def http(monkeypatch):
    monkeypatch.setenv("N8N_WEBHOOK_URL", ORIGIN + "/webhook/misp")
    monkeypatch.setenv("N8N_WEBHOOK_HEADER_VALUE", SECRET)
    monkeypatch.delenv("N8N_WEBHOOK_HEADER_NAME", raising=False)
    monkeypatch.delenv("N8N_WEBHOOK_TIMEOUT", raising=False)
    fake = FakeHTTP()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


@pytest.mark.parametrize("dry_run", [None, "", "true", True, "1"])
def test_default_preview_needs_no_connection_and_preserves_input(http, monkeypatch, dry_run):
    monkeypatch.delenv("N8N_WEBHOOK_URL")
    monkeypatch.delenv("N8N_WEBHOOK_HEADER_VALUE")
    request = query(dry_run=dry_run)
    original = copy.deepcopy(request)
    result = handle(request)
    assert "error" not in result and request == original and not http.calls
    data = result["data"]
    assert data["dry_run"] and data["status"] == "planned" and data["attributes"] == 3 and data["objects"] == 1
    assert data["skipped"] == {"deleted_attribute": 1, "binary_attribute": 1, "deleted_object": 1}
    payload = data["payload"]
    assert payload["Event"]["uuid"] == EVENT_UUID and payload["Event"]["Attribute"][0]["to_ids"] is True
    assert payload["Event"]["Attribute"][1]["to_ids"] is False
    assert payload["Event"]["Object"][0]["Attribute"][0]["object_relation"] == "domain"
    assert "binary-secret" not in json.dumps(result) and SECRET not in json.dumps(result)


def test_live_delivery_is_one_post_with_canonical_payload_and_digest(http):
    request = query(dry_run=False, to_ids_only="true")
    result = handle(request)
    assert (
        "error" not in result and result["data"]["status"] == "delivered" and not result["data"]["execution_confirmed"]
    )
    assert result["data"]["attributes"] == 2 and len(http.calls) == 1
    prepared, options = http.calls[0]
    assert prepared.method == "POST" and prepared.url == ORIGIN + "/webhook/misp"
    assert prepared.headers["X-MISP-Token"] == SECRET and "X-N8N-API-KEY" not in prepared.headers
    assert (
        prepared.headers["X-MISP-Payload-SHA256"]
        == hashlib.sha256(prepared.body).hexdigest()
        == result["data"]["payload_sha256"]
    )
    assert json.loads(prepared.body)["Event"]["Attribute"][0]["uuid"] == ATTR_UUID and options["verify"]


@pytest.mark.parametrize("status,body", [(200, b"<html>ignored</html>"), (202, b"queued"), (204, b"")])
def test_successful_http_delivery_does_not_claim_execution_or_expose_body(http, status, body):
    http.replies["/webhook/misp"] = (status, body)
    result = handle(query(dry_run=False))
    assert (
        "error" not in result and result["data"]["http_status"] == status and not result["data"]["execution_confirmed"]
    )
    assert "ignored" not in json.dumps(result) and len(http.calls) == 1


def test_no_api_or_webhook_connection_override_from_request(http, monkeypatch):
    monkeypatch.setenv("N8N_API_KEY", "public-api-secret")
    request = query(dry_run=False, url="https://unexpected.example", api_key="wrong")
    request["config"] = {"url": "https://unexpected.example", "header_value": "wrong"}
    result = handle(request)
    assert "error" not in result and http.calls[0][0].url == ORIGIN + "/webhook/misp"
    assert "public-api-secret" not in str(http.calls[0][0].headers)


@pytest.mark.parametrize("name", ["X-N8N-API-KEY", "X-MISP-Payload-SHA256", "Host"])
def test_reserved_header_names_fail_before_delivery(http, monkeypatch, name):
    monkeypatch.setenv("N8N_WEBHOOK_HEADER_NAME", name)
    result = handle(query(dry_run=False))
    assert result["data"]["status"] == "not_attempted" and "error" in result and not http.calls


def test_custom_header_and_base_path_are_preserved(http, monkeypatch):
    monkeypatch.setenv("N8N_WEBHOOK_URL", ORIGIN + "/automation/custom-hooks/misp/")
    monkeypatch.setenv("N8N_WEBHOOK_HEADER_NAME", "Authorization")
    monkeypatch.setenv("N8N_WEBHOOK_HEADER_VALUE", "Bearer " + SECRET)
    monkeypatch.setenv("N8N_WEBHOOK_TIMEOUT", "7")
    result = handle(query(dry_run=False))
    prepared, options = http.calls[0]
    assert "error" not in result and prepared.url.endswith("/automation/custom-hooks/misp/")
    assert prepared.headers["Authorization"] == "Bearer " + SECRET and options["timeout"] == 7


@pytest.mark.parametrize("reply", [(302, {}), (401, {}), (404, {}), (429, {}), (500, {}), requests.Timeout(SECRET)])
def test_ambiguous_delivery_is_not_retried(http, reply):
    http.replies["/webhook/misp"] = reply
    result = handle(query(dry_run=False))
    assert "error" in result and result["data"]["status"] == "uncertain" and not result["data"]["success"]
    assert "before retrying" in result["error"] and SECRET not in json.dumps(result) and len(http.calls) == 1


@pytest.mark.parametrize("shape", ["bare", "list", "legacy"])
def test_workflow_core_format_shapes(http, shape):
    data = event()
    if shape == "list":
        data = [{"Event": data}]
    elif shape == "legacy":
        data = {"Event": {"uuid": EVENT_UUID}, "Attribute": data["Attribute"], "Object": data["Object"]}
    assert handle(query(data))["data"]["attributes"] == 3


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
        {"uuid": EVENT_UUID, "Attribute": [attribute(value=None)]},
        {"uuid": EVENT_UUID, "Attribute": [attribute(to_ids="wrong")]},
    ],
)
def test_invalid_selection_makes_no_request(http, data):
    assert "error" in handle(query(data, dry_run=False)) and not http.calls


@pytest.mark.parametrize(
    "data",
    [
        {"uuid": EVENT_UUID, "Attribute": [attribute()] * 1001},
        {"uuid": EVENT_UUID, "Attribute": [attribute(value="x" * (1024 * 1024))]},
    ],
)
def test_payload_limits_fail_before_write(http, data):
    assert "error" in handle(query(data, dry_run=False)) and not http.calls


def test_missing_credentials_is_not_attempted(http, monkeypatch):
    monkeypatch.delenv("N8N_WEBHOOK_HEADER_VALUE")
    result = handle(query(dry_run=False))
    assert result["data"]["status"] == "not_attempted" and "error" in result and not http.calls


@pytest.mark.parametrize("key", ["filteredItems", "matchingData"])
@pytest.mark.parametrize("extracted", [None, [], {}])
@pytest.mark.parametrize("dry_run", [True, False])
def test_extracted_data_never_falls_back_to_unfiltered_event(http, key, extracted, dry_run):
    envelope = query(dry_run=dry_run)
    envelope[key] = extracted
    result = handle(envelope)
    assert "error" in result and "data" not in result and not http.calls


@pytest.mark.parametrize(
    "envelope", [{}, [], None, {"params": []}, {"filters": [1]}, query(dry_run="bad"), query(to_ids_only="bad")]
)
def test_invalid_envelopes_and_settings(http, envelope):
    assert "error" in handle(envelope) and not http.calls


def test_discovery_contract():
    assert module.handler(False) is False and module.returns == "data" and module.introspection() == {}
    assert module.version()["config"]["expect_misp_core_format"]


class TestN8nWebhookHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"n8n_webhook": module, "type:n8n_webhook": "action"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "n8n_webhook"
        response = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "n8n_webhook", **query()}),
        )
        assert response.code == 200 and json.loads(response.body)["data"]["status"] == "planned"
