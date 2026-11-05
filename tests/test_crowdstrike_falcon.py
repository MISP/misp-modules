import copy
import json
from unittest.mock import patch

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.modules.expansion import crowdstrike_falcon as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-client-secret"
CONFIG = {"api_id": "test-client-id", "apikey": SECRET}
ATTRIBUTE = {"type": "sha256", "value": "a" * 64, "uuid": UUID, "to_ids": True, "comment": "source metadata"}


def query(config=CONFIG, attribute=ATTRIBUTE):
    return json.dumps({"attribute": attribute, "config": config})


def response(resources=None, errors=None, status=200):
    return {"status_code": status, "body": {"resources": [] if resources is None else resources, "errors": errors}}


def handle(payload, **kwargs):
    with patch.object(module, "Intel") as sdk:
        sdk.return_value.query_indicator_entities.return_value = payload
        result = module.handler(query(**kwargs))
    return result, sdk


def assert_source(result):
    assert "results" in result, result
    source = next(attr for attr in result["results"]["Attribute"] if attr["uuid"] == UUID)
    assert source["value"] == ATTRIBUTE["value"]
    assert source["to_ids"] is True
    assert source["comment"] == "source metadata"


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == ["api_id", "apikey"]
    assert module.version()["module-type"] == ["expansion", "hover"]


@pytest.mark.parametrize("config", [None, {}, {"api_id": "client"}, {"apikey": ""}, {"apikey": "  "}, {"apikey": 42}])
def test_missing_client_secret_is_actionable_and_never_authenticates(config):
    with patch.object(module, "Intel") as sdk:
        result = module.handler(query(config=config))
    assert result["error"].startswith("CrowdStrike apikey is missing")
    sdk.assert_not_called()


def test_absent_config_is_actionable():
    with patch.object(module, "Intel") as sdk:
        result = module.handler(json.dumps({"attribute": ATTRIBUTE}))
    assert "OAuth2 client secret" in result["error"]
    sdk.assert_not_called()


@pytest.mark.parametrize("client_id", [None, "", " ", 42])
def test_missing_client_id_is_actionable(client_id):
    with patch.object(module, "Intel") as sdk:
        result = module.handler(query(config={"apikey": SECRET, "api_id": client_id}))
    assert result["error"].startswith("CrowdStrike api_id is missing")
    sdk.assert_not_called()


@pytest.mark.parametrize("raw", ["{", "[]", "null", '"text"'])
def test_invalid_json_envelope_never_authenticates(raw):
    with patch.object(module, "Intel") as sdk:
        assert "JSON object" in module.handler(raw)["error"]
    sdk.assert_not_called()


@pytest.mark.parametrize("config", [[], "invalid", 1])
def test_invalid_configuration_never_authenticates(config):
    with patch.object(module, "Intel") as sdk:
        assert "config must be an object" in module.handler(query(config=config))["error"]
    sdk.assert_not_called()


@pytest.mark.parametrize("attribute", [None, [], {}, {"type": "sha256"}, dict(ATTRIBUTE, type="comment")])
def test_invalid_or_unsupported_attribute_never_authenticates(attribute):
    with patch.object(module, "Intel") as sdk:
        assert "error" in module.handler(query(attribute=attribute))
    sdk.assert_not_called()


@pytest.mark.parametrize(
    "status, expected",
    [
        (400, "parameters"),
        (401, "OAuth2"),
        (403, "Intel: Read"),
        (404, "availability"),
        (429, "rate limit"),
        (500, "availability"),
    ],
)
def test_http_errors_explain_authentication_and_access_without_echoing_service_errors(status, expected):
    result, _ = handle(response(errors=[{"message": SECRET}], status=status))
    assert result["error"].startswith(f"HTTP Error: {status}")
    assert expected in result["error"]
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize("errors", [[{"code": 403, "message": SECRET}], [SECRET], [{"message": SECRET}]])
def test_structured_and_legacy_api_errors_return_diagnostics(errors):
    result, _ = handle(response(errors=errors))
    assert result["error"].startswith("API Error:")
    assert SECRET not in json.dumps(result)
    assert "sequence item" not in result["error"]


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"status_code": 200},
        {"status_code": 200, "body": None},
        {"status_code": 200, "body": {}},
        {"status_code": 200, "body": {"resources": None}},
        {"status_code": 200, "body": {"resources": ["invalid"]}},
    ],
)
def test_malformed_success_is_not_reported_as_no_matches(payload):
    result, _ = handle(payload)
    assert "error" in result


@pytest.mark.parametrize("errors_field", ["absent", "null", "empty"])
def test_no_matches_is_a_success_preserving_source(errors_field):
    payload = response()
    if errors_field == "absent":
        payload["body"].pop("errors")
    elif errors_field == "empty":
        payload["body"]["errors"] = []
    result, sdk = handle(payload)
    assert_source(result)
    assert len(result["results"]["Attribute"]) == 1
    sdk.assert_called_once_with(client_id=CONFIG["api_id"], client_secret=SECRET)
    sdk.return_value.query_indicator_entities.assert_called_once_with(q=ATTRIBUTE["value"])


@pytest.mark.parametrize(
    "optional", [{}, {"relations": None, "actors": None, "labels": None, "ip_address_types": None}]
)
def test_missing_optional_indicator_fields_do_not_crash(optional):
    result, _ = handle(response(resources=[{"type": "hash_sha256", "indicator": ATTRIBUTE["value"], **optional}]))
    assert_source(result)


def test_related_indicators_and_threat_metadata_are_preserved():
    indicator = {
        "relations": [{"type": "domain", "indicator": "example.org"}],
        "actors": ["Example actor"],
        "malware_families": ["Example family"],
        "ip_address_types": ["ipv4"],
        "malicious_confidence": "high",
        "labels": [{"name": "example label", "created_on": 1700000000, "last_valid_on": 1700000100}],
        "reports": ["example report"],
        "threat_types": ["example threat"],
        "last_updated": 1700000200,
    }
    original = copy.deepcopy(indicator)
    result, _ = handle(response(resources=[indicator]))
    assert_source(result)
    attributes = result["results"]["Attribute"]
    assert any(a["type"] == "hostname" and a["value"] == "example.org" for a in attributes)
    assert any(a["type"] == "threat-actor" and a["value"] == "Example actor" for a in attributes)
    for text in (
        "malware_families: Example family",
        "IP_Type: ipv4",
        "Malicious_Confidence: high",
        "Report: example report",
        "Threat_Type: example threat",
    ):
        assert any(a["value"] == text for a in attributes)
    assert any(a["type"] == "datetime" for a in attributes)
    assert any("created_on:" in str(a["value"]) for a in attributes)
    assert indicator == original


@pytest.mark.parametrize("stage", ["construct", "query"])
def test_sdk_exceptions_do_not_expose_credentials(stage):
    with patch.object(module, "Intel") as sdk:
        if stage == "construct":
            sdk.side_effect = RuntimeError(SECRET)
        else:
            sdk.return_value.query_indicator_entities.side_effect = RuntimeError(SECRET)
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in json.dumps(result)


class TestCrowdStrikeEnrichmentHTTP(AsyncHTTPTestCase):
    def get_app(self):
        handlers = {"crowdstrike_falcon": module, "type:crowdstrike_falcon": "expansion"}
        self.handlers_patch = patch.object(server, "MODULES_HANDLERS", handlers)
        self.handlers_patch.start()
        self.addCleanup(self.handlers_patch.stop)
        return Application([(r"/modules", server.ListModules), (r"/query", server.QueryModule)])

    def test_missing_credentials_returns_configuration_error(self):
        body = json.loads(query(config={}))
        body["module"] = "crowdstrike_falcon"
        with patch.object(module, "Intel") as sdk:
            result = json.loads(self.fetch("/query", method="POST", body=json.dumps(body)).body)
        assert result["error"].startswith("CrowdStrike apikey is missing")
        sdk.assert_not_called()

    def test_discovery_and_successful_enrichment(self):
        discovered = json.loads(self.fetch("/modules").body)[0]
        assert discovered["type"] == "expansion"
        assert discovered["meta"]["config"] == ["api_id", "apikey"]
        body = json.loads(query())
        body["module"] = "crowdstrike_falcon"
        with patch.object(module, "Intel") as sdk:
            sdk.return_value.query_indicator_entities.return_value = response(resources=[{"actors": ["Example actor"]}])
            result = json.loads(self.fetch("/query", method="POST", body=json.dumps(body)).body)
        assert_source(result)
        assert any(a["type"] == "threat-actor" for a in result["results"]["Attribute"])
