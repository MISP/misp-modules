import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import intel471_hunt as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {"apikey": "test-service-secret"}
KIND, VALUE = ("text", "T1059.001")


def query(kind=KIND, value=VALUE, config=None, data=None):
    attribute = {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source context"}
    if data is not None:
        attribute["data"] = data
    return json.dumps({"attribute": attribute, "config": CONFIG if config is None else config})


def response(payload=None, status=200):
    result = Mock(status_code=status, headers={})
    result.json.return_value = payload
    return result


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def assert_source(result):
    assert "results" in result, result
    original = next(a for a in result["results"]["Attribute"] if a["uuid"] == UUID)
    assert original["to_ids"] is True
    assert original["comment"] == "source context"
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False for a in obj["Attribute"])
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(raw):
    assert "error" in module.handler(raw)


@pytest.mark.parametrize("value", ["", "  ", 5, []])
def test_invalid_value(value):
    assert "error" in module.handler(query(value=value))


def test_unsupported_type():
    assert "error" in module.handler(query(kind="comment"))


@pytest.mark.parametrize("status", [301, 401, 403, 429, 500])
def test_service_errors_are_redacted(status):
    with patch.object(module.requests, "request", return_value=response({"error": SECRET}, status)) as request:
        result = module.handler(query())
    assert str(status) in result["error"]
    assert SECRET not in str(result)
    for call in request.call_args_list:
        assert call.kwargs["verify"] is True
        assert call.kwargs["allow_redirects"] is False
        assert call.kwargs["timeout"] == 30


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_transport_errors_are_redacted(failure):
    with patch.object(module.requests, "request", side_effect=failure(SECRET)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in str(result)


def test_invalid_json_is_redacted():
    reply = response()
    reply.json.side_effect = ValueError(SECRET)
    with patch.object(module.requests, "request", return_value=reply):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in str(result)


def test_missing_configuration_never_calls_service():
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(config={}))
    request.assert_not_called()


def test_sigma_and_runbook_preserved():
    package = {
        "id": "hunt-1",
        "title": "Suspicious interpreter",
        "sigma": "title: Suspicious interpreter\ndetection:\n  condition: selection",
        "severity": "High",
        "response_actions": {"analyst_runbook": "Check process ancestry"},
    }
    with patch.object(
        module.requests, "request", return_value=response({"total": 2, "results": [package, package]})
    ) as request:
        result = module.handler(query(config={"apikey": SECRET, "max_results": 1}))
    assert_source(result)
    assert values(objects(result, "sigma")[0])["sigma"] == package["sigma"]
    assert any("Check process ancestry" in values(o)["text"] for o in objects(result, "annotation"))
    assert len(objects(result, "sigma")) == 1
    assert request.call_args.kwargs["params"] == {
        "indexes": "cyborg_usecases",
        "mitre_technique_ids": "T1059.001",
        "size": 1,
    }
    assert request.call_args.kwargs["headers"]["Authorization"] == "API-Key " + SECRET


def test_cve_uses_vulnerability_filter():
    with patch.object(module.requests, "request", return_value=response({"total": 0, "results": []})) as request:
        result = module.handler(query(kind="vulnerability", value="CVE-2025-12345"))
    assert_source(result)
    assert request.call_args.kwargs["params"]["exploit_or_vulns"] == "CVE-2025-12345"


def test_invalid_search_type_does_not_request():
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(config={"apikey": SECRET, "search_type": "arbitrary"}))
    request.assert_not_called()


def test_requests_configured_result_size():
    with patch.object(module.requests, "request", return_value=response({"total": 20, "results": []})) as request:
        result = module.handler(query())
    assert_source(result)
    assert request.call_args.kwargs["params"]["size"] == 25
    assert objects(result, "annotation")
