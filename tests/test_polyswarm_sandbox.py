import base64
import hashlib
import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import polyswarm_sandbox as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {"apikey": "test-service-secret"}


def query(
    kind="sha256", value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", config=None, data=None
):
    attribute = {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "original context"}
    if data is not None:
        attribute["data"] = data
    return json.dumps({"attribute": attribute, "config": CONFIG if config is None else config})


def response(payload=None, status=200, xml=None, content=None):
    result = Mock(status_code=status, headers={})
    result.json.return_value = payload
    result.content = (
        content if content is not None else xml.encode() if xml is not None else json.dumps(payload).encode()
    )
    return result


def handle(payload=None, xml=None, **kwargs):
    with patch.object(module.requests, "request", return_value=response(payload, xml=xml)) as request:
        result = module.handler(query(**kwargs))
    return result, request


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {item["object_relation"]: item["value"] for item in obj["Attribute"]}


def contexts(result):
    return [json.loads(values(obj)["text"]) for obj in objects(result, "annotation")]


def assert_source(result):
    source = next(item for item in result["results"]["Attribute"] if item["uuid"] == UUID)
    assert source["to_ids"] is True
    assert source["comment"] == "original context"
    for obj in result["results"]["Object"]:
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])
        assert all(item["to_ids"] is False for item in obj["Attribute"])
    assert all(item["to_ids"] is False for item in result["results"]["Attribute"] if item["uuid"] != UUID)


def test_discovery_contract():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig
    assert "expansion" in module.version()["module-type"]


@pytest.mark.parametrize(
    "raw", ["{", "[]", "null", "{}", '{"attribute":[]}', '{"attribute":{"type":"ip-src","value":"1.1.1.1"}}']
)
def test_invalid_request_never_calls_service(raw):
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(raw)
    request.assert_not_called()


@pytest.mark.parametrize("value", ["", "  ", 5, ["example.com"]])
def test_invalid_value_never_calls_service(value):
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(value=value))
    request.assert_not_called()


def test_unsupported_type_never_calls_service():
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(kind="comment"))
    request.assert_not_called()


def test_missing_config_never_calls_service():
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(config={}))
    request.assert_not_called()


@pytest.mark.parametrize("status", [401, 403, 429, 500, 302])
def test_http_errors_are_actionable_and_redacted(status):
    with patch.object(module.requests, "request", return_value=response({"error": SECRET}, status=status)):
        result = module.handler(query())
    assert str(status) in result["error"]
    assert SECRET not in result["error"]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_connection_failures_are_redacted(failure):
    with patch.object(module.requests, "request", side_effect=failure("credentials=" + SECRET)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("status", [404, 204])
def test_empty_lookup_preserves_source(status):
    with patch.object(module.requests, "request", return_value=response(status=status)):
        result = module.handler(query())
    assert_source(result)
    assert not result["results"]["Object"]


def test_malformed_service_body_is_reported():
    reply = response(content=b"not-valid-xml")
    reply.json.side_effect = ValueError(SECRET)
    with patch.object(module.requests, "request", return_value=reply):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


def task():
    return {"id": 42, "status": "pending", "sha256": "a" * 64, "report": {}, "sandbox": "triage"}


def test_latest_task_lookup_and_pending_status():
    result, request = handle({"status": "OK", "result": task()})
    assert_source(result)
    assert contexts(result)[0]["status"] == "pending"
    assert request.call_args.args[1].endswith("/sandbox/sandboxtask/latest")
    assert request.call_args.kwargs["params"] == {"sha256": "a" * 64, "sandbox": "triage", "community": "default"}
    assert request.call_count == 1


def test_lookup_by_task_id():
    result, request = handle({"result": task()}, kind="text", value="42")
    assert_source(result)
    assert request.call_args.kwargs["params"]["sandbox_task_id"] == "42"


def test_existing_sample_submission_uses_artifact_id_and_does_not_poll():
    with patch.object(
        module.requests,
        "request",
        side_effect=[
            response({"result": [{"sha256": "a" * 64, "artifact_id": 123, "id": 456}]}),
            response({"result": task()}),
        ],
    ) as request:
        result = module.handler(query(config=dict(CONFIG, mode="submit", provider="triage", vm="windows10")))
    assert_source(result)
    assert request.call_count == 2
    assert request.call_args.args == ("POST", "https://api.polyswarm.network/v3/sandbox/sandboxtask")
    assert request.call_args.kwargs["json"] == {
        "artifact_id": 456,
        "provider_slug": "triage",
        "vm_slug": "windows10",
        "network_enabled": 1,
        "community": "default",
    }


def test_submission_requires_an_existing_sample():
    with patch.object(module.requests, "request", return_value=response(status=404)) as request:
        result = module.handler(query(config=dict(CONFIG, mode="submit", provider="triage", vm="windows10")))
    assert "error" in result
    assert request.call_count == 1


def test_submit_without_vm_never_calls_service():
    with patch.object(module.requests, "request") as request:
        result = module.handler(query(config=dict(CONFIG, mode="submit", provider="triage")))
    assert "error" in result
    request.assert_not_called()


def test_mismatched_sandbox_sample_is_rejected():
    result, _ = handle({"result": dict(task(), sha256="b" * 64)})
    assert "error" in result


def test_transport_is_bounded_and_credentials_are_absent_from_url():
    with patch.object(module.requests, "request", return_value=response(status=404)) as request:
        module.handler(query())
    assert request.call_count >= 1
    for call in request.call_args_list:
        assert SECRET not in call.args[1]
        assert call.kwargs["timeout"] == 30
        assert call.kwargs["verify"] is True
        assert call.kwargs["allow_redirects"] is False
        assert SECRET not in json.dumps(call.kwargs.get("params", {}))
