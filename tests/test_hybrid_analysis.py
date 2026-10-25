import base64
import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import hybrid_analysis as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {"apikey": "test-service-secret"}
KIND, VALUE = ("sha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


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


def test_hash_search_uses_get_and_preserves_zero_score():
    with patch.object(
        module.requests,
        "request",
        return_value=response([{"sha256": "a" * 64, "threat_score": 0, "verdict": "no specific threat"}]),
    ) as request:
        result = module.handler(query())
    assert_source(result)
    assert values(objects(result, "sandbox-report")[0])["score"] == "0"
    assert values(objects(result, "file")[0])["sha256"] == "a" * 64
    assert request.call_args.args == ("GET", "https://hybrid-analysis.com/api/v2/search/hash")
    assert request.call_args.kwargs["params"] == {"hash": "a" * 64}


def test_attachment_submission_once_with_real_filename():
    with patch.object(
        module.requests, "request", return_value=response({"job_id": "job-1", "sha256": "a" * 64}, 202)
    ) as request:
        result = module.handler(
            query(kind="attachment", value="sample.bin", data=base64.b64encode(b"file bytes").decode())
        )
    assert_source(result)
    assert request.call_count == 1
    assert request.call_args.kwargs["files"]["file"] == ("sample.bin", b"file bytes")
    assert request.call_args.kwargs["data"]["environment_id"] == 110
    assert "job-1" in values(objects(result, "sandbox-report")[0])["raw-report"]


def test_url_submission_once():
    with patch.object(module.requests, "request", return_value=response({"job_id": "job-1"}, 202)) as request:
        result = module.handler(query(kind="url", value="https://example.com"))
    assert_source(result)
    assert request.call_count == 1
    assert request.call_args.args[1].endswith("/submit/url")


def test_report_lookup_and_pending_state():
    identifier = "a" * 64 + ":110"
    with patch.object(
        module.requests, "request", return_value=response({"state": "IN_QUEUE", "sha256": "a" * 64})
    ) as request:
        result = module.handler(query(kind="text", value=identifier))
    assert_source(result)
    assert "IN_QUEUE" in values(objects(result, "sandbox-report")[0])["raw-report"]
    assert request.call_args.args[1].endswith("/report/" + identifier + "/summary")


@pytest.mark.parametrize("data", ["not base64", "", base64.b64encode(b"").decode()])
def test_invalid_attachment_never_submits(data):
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(kind="attachment", value="sample", data=data))
    request.assert_not_called()


def test_mismatched_hash_rejected():
    with patch.object(module.requests, "request", return_value=response([{"sha256": "b" * 64}])):
        assert "error" in module.handler(query())


def test_submission_requires_job_receipt():
    with patch.object(module.requests, "request", return_value=response({"message": "unexpected"})):
        assert "error" in module.handler(query(kind="url", value="https://example.com"))


@pytest.mark.parametrize("identifier", ["a" * 24, "a" * 64 + ":110"])
def test_api_report_identifier_forms(identifier):
    with patch.object(module.requests, "request", return_value=response({"state": "IN_QUEUE"})) as request:
        result = module.handler(query(kind="text", value=identifier))
    assert_source(result)
    assert request.call_args.args[1].endswith("/report/" + identifier + "/summary")
