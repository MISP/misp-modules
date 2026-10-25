import base64
import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import intezer as module

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


ANALYSIS_ID = "f010f718-8cea-4f00-9113-a3f6e346a164"
TOKEN = "access-token"


def test_existing_file_report_uses_token_and_read_only_lookup():
    payload = {"result": {"analysis_id": ANALYSIS_ID, "sha256": "a" * 64, "verdict": "benign", "is_private": True}}
    with patch.object(
        module.requests, "request", side_effect=[response({"result": TOKEN}), response(payload)]
    ) as request:
        result = module.handler(query())
    assert_source(result)
    assert request.call_count == 2
    assert request.call_args_list[0].kwargs["json"] == {"api_key": SECRET}
    assert request.call_args.args == ("GET", "https://analyze.intezer.com/api/v2-0/files/" + "a" * 64)
    assert request.call_args.kwargs["headers"]["Authorization"] == "Bearer " + TOKEN
    assert "benign" in values(objects(result, "sandbox-report")[0])["raw-report"]
    assert values(objects(result, "file")[0])["sha256"] == "a" * 64
    assert values(objects(result, "sandbox-report")[0])["sandbox-type"] == "saas"


def test_submission_receipt_does_not_poll():
    with patch.object(
        module.requests,
        "request",
        side_effect=[
            response({"result": TOKEN}),
            response({"result_url": "/analyses/" + ANALYSIS_ID, "status": "queued"}, 202),
        ],
    ) as request:
        result = module.handler(
            query(kind="attachment", value="sample.bin", data=base64.b64encode(b"content").decode())
        )
    assert_source(result)
    assert request.call_count == 2
    assert request.call_args.kwargs["files"]["file"] == ("sample.bin", b"content")
    assert values(objects(result, "sandbox-report")[0])["permalink"].endswith(ANALYSIS_ID)


@pytest.mark.parametrize(
    "path",
    ["https://evil.example/analyses/" + ANALYSIS_ID, "//evil.example/analyses/" + ANALYSIS_ID, "/analyses/../../token"],
)
def test_untrusted_receipt_never_followed(path):
    with patch.object(
        module.requests, "request", side_effect=[response({"result": TOKEN}), response({"result_url": path})]
    ) as request:
        result = module.handler(
            query(kind="attachment", value="sample.bin", data=base64.b64encode(b"content").decode())
        )
    assert "error" in result
    assert request.call_count == 2


def test_pending_analysis_by_id():
    with patch.object(
        module.requests,
        "request",
        side_effect=[
            response({"result": TOKEN}),
            response({"status": "in_progress", "result_url": "/analyses/" + ANALYSIS_ID}),
        ],
    ) as request:
        result = module.handler(query(kind="text", value=ANALYSIS_ID))
    assert_source(result)
    assert request.call_args.args[1].endswith("/analyses/" + ANALYSIS_ID)


def test_no_existing_file():
    with patch.object(module.requests, "request", side_effect=[response({"result": TOKEN}), response(status=404)]):
        result = module.handler(query())
    assert_source(result)
    assert not result["results"]["Object"]


def test_bad_attachment_validated_before_token_request():
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(kind="attachment", value="sample", data="bad"))
    request.assert_not_called()


def test_provider_filename_is_pivotable():
    data = {"result": {"analysis_id": ANALYSIS_ID, "sha256": "a" * 64, "file_name": "sample.exe"}}
    with patch.object(module.requests, "request", side_effect=[response({"result": TOKEN}), response(data)]):
        result = module.handler(query())
    assert_source(result)
    assert values(objects(result, "file")[0])["filename"] == "sample.exe"


def test_expired_analysis_is_no_match():
    with patch.object(module.requests, "request", side_effect=[response({"result": TOKEN}), response(status=410)]):
        result = module.handler(query(kind="text", value=ANALYSIS_ID))
    assert_source(result)
    assert not result["results"]["Object"]


def test_410_on_submission_remains_an_error():
    with patch.object(module.requests, "request", side_effect=[response({"result": TOKEN}), response(status=410)]):
        result = module.handler(
            query(kind="attachment", value="sample.bin", data=base64.b64encode(b"content").decode())
        )
    assert "410" in result["error"]
