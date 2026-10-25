import base64
import hashlib
import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import reversinglabs_spectra_intel_submission as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {"username": "test-user", "password": "test-service-secret", "mode": "report"}


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


def test_hash_submission_has_receipt_and_no_polling():
    result, request = handle(
        {"rl": {"analysis_id": "analysis-42", "status": "queued", "sha256": "a" * 64}},
        config=dict(CONFIG, mode="submit"),
    )
    assert_source(result)
    assert request.call_args.args[0] == "POST"
    assert request.call_args.kwargs["json"] == {
        "rl": {"platform": "windows10", "response_format": "json", "sha256": "a" * 64}
    }
    assert contexts(result)[0]["analysis_id"] == "analysis-42"
    assert request.call_count == 1


def test_attachment_is_uploaded_before_detonation_with_verified_local_hash():
    content = b"sample bytes"
    sha1 = hashlib.sha1(content).hexdigest()
    with patch.object(
        module.requests,
        "request",
        side_effect=[
            response(content=b""),
            response(content=b""),
            response({"rl": {"analysis_id": "analysis-42", "sha1": sha1}}),
        ],
    ) as request:
        result = module.handler(
            query(
                kind="attachment",
                value="sample.bin",
                data=base64.b64encode(content).decode(),
                config=dict(CONFIG, mode="submit"),
            )
        )
    assert_source(result)
    assert request.call_args_list[0].args[1].endswith("/api/spex/upload/" + sha1)
    assert request.call_args_list[0].kwargs["data"] == content
    assert request.call_args_list[2].kwargs["json"]["rl"]["sha1"] == sha1
    assert request.call_count == 3


def test_latest_report_mode_does_not_submit():
    result, request = handle({"rl": {"report": {"verdict": "malicious"}}})
    assert_source(result)
    assert request.call_args.args[0] == "GET"
    assert request.call_args.args[1].endswith("/query/sha256/" + "a" * 64 + "/latest")


def test_url_report_identifier_is_urlsafe_base64():
    value = "https://example.com/path?x=1"
    result, request = handle({"rl": {"report": {}}}, kind="url", value=value)
    assert_source(result)
    encoded = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
    assert request.call_args.args[1].endswith("/url/base64/" + encoded + "/latest")


def test_url_submission_preserves_url_as_json_data():
    value = "https://example.com/path?x=1"
    result, request = handle({"rl": {"analysis_id": "42"}}, kind="url", value=value, config=dict(CONFIG, mode="submit"))
    assert_source(result)
    assert request.call_args.kwargs["json"]["rl"]["url"] == value


def test_missing_submission_id_is_reported():
    result, _ = handle({"rl": {"status": "queued"}}, config=dict(CONFIG, mode="submit"))
    assert "error" in result


def test_failed_upload_does_not_detonate():
    with patch.object(module.requests, "request", return_value=response(status=500)) as request:
        result = module.handler(
            query(
                kind="attachment",
                value="sample.bin",
                data=base64.b64encode(b"content").decode(),
                config=dict(CONFIG, mode="submit"),
            )
        )
    assert "error" in result
    assert request.call_count == 1


@pytest.mark.parametrize("data", ["invalid-base64", ""])
def test_invalid_attachment_never_calls_service(data):
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(
            query(kind="attachment", value="sample.bin", data=data, config=dict(CONFIG, mode="submit"))
        )
    request.assert_not_called()


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


def test_filename_metadata_is_uploaded_and_xml_escaped_before_detonation():
    import xml.etree.ElementTree as ET

    content = b"metadata test"
    filename = "sample&<test>.bin"
    with patch.object(
        module.requests,
        "request",
        side_effect=[response(content=b""), response(content=b""), response({"rl": {"analysis_id": "42"}})],
    ) as request:
        result = module.handler(
            query(
                kind="attachment",
                value=filename,
                data=base64.b64encode(content).decode(),
                config=dict(CONFIG, mode="submit"),
            )
        )
    assert_source(result)
    metadata_call = request.call_args_list[1]
    assert metadata_call.args[1].endswith("/api/spex/upload/" + hashlib.sha1(content).hexdigest() + "/meta")
    assert metadata_call.kwargs["headers"]["Content-Type"] == "application/octet-stream"
    root = ET.fromstring(metadata_call.kwargs["data"])
    assert root.findtext("properties/property/name") == "filename"
    assert root.findtext("properties/property/value") == filename
    assert root.find("domain") is not None
    assert request.call_args_list[2].args[1].endswith("/api/dynamic/analysis/analyze/v1/query/json")


def test_metadata_failure_prevents_detonation():
    with patch.object(module.requests, "request", side_effect=[response(content=b""), response(status=500)]) as request:
        result = module.handler(
            query(
                kind="attachment",
                value="sample.bin",
                data=base64.b64encode(b"content").decode(),
                config=dict(CONFIG, mode="submit"),
            )
        )
    assert "error" in result
    assert request.call_count == 2


def test_unsupported_macos_platform_is_rejected_before_submission():
    with patch.object(module.requests, "request") as request:
        result = module.handler(query(config=dict(CONFIG, mode="submit", platform="macos15")))
    assert "error" in result
    request.assert_not_called()
