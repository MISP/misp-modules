import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import vmray_analyzer as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"


def query(kind="sha256", value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source metadata"},
            "config": {"apikey": "test-api-secret", "url": "https://vmray.example"} if config is None else config,
        }
    )


def response(payload=None, status=200):
    result = Mock(status_code=status, headers={})
    result.json.return_value = payload
    result.iter_content.return_value = iter([b"sample bytes"])
    return result


def handle(payload, **kwargs):
    with patch.object(module.requests, "get", return_value=response(payload)) as get:
        result = module.handler(query(**kwargs))
    return result, get


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {item["object_relation"]: item["value"] for item in obj["Attribute"]}


def assert_source(result):
    source = next(item for item in result["results"]["Attribute"] if item["uuid"] == UUID)
    assert source["to_ids"] is True
    assert source["comment"] == "source metadata"
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
    "raw", ["{", "[]", "null", "{}", '{"attribute": []}', '{"attribute":{"type":"ip-dst","value":"1.1.1.1"}}']
)
def test_invalid_request_never_calls_service(raw):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(raw)
    get.assert_not_called()


def test_unsupported_type_never_calls_service():
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(kind="comment"))
    get.assert_not_called()


@pytest.mark.parametrize("value", ["", "   ", 123, ["example.com"]])
def test_invalid_values_never_call_service(value):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(value=value))
    get.assert_not_called()


@pytest.mark.parametrize("status", [401, 403, 429, 500, 302])
def test_http_failures_are_reported(status):
    with patch.object(module.requests, "get", return_value=response(status=status)):
        result = module.handler(query())
    assert str(status) in result["error"]
    assert SECRET not in result["error"]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_network_failures_do_not_leak_credentials(failure):
    with patch.object(module.requests, "get", side_effect=failure("url?apikey=" + SECRET)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("status", [404, 204])
def test_empty_service_response_preserves_source(status):
    with patch.object(module.requests, "get", return_value=response(status=status)):
        result = module.handler(query())
    assert_source(result)
    assert result["results"]["Object"] == []


def test_invalid_service_json_is_reported():
    reply = response()
    reply.json.side_effect = ValueError("invalid JSON " + SECRET)
    with patch.object(module.requests, "get", return_value=reply):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("payload", [[], "wrong", 1])
def test_unexpected_service_shape_is_reported(payload):
    result, _ = handle(payload)
    assert "error" in result


def test_missing_configuration_never_calls_service():
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(config={}))
    get.assert_not_called()


def sample():
    return {
        "sample_id": 42,
        "sample_sha256hash": "a" * 64,
        "sample_filename": "test.exe",
        "sample_score": 0,
        "sample_classifications": ["trojan"],
        "sample_threat_names": ["example"],
        "sample_webif_url": "https://vmray.example/sample/42",
    }


def test_sample_and_analysis_context():
    with patch.object(
        module.requests,
        "get",
        side_effect=[
            response({"data": [sample()]}),
            response({"data": [{"analysis_id": 7, "analysis_finished": True}]}),
        ],
    ) as get:
        result = module.handler(query())
    assert_source(result)
    assert values(objects(result, "file")[0])["sha256"] == "a" * 64
    annotations = [json.loads(values(obj)["text"]) for obj in objects(result, "annotation")]
    assert annotations[0]["sample_score"] == 0
    assert annotations[1]["analysis_id"] == 7
    assert get.call_args_list[0].args[0] == "https://vmray.example/rest/sample/sha256/" + "a" * 64
    assert get.call_args_list[1].args[0] == "https://vmray.example/rest/analysis/sample/42"
    assert get.call_args.kwargs["headers"] == {"Authorization": "api_key " + SECRET}
    assert any(x["type"] == "link" for x in result["results"]["Attribute"])


def test_continuation_has_a_truncation_notice():
    with patch.object(
        module.requests,
        "get",
        side_effect=[
            response({"data": [sample()], "continuation_id": 4}),
            response({"data": [], "continuation_id": 5}),
        ],
    ):
        result = module.handler(query())
    assert len([x for x in objects(result, "annotation") if "result limit" in x["comment"]]) == 2


@pytest.mark.parametrize(
    "url", ["http://vmray.example", "https://user:pass@vmray.example", "https://vmray.example?api_key=secret"]
)
def test_invalid_server_url_never_calls_service(url):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(config={"apikey": SECRET, "url": url}))
    get.assert_not_called()


def test_sample_hash_mismatch_is_rejected():
    row = dict(sample(), sample_sha256hash="b" * 64)
    result, get = handle({"data": [row]})
    assert "error" in result
    assert get.call_count == 1
