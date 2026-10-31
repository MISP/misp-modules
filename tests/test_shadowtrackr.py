import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import shadowtrackr as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"


def query(kind="ip-dst", value="1.1.1.1", config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source metadata"},
            "config": {"apikey": "test-api-secret"} if config is None else config,
        }
    )


def response(payload=None, status=200):
    result = Mock(status_code=status, headers={})
    result.json.return_value = payload
    result.iter_content.return_value = iter([b"sample bytes"])
    return result


def handle(payload, **kwargs):
    with patch.object(module.requests, "post", return_value=response(payload)) as post:
        result = module.handler(query(**kwargs))
    return result, post


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
    with patch.object(module.requests, "post") as post:
        assert "error" in module.handler(raw)
    post.assert_not_called()


def test_unsupported_type_never_calls_service():
    with patch.object(module.requests, "post") as post:
        assert "error" in module.handler(query(kind="comment"))
    post.assert_not_called()


@pytest.mark.parametrize("value", ["", "   ", 123, ["example.com"]])
def test_invalid_values_never_call_service(value):
    with patch.object(module.requests, "post") as post:
        assert "error" in module.handler(query(value=value))
    post.assert_not_called()


@pytest.mark.parametrize("status", [401, 403, 429, 500, 302])
def test_http_failures_are_reported(status):
    with patch.object(module.requests, "post", return_value=response(status=status)):
        result = module.handler(query())
    assert str(status) in result["error"]
    assert SECRET not in result["error"]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_network_failures_do_not_leak_credentials(failure):
    with patch.object(module.requests, "post", side_effect=failure("url?apikey=" + SECRET)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("status", [404, 204])
def test_empty_service_response_preserves_source(status):
    with patch.object(module.requests, "post", return_value=response(status=status)):
        result = module.handler(query())
    assert_source(result)
    assert result["results"]["Object"] == []


def test_invalid_service_json_is_reported():
    reply = response()
    reply.json.side_effect = ValueError("invalid JSON " + SECRET)
    with patch.object(module.requests, "post", return_value=reply):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("payload", [[], "wrong", 1])
def test_unexpected_service_shape_is_reported(payload):
    result, _ = handle(payload)
    assert "error" in result


def test_missing_configuration_never_calls_service():
    with patch.object(module.requests, "post") as post:
        assert "error" in module.handler(query(config={}))
    post.assert_not_called()


def test_zero_estimate_and_false_flags_are_retained():
    payload = {"false_positive_estimate": 0, "vpn": False, "cdn": True, "cdn_provider": "Example"}
    result, post = handle(payload)
    assert_source(result)
    assert json.loads(values(objects(result, "annotation")[0])["text"]) == payload
    assert post.call_args.args[0] == "https://shadowtrackr.com/api/v3/ip_info"
    assert post.call_args.kwargs["json"] == {"api_key": SECRET, "ip": "1.1.1.1", "labels": ""}
    assert post.call_args.kwargs["timeout"] == 30


def test_labels_are_forwarded_without_modifying_the_source():
    data = json.loads(query())
    data["attribute"]["Tag"] = [{"name": "test-tag"}]
    with patch.object(module.requests, "post", return_value=response({"vpn": True})) as post:
        result = module.handler(json.dumps(data))
    assert_source(result)
    assert post.call_args.kwargs["json"]["labels"] == ["test-tag"]
    assert result["results"]["Attribute"][0]["Tag"][0]["name"] == "test-tag"


def test_service_error_is_not_imported_as_intelligence():
    result, _ = handle({"error": SECRET})
    assert "error" in result
    assert SECRET not in result["error"]


def test_prepared_request_keeps_credentials_out_of_url():
    reply = requests.Response()
    reply.status_code = 200
    reply._content = b'{"vpn":true}'
    with patch("requests.sessions.Session.send", return_value=reply) as send:
        result = module.handler(query())
    assert_source(result)
    prepared = send.call_args.args[0]
    assert prepared.method == "POST"
    assert prepared.url == "https://shadowtrackr.com/api/v3/ip_info"
    assert SECRET not in prepared.url
    assert "api_key" not in prepared.url
    assert prepared.headers["Content-Type"] == "application/json"
    assert json.loads(prepared.body) == {"api_key": SECRET, "ip": "1.1.1.1", "labels": ""}
    assert send.call_args.kwargs["allow_redirects"] is False
