import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import virustotal_downloader as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"


def query(kind="sha256", value="8e13f6c598de092f99affe5c64d3aca48f4b4e0bea6e396bc257c40482674e3a", config=None):
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


@pytest.mark.parametrize("status", [401, 403, 429, 500])
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


@pytest.mark.parametrize("status", [404])
def test_empty_service_response_preserves_source(status):
    with patch.object(module.requests, "get", return_value=response(status=status)):
        result = module.handler(query())
    assert_source(result)
    assert result["results"]["Object"] == []


def test_missing_configuration_never_calls_service():
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(config={}))
    get.assert_not_called()


import base64
import hashlib


def downloaded(content=b"sample bytes", status=200, headers=None):
    reply = response(status=status)
    reply.headers = headers or {}
    reply.iter_content.return_value = iter([content])
    return reply


@pytest.mark.parametrize("kind", ["md5", "sha1", "sha256"])
def test_binary_download_and_all_hashes(kind):
    content = b"sample bytes"
    digest = hashlib.new(kind, content).hexdigest()
    reply = downloaded(content)
    with patch.object(module.requests, "get", return_value=reply) as get:
        result = module.handler(query(kind=kind, value=digest))
    assert_source(result)
    obj = objects(result, "file")[0]
    attachment = next(x for x in obj["Attribute"] if x["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == content
    assert values(obj)["sha256"] == hashlib.sha256(content).hexdigest()
    assert get.call_args.kwargs["stream"] is True
    assert get.call_args.kwargs["timeout"] == 30
    reply.close.assert_called_once()


def test_signed_redirect_receives_no_api_key():
    replies = [
        downloaded(status=302, headers={"Location": "https://download.example/sample?signature=signed"}),
        downloaded(),
    ]
    with patch.object(module.requests, "get", side_effect=replies) as get:
        result = module.handler(query())
    assert_source(result)
    assert get.call_args_list[0].kwargs["headers"] == {"x-apikey": SECRET}
    assert get.call_args_list[1].kwargs["headers"] == {}
    assert get.call_args_list[1].args[0] == "https://download.example/sample?signature=signed"
    assert all(reply.close.call_count == 1 for reply in replies)


def test_hash_mismatch_rejects_the_download():
    with patch.object(module.requests, "get", return_value=downloaded(b"wrong")):
        result = module.handler(query())
    assert "does not match" in result["error"]


@pytest.mark.parametrize(
    "headers,body",
    [({"Content-Length": "1048577"}, b"x"), ({}, b"x" * 1048577)],
    ids=["declared-size", "streamed-size"],
)
def test_download_size_cap_applies_with_and_without_content_length(headers, body):
    reply = downloaded(body, headers=headers)
    with patch.object(module.requests, "get", return_value=reply):
        result = module.handler(query(config={"apikey": SECRET, "max_size_mb": "1"}))
    assert "max_size_mb" in result["error"]
    reply.close.assert_called_once()


@pytest.mark.parametrize("target", ["http://download.example/sample", "https://user:pass@download.example/sample", ""])
def test_invalid_redirects_are_rejected(target):
    with patch.object(module.requests, "get", return_value=downloaded(status=302, headers={"Location": target})) as get:
        assert "error" in module.handler(query())
    assert get.call_count == 1


def test_redirect_loop_is_bounded():
    with patch.object(
        module.requests,
        "get",
        return_value=downloaded(status=302, headers={"Location": "https://download.example/loop"}),
    ) as get:
        assert "redirects" in module.handler(query())["error"]
    assert get.call_count == 4


def test_empty_http_success_is_reported_as_an_error():
    with patch.object(module.requests, "get", return_value=downloaded(status=204)):
        assert "204" in module.handler(query())["error"]
