import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import shodan_internetdb as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"


def query(kind="ip-dst", value="1.1.1.1", config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source metadata"},
            "config": {} if config is None else config,
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


PAYLOAD = {
    "ip": "1.1.1.1",
    "ports": [53, 443, 443],
    "hostnames": ["one.one.one.one"],
    "cpes": ["cpe:/a:example:server:1"],
    "vulns": ["CVE-2025-1234"],
    "tags": ["cdn"],
}


def test_host_intelligence_is_pivotable_and_referenced():
    result, get = handle(PAYLOAD)
    assert_source(result)
    obj = objects(result, "ip-port")[0]
    assert values(obj)["ip-dst"] == "1.1.1.1"
    assert [x["value"] for x in obj["Attribute"] if x["object_relation"] == "dst-port"] == ["53", "443"]
    assert {x["type"] for x in result["results"]["Attribute"]} == {"ip-dst", "hostname", "cpe", "vulnerability"}
    assert json.loads(values(objects(result, "annotation")[0])["text"])["tags"] == ["cdn"]
    get.assert_called_once_with("https://internetdb.shodan.io/1.1.1.1", timeout=30, allow_redirects=False)


def test_ipv6_source_port_direction():
    payload = dict(PAYLOAD, ip="2001:4860:4860::8888")
    result, get = handle(payload, kind="ip-src", value=payload["ip"])
    assert "src-port" in values(objects(result, "ip-port")[0])
    assert "%3A" in get.call_args.args[0]


@pytest.mark.parametrize("changes", [{"ip": "8.8.8.8"}, {"ports": "443"}, {"ports": [65536]}, {"ports": [True]}])
def test_mismatched_or_invalid_results(changes):
    result, _ = handle(dict(PAYLOAD, **changes))
    assert "error" in result
