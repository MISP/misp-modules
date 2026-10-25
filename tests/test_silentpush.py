import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import silentpush as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"


def query(kind="domain", value="example.com", config=None):
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


def test_ipv4_envelope_and_zero_score():
    context = {"sp_risk_score": 0, "asn": 13335, "ip_ptr": "one.one.one.one", "ip_flags": {"is_vpn": False}}
    result, get = handle({"response": {"ip2asn": [context]}}, kind="ip-dst", value="1.1.1.1")
    assert_source(result)
    assert json.loads(values(objects(result, "annotation")[0])["text"]) == context
    assert any(x["type"] == "AS" and x["value"] == "AS13335" for x in result["results"]["Attribute"])
    assert get.call_args.args[0] == "https://api.silentpush.com/api/v1/merge-api/explore/enrich/ipv4/1.1.1.1"
    assert get.call_args.kwargs["headers"] == {"x-api-key": SECRET}


def test_domain_nameserver_and_url_host_only():
    context = {"sp_risk_score": 12, "ns_reputation": {"ns_srv_reputation": [{"ns_server": "ns.example.com"}]}}
    result, get = handle({"response": context}, kind="url", value="https://Example.COM/private?secret=never-send")
    assert_source(result)
    assert get.call_args.args[0] == "https://api.silentpush.com/api/v1/merge-api/explore/enrich/domain/example.com"
    assert "never-send" not in str(get.call_args)
    assert any(x["value"] == "ns.example.com" for x in result["results"]["Attribute"])


def test_ipv6_url_host_is_routed_correctly():
    result, get = handle({"response": {"ip2asn": []}}, kind="url", value="https://[2001:4860:4860::8888]/")
    assert_source(result)
    assert "/ipv6/2001%3A4860" in get.call_args.args[0]


@pytest.mark.parametrize("payload", [{"response": []}, {"response": {"ip2asn": "bad"}}, {"errors": [SECRET]}])
def test_invalid_envelopes_and_errors(payload):
    result, _ = handle(payload, kind="ip-src", value="1.1.1.1")
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize(
    "kind,value", [("domain", "example.com"), ("hostname", "host.example.com"), ("url", "https://example.com/path")]
)
def test_domain_resolved_addresses_produce_deduplicated_asn_and_ptr_pivots(kind, value):
    payload = {
        "response": {
            "ip2asn": [
                {"asn": 13335, "ip_ptr": "first.example.com"},
                {"asn": 13335, "ip_ptr": "second.example.com"},
                {"asn": 13335, "ip_ptr": "first.example.com"},
            ],
            "sp_risk_score": 0,
        }
    }
    result, _ = handle(payload, kind=kind, value=value)
    assert_source(result)
    added = [item for item in result["results"]["Attribute"] if item["uuid"] != UUID]
    assert [(item["type"], item["value"]) for item in added] == [
        ("AS", "AS13335"),
        ("hostname", "first.example.com"),
        ("hostname", "second.example.com"),
    ]
    assert json.loads(values(objects(result, "annotation")[0])["text"])["ip2asn"] == payload["response"]["ip2asn"]


def test_domain_invalid_ip_context_is_reported():
    result, _ = handle({"response": {"ip2asn": ["invalid"]}}, kind="domain", value="example.com")
    assert "error" in result
