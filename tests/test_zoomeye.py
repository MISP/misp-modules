import base64
import copy
import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import zoomeye as module

METHOD = "post"
KIND = "ip-dst"
VALUE = "1.1.1.1"
CONFIG = {"api_key": "test-api-secret"}
PAYLOAD = {
    "code": 60000,
    "total": 5,
    "data": [
        {
            "ip": "1.1.1.1",
            "port": 443,
            "domain": "example.com",
            "hostname": "SPACEX",
            "service": "https",
            "protocol": "TCP",
            "banner": "HTTP/1.1 200 OK",
            "product": "nginx",
            "update_time": "2026-10-01T12:00:00",
        }
    ],
}

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"


def query(kind=KIND, value=VALUE, config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source metadata"},
            "config": dict(CONFIG) if config is None else config,
        }
    )


def response(payload=None, status=200):
    reply = Mock(status_code=status)
    reply.json.return_value = payload
    return reply


def handle(payload=None, status=200, **kwargs):
    with patch.object(
        module.requests, METHOD, return_value=response(PAYLOAD if payload is None else payload, status)
    ) as call:
        result = module.handler(query(**kwargs))
    return result, call


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {item["object_relation"]: item["value"] for item in obj["Attribute"]}


def annotations(result):
    return [json.loads(values(obj)["text"]) for obj in objects(result, "annotation")]


def assert_source(result):
    source = next(item for item in result["results"]["Attribute"] if item["uuid"] == UUID)
    assert source["to_ids"] is True
    assert source["comment"] == "source metadata"
    for obj in result["results"]["Object"]:
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])
        assert all(item["to_ids"] is False for item in obj["Attribute"])
        assert obj["template_uuid"]
    assert all(item["to_ids"] is False for item in result["results"]["Attribute"] if item["uuid"] != UUID)


def test_module_discovery():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig
    assert module.version()["module-type"] == ["expansion"]


@pytest.mark.parametrize(
    "raw", ["{", "[]", "null", "{}", '{"attribute":[]}', '{"attribute":{"type":"ip-dst","value":"1.1.1.1"}}']
)
def test_invalid_request_does_not_call_api(raw):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(raw)
    call.assert_not_called()


@pytest.mark.parametrize("value", ["", "  ", 42, ["example.com"]])
def test_invalid_attribute_value_does_not_call_api(value):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(value=value))
    call.assert_not_called()


def test_unsupported_type_does_not_call_api():
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(kind="comment"))
    call.assert_not_called()


@pytest.mark.parametrize("config", [None, [], "wrong"])
def test_invalid_config_does_not_call_api(config):
    data = json.loads(query())
    data["config"] = config
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(json.dumps(data))
    call.assert_not_called()


@pytest.mark.parametrize("status", [301, 401, 403, 429, 500])
def test_http_errors_do_not_leak_credentials(status):
    result, call = handle({"error": SECRET}, status=status)
    assert str(status) in result["error"]
    assert SECRET not in result["error"]
    assert call.call_count == 1
    if status == 429:
        assert "Retry-After" in result["error"]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_network_errors_do_not_leak_urls_or_credentials(failure):
    with patch.object(module.requests, METHOD, side_effect=failure("url?key=" + SECRET)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


def test_invalid_service_json():
    reply = response()
    reply.json.side_effect = ValueError(SECRET)
    with patch.object(module.requests, METHOD, return_value=reply):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("payload", [[], "wrong", 1, {}, {"error": SECRET}, {"errors": [{"message": SECRET}]}])
def test_invalid_service_response(payload):
    result, _ = handle(payload)
    assert "error" in result
    assert SECRET not in result["error"]


def test_success_preserves_source_and_disables_ids_on_enrichment():
    result, call = handle()
    assert_source(result)
    assert call.call_count == 1
    assert call.call_args.kwargs["timeout"] == 30
    assert call.call_args.kwargs["allow_redirects"] is False


def test_v2_request_and_structured_service():
    result, call = handle()
    assert call.call_args.args[0] == "https://api.zoomeye.ai/v2/search"
    kwargs = call.call_args.kwargs
    assert kwargs["headers"] == {"API-KEY": SECRET}
    assert base64.b64decode(kwargs["json"]["qbase64"]).decode() == 'ip="1.1.1.1"'
    assert kwargs["json"]["sub_type"] == "v4"
    assert kwargs["json"]["pagesize"] == 20
    service = values(objects(result, "ip-port")[0])
    assert service["ip"] == VALUE
    assert service["dst-port"] == "443"
    assert service["hostname"] == "spacex"
    assert service["protocol"] == "tcp"
    assert json.loads(service["text"])["service"] == "https"
    assert annotations(result)[0]["truncated"] is True


@pytest.mark.parametrize(
    "kind,value,expected,dataset",
    [
        ("ip-src", "2606:4700:4700::1111", 'ip="2606:4700:4700::1111"', "v6"),
        ("domain", "EXAMPLE.COM.", 'domain="example.com"', "web"),
        ("hostname", "www.example.com", 'hostname="www.example.com"', "all"),
        ("x509-fingerprint-sha1", "AA:" * 19 + "AA", 'ssl.cert.fingerprint="' + "aa" * 20 + '"', "all"),
    ],
)
def test_search_types_and_encoding(kind, value, expected, dataset):
    result, call = handle({"code": 60000, "total": 0, "data": []}, kind=kind, value=value)
    assert_source(result)
    body = call.call_args.kwargs["json"]
    assert base64.b64decode(body["qbase64"]).decode() == expected
    assert body["sub_type"] == dataset


def test_hostname_query_includes_non_web_hosts():
    result, call = handle(
        {
            "code": 60000,
            "total": 1,
            "data": [{"ip": "1.1.1.1", "port": 22, "hostname": "ssh.example.com", "service": "ssh", "protocol": "TCP"}],
        },
        kind="hostname",
        value="ssh.example.com",
    )
    assert_source(result)
    assert call.call_args.kwargs["json"]["sub_type"] == "all"
    assert values(objects(result, "ip-port")[0])["dst-port"] == "22"


@pytest.mark.parametrize("key", ["  " + SECRET + "  ", "\t" + SECRET + "\n"])
def test_api_key_is_trimmed_before_authentication(key):
    result, call = handle(config=dict(CONFIG, api_key=key))
    assert_source(result)
    assert call.call_args.kwargs["headers"] == {"API-KEY": SECRET}


@pytest.mark.parametrize(
    "value",
    [
        "224.0.0.1",
        "239.255.255.255",
        "ff0e::1",
        "ff02::1",
        "240.0.0.1",
        "64:ff9b::808:808",
        "::ffff:8.8.8.8",
        "::ffff:127.0.0.1",
    ],
)
def test_special_use_ip_is_rejected_before_network_access(value):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(value=value))
    call.assert_not_called()


@pytest.mark.parametrize(
    "kind,value",
    [
        ("domain", 'example.com" || ip="8.8.8.8'),
        ("x509-fingerprint-sha256", "ab" * 32),
        ("x509-fingerprint-sha1", "bad"),
        ("ip-dst", "10.0.0.1"),
    ],
)
def test_invalid_queries_are_not_sent(kind, value):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(kind=kind, value=value))
    call.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [
        {},
        dict(CONFIG, max_results="bad"),
        dict(CONFIG, max_results=0),
        dict(CONFIG, max_results=101),
        dict(CONFIG, max_results=True),
    ],
)
def test_invalid_config_is_not_sent(config):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(config=config))
    call.assert_not_called()


def test_response_cannot_exceed_configured_limit():
    payload = {"code": 60000, "total": 3, "data": PAYLOAD["data"] * 3}
    result, call = handle(payload, config=dict(CONFIG, max_results="2"))
    assert len(objects(result, "ip-port")) == 2
    assert call.call_args.kwargs["json"]["pagesize"] == 2
    assert annotations(result)[0]["truncated"] is True
    assert "first page" in annotations(result)[0]["notice"]


def test_empty_results_are_valid_and_labelled():
    result, _ = handle({"code": 60000, "total": 0, "data": []})
    assert_source(result)
    assert annotations(result)[0]["truncated"] is False
    assert annotations(result)[0]["status"] == "No assets returned"


def test_api_error_is_not_exposed():
    result, _ = handle({"code": 50000, "message": SECRET})
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("changes", [{"port": True}, {"port": 65536}, {"ip": "bad"}, {"protocol": []}])
def test_invalid_asset_fields(changes):
    data = copy.deepcopy(PAYLOAD)
    data["data"][0].update(changes)
    result, _ = handle(data)
    assert "error" in result
