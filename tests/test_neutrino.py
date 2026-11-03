import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import neutrino as module

METHOD = "post"
KIND = "ip-dst"
VALUE = "1.1.1.1"
CONFIG = {"user_id": "test-user", "api_key": "test-api-secret"}
PAYLOAD = {
    "ip": "1.1.1.1",
    "is-listed": True,
    "is-tor": False,
    "is-proxy": True,
    "is-vpn": False,
    "first-seen": 1700000000,
    "last-seen": 1700001000,
    "total-hits": 2,
    "list-count": 1,
    "blocklists": ["proxy"],
    "sensors": [{"id": 1, "blocklist": "proxy", "description": "test sensor"}],
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


def test_headers_form_body_and_detection_context():
    result, call = handle()
    kwargs = call.call_args.kwargs
    assert call.call_args.args[0] == "https://neutrinoapi.net/ip-blocklist"
    assert kwargs["headers"] == {"User-ID": "test-user", "API-Key": SECRET}
    assert kwargs["data"] == {"ip": VALUE, "vpn-lookup": "false"}
    assert SECRET not in call.call_args.args[0]
    summary = annotations(result)[0]
    assert summary["is-proxy"] is True
    assert summary["is-tor"] is False
    assert "is-vpn" not in summary
    assert "is-malware" not in summary
    assert summary["sensors"][0]["description"] == "test sensor"


@pytest.mark.parametrize("key", ["user_id", "api_key"])
def test_credentials_are_trimmed_before_authentication(key):
    config = dict(CONFIG)
    config[key] = "  " + config[key] + "\n"
    result, call = handle(config=config)
    assert_source(result)
    assert call.call_args.kwargs["headers"] == {"User-ID": "test-user", "API-Key": SECRET}


@pytest.mark.parametrize("value", [True, "true", "1"])
def test_vpn_lookup_is_explicit(value):
    result, call = handle(config=dict(CONFIG, vpn_lookup=value))
    assert call.call_args.kwargs["data"]["vpn-lookup"] == "true"
    assert annotations(result)[0]["is-vpn"] is False


def test_unlisted_and_zero_counts_are_preserved():
    result, _ = handle({"ip": VALUE, "is-listed": False, "total-hits": 0, "list-count": 0, "blocklists": []})
    summary = annotations(result)[0]
    assert summary["is-listed"] is False
    assert summary["total-hits"] == 0
    assert "is-proxy" not in summary


@pytest.mark.parametrize("config", [{}, {"user_id": "test"}, {"api_key": SECRET}, dict(CONFIG, vpn_lookup="wrong")])
def test_invalid_credentials_or_configuration_are_not_sent(config):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(config=config))
    call.assert_not_called()


def test_api_error_in_successful_http_response_is_reported_safely():
    result, _ = handle({"api-error": 1, "api-error-msg": SECRET})
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize(
    "changes",
    [
        {"ip": "8.8.8.8"},
        {"is-listed": "false"},
        {"is-tor": "true"},
        {"total-hits": -1},
        {"blocklists": "proxy"},
        {"sensors": ["bad"]},
    ],
)
def test_invalid_api_fields(changes):
    result, _ = handle(dict(PAYLOAD, **changes))
    assert "error" in result


@pytest.mark.parametrize("value", ["127.0.0.1", "10.0.0.1", "::1", "bad", "1.1.1.1/24"])
def test_private_or_invalid_ip_is_not_sent(value):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(value=value))
    call.assert_not_called()


def test_public_ipv6_lookup():
    address = "2606:4700:4700::1111"
    result, call = handle({"ip": address, "is-listed": False}, value=address)
    assert_source(result)
    assert call.call_args.kwargs["data"]["ip"] == address


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
