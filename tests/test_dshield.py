import copy
import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import dshield as module

METHOD = "get"
KIND = "ip-dst"
VALUE = "1.1.1.1"
CONFIG = {"user_agent": "misp-tests (soc@example.com)"}
PAYLOAD = {
    "ip": {
        "number": "1.1.1.1",
        "count": "42",
        "attacks": "2",
        "mindate": "2026-01-01",
        "maxdate": "2026-10-01",
        "as": "13335",
        "asname": "CLOUDFLARENET",
        "ascountry": "US",
        "network": "1.1.1.0/24",
        "asabusecontact": "abuse@example.com",
        "threatfeeds": {"testfeed": {"firstseen": "2026-01-01", "lastseen": "2026-10-01"}},
    }
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


def test_ip_observations_and_network_ownership():
    result, call = handle()
    summary = annotations(result)[0]
    assert summary["reported-packets"] == 42
    assert summary["unique-targets"] == 2
    assert summary["threatfeeds"]["testfeed"]["firstseen"] == "2026-01-01"
    asn = values(objects(result, "asn")[0])
    assert asn["asn"] == "AS13335"
    assert asn["subnet-announced"] == "1.1.1.0/24"
    assert any(item["value"] == "abuse@example.com" for item in result["results"]["Attribute"])
    assert call.call_args.args[0] == "https://isc.sans.edu/api/ip/1.1.1.1?json"
    assert call.call_args.kwargs["headers"]["User-Agent"] == CONFIG["user_agent"]


def test_unwrapped_response_and_zero_reports_are_retained():
    data = {"number": VALUE, "count": 0, "attacks": "0", "threatfeeds": []}
    result, _ = handle(data)
    assert annotations(result)[0]["reported-packets"] == 0
    assert annotations(result)[0]["unique-targets"] == 0
    assert objects(result, "asn") == []
    assert "benign" not in json.dumps(result).lower()


@pytest.mark.parametrize("status", [204, 404])
def test_missing_information_is_labelled(status):
    result, _ = handle(status=status)
    assert_source(result)
    assert annotations(result)[0]["status"] == "No information available"


@pytest.mark.parametrize("value", ["127.0.0.1", "10.0.0.1", "::1", "bad", "1.1.1.1/24", "fe80::1%eth0"])
def test_invalid_or_private_ip_is_not_sent(value):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(value=value))
    call.assert_not_called()


def test_ipv6_uses_escaped_path():
    address = "2606:4700:4700::1111"
    result, call = handle({"ip": {"number": address, "count": 0}}, value=address)
    assert_source(result)
    assert "%3A" in call.call_args.args[0]


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
    "changes",
    [
        {"number": "8.8.8.8"},
        {"count": True},
        {"attacks": "-1"},
        {"as": "bad"},
        {"network": "8.8.8.0/24"},
        {"threatfeeds": "bad"},
    ],
)
def test_malformed_or_mismatched_observations(changes):
    data = copy.deepcopy(PAYLOAD)
    data["ip"].update(changes)
    result, _ = handle(data)
    assert "error" in result
