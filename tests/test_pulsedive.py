import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import pulsedive as module

METHOD = "get"
KIND = "domain"
VALUE = "example.com"
CONFIG = {"api_key": "test-api-secret"}
PAYLOAD = {
    "indicator": "example.com",
    "type": "domain",
    "iid": 123,
    "risk": "high",
    "retired": 1,
    "stamp_seen": "2026-10-01 12:00:00",
    "riskfactors": [{"description": "Found in feed", "risk": "high"}],
    "threats": [{"name": "Example malware", "category": "malware"}],
    "feeds": [{"name": "Example feed", "organization": "Example org"}],
    "properties": {
        "dns": {"a": [["1.1.1.1", "1.1.1.1"], "1.0.0.1"], "aaaa": "2606:4700:4700::1111", "ns": ["ns1.example.com"]}
    },
    "redirects": {"to": [{"indicator": "https://redirect.example.com/"}]},
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


def test_risk_provenance_and_dns_pivots():
    result, call = handle()
    assert call.call_args.args[0] == "https://pulsedive.com/api/indicator.php"
    assert call.call_args.kwargs["params"] == {"indicator": VALUE, "key": SECRET}
    summary = annotations(result)[0]
    assert summary["risk"] == "high"
    assert summary["retired"] == 1
    assert summary["feeds"][0]["organization"] == "Example org"
    obj = objects(result, "domain-ip")[0]
    assert values(obj)["domain"] == VALUE
    ips = [item["value"] for item in obj["Attribute"] if item["object_relation"] == "ip"]
    assert sorted(ips) == sorted(["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"])
    attributes = result["results"]["Attribute"]
    assert any(item["type"] == "hostname" and item["value"] == "ns1.example.com" for item in attributes)
    assert any(item["type"] == "url" and item["value"] == "https://redirect.example.com/" for item in attributes)


def test_redirect_domain_is_not_mislabelled_as_url():
    data = dict(PAYLOAD, redirects={"to": [{"indicator": "redirect.example.com"}]})
    result, _ = handle(data)
    assert any(
        item["type"] == "domain" and item["value"] == "redirect.example.com" for item in result["results"]["Attribute"]
    )


def test_keyless_lookup_and_domain_normalization():
    result, call = handle(value="EXAMPLE.COM.", config={})
    assert_source(result)
    assert call.call_args.kwargs["params"] == {"indicator": VALUE}


@pytest.mark.parametrize("ptr", ["ptr.example.com.", ["ptr.example.com."], [["ptr.example.com.", "ptr.example.com."]]])
def test_ip_ptr_records_become_hostname_pivots(ptr):
    value = "44.238.122.172"
    result, _ = handle(
        {"indicator": value, "type": "ip", "properties": {"dns": {"ptr": ptr}}}, kind="ip-dst", value=value
    )
    assert_source(result)
    hostnames = [item for item in result["results"]["Attribute"] if item["type"] == "hostname"]
    assert len(hostnames) == 1
    assert hostnames[0]["value"] == "ptr.example.com"
    assert "DNS ptr" in hostnames[0]["comment"]
    assert hostnames[0]["to_ids"] is False


@pytest.mark.parametrize("key", ["  " + SECRET + "  ", "\t" + SECRET + "\n"])
def test_api_key_is_trimmed_before_authentication(key):
    result, call = handle(config={"api_key": key})
    assert_source(result)
    assert call.call_args.kwargs["params"]["key"] == SECRET


def test_whitespace_only_optional_key_uses_keyless_lookup():
    result, call = handle(config={"api_key": "  \t\n"})
    assert_source(result)
    assert "key" not in call.call_args.kwargs["params"]


@pytest.mark.parametrize("key", [False, 0, [], {}])
def test_non_string_optional_key_is_not_sent(key):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(config={"api_key": key}))
    call.assert_not_called()


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
        assert "error" in module.handler(query(kind="ip-dst", value=value))
    call.assert_not_called()


@pytest.mark.parametrize("status", [204, 404])
def test_missing_indicator_is_not_a_clean_verdict(status):
    result, _ = handle(status=status)
    assert_source(result)
    assert annotations(result)[0]["status"] == "No information available"


@pytest.mark.parametrize(
    "kind,value,service_type",
    [
        ("ip-src", "1.1.1.1", "ip"),
        ("ip-dst", "2606:4700:4700::1111", "ip"),
        ("url", "https://example.com/path?a=b", "url"),
    ],
)
def test_other_indicator_types(kind, value, service_type):
    result, call = handle({"indicator": value, "type": service_type, "risk": "unknown"}, kind=kind, value=value)
    assert_source(result)
    assert call.call_args.kwargs["params"]["indicator"] == value
    assert objects(result, "domain-ip") == []


@pytest.mark.parametrize(
    "kind,value",
    [
        ("domain", 'example.com" || domain="other.com'),
        ("ip-dst", "127.0.0.1"),
        ("url", "file:///etc/passwd"),
        ("url", "https://user:password@example.com"),
        ("url", "https://127.0.0.1/"),
    ],
)
def test_invalid_or_credential_bearing_indicator_is_not_sent(kind, value):
    with patch.object(module.requests, METHOD) as call:
        assert "error" in module.handler(query(kind=kind, value=value))
    call.assert_not_called()


@pytest.mark.parametrize(
    "changes",
    [
        {"indicator": "other.com"},
        {"indicator": {}},
        {"type": "ip"},
        {"feeds": "bad"},
        {"properties": {"dns": {"a": [123]}}},
        {"redirects": {"to": ["bad"]}},
    ],
)
def test_invalid_or_mismatched_api_results(changes):
    result, _ = handle(dict(PAYLOAD, **changes))
    assert "error" in result
