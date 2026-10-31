import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import zetalytics as module

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


def test_dns_records_preserve_times_and_deduplicate():
    record = {"qname": "example.com", "rrtype": "a", "value": "1.2.3.4", "first_ts": 0, "last_ts": 1735689600}
    result, get = handle({"results": [record, record]})
    assert_source(result)
    assert len(objects(result, "dns-record")) == 1
    obj = objects(result, "dns-record")[0]
    assert values(obj)["a-record"] == "1.2.3.4"
    assert obj["first_seen"].startswith("1970-01-01")
    assert obj["last_seen"].startswith("2025-01-01")
    assert get.call_args.args[0] == "https://zonecruncher.com/api/v2/domain2rrtypes"
    assert get.call_args.kwargs["params"]["token"] == SECRET


def test_reverse_ip_lookup():
    result, get = handle(
        {"results": [{"qname": "example.com", "rrtype": "aaaa", "value": "2001:db8::1"}]},
        kind="ip-src",
        value="2001:db8::1",
    )
    assert_source(result)
    assert get.call_args.args[0].endswith("/ip")
    assert get.call_args.kwargs["params"]["q"] == "2001:db8::1"


@pytest.mark.parametrize(
    "kind,value,relation,expected",
    [
        ("mx", "10 mail.example.com.", "mx-record", "mail.example.com"),
        ("ns", "NS1.EXAMPLE.COM.", "ns-record", "ns1.example.com"),
        ("txt", "v=spf1 -all", "txt-record", "v=spf1 -all"),
        ("cname", "alias.example.com", "cname-record", "alias.example.com"),
    ],
)
def test_dns_record_mapping(kind, value, relation, expected):
    result, _ = handle({"results": [{"qname": "example.com", "rrtype": kind, "value": value}]})
    assert values(objects(result, "dns-record")[0])[relation] == expected


def test_unsupported_record_retained_and_cap_reported():
    result, _ = handle(
        {"total": 10, "results": [{"qname": "example.com", "rrtype": "caa", "value": "0 issue letsencrypt.org"}]},
        config={"apikey": SECRET, "max_results": 1},
    )
    assert len(objects(result, "annotation")) == 2


def test_invalid_address_family_rejected():
    result, _ = handle({"results": [{"qname": "example.com", "rrtype": "a", "value": "2001:db8::1"}]})
    assert "error" in result


@pytest.mark.parametrize(
    "record",
    [
        {"qname": "example.com", "rrtype": "mx", "value": ""},
        {"qname": None, "rrtype": "a", "value": "1.2.3.4"},
        {"qname": "example.com", "rrtype": "a", "value": "1.2.3.4", "first_ts": 1e100},
    ],
)
def test_invalid_record_fields_return_a_module_error(record):
    result, _ = handle({"results": [record]})
    assert "error" in result


@pytest.mark.parametrize(
    "first,last,expected_first,expected_last",
    [
        (0, 1735689600, "1970-01-01T00:00:00", "2025-01-01T00:00:00"),
        ("2025-01-01T01:00:00+01:00", "2025-01-02T00:00:00Z", "2025-01-01T00:00:00", "2025-01-02T00:00:00"),
        ("2025-01-01 00:00:00", "2025-01-02", "2025-01-01T00:00:00", "2025-01-02T00:00:00"),
    ],
)
def test_provider_observation_fields_are_parsed(first, last, expected_first, expected_last):
    record = {"qname": "example.com", "rrtype": "a", "value": "1.2.3.4", "first_seen": first, "last_seen": last}
    result, _ = handle({"results": [record]})
    obj = objects(result, "dns-record")[0]
    assert obj["first_seen"].startswith(expected_first)
    assert obj["last_seen"].startswith(expected_last)


def test_deduplication_uses_the_actual_observation_boundaries():
    row = {
        "qname": "example.com",
        "rrtype": "a",
        "value": "1.2.3.4",
        "first_seen": "2025-01-01",
        "last_seen": "2025-01-02",
    }
    result, _ = handle({"results": [row, row, dict(row, last_seen="2025-01-03")]})
    assert len(objects(result, "dns-record")) == 2


def test_provider_fields_take_precedence_over_legacy_timestamps():
    row = {
        "qname": "example.com",
        "rrtype": "a",
        "value": "1.2.3.4",
        "first_seen": 0,
        "first_ts": 1735689600,
        "last_seen": 1735689600,
    }
    result, _ = handle({"results": [row]})
    assert objects(result, "dns-record")[0]["first_seen"].startswith("1970-01-01")
