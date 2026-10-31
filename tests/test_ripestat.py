import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import ripestat

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"


def query(kind="ip-dst", value="193.0.6.139", config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "comment": "source context", "to_ids": True},
            "config": config,
        }
    )


def response(data, status="ok", http=200):
    result = Mock(status_code=http)
    result.json.return_value = {"status": status, "data": data}
    return result


def overview(number="3333", holder="RIPE-NCC-AS", announced=True):
    return response({"resource": number, "holder": holder, "announced": announced})


def values(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def assert_result(result, count):
    assert "results" in result, result
    (source,) = result["results"]["Attribute"]
    assert source["uuid"] == UUID
    assert source["comment"] == "source context"
    assert source["to_ids"] is True
    objects = result["results"]["Object"]
    assert len(objects) == count
    for obj in objects:
        assert obj["name"] == "asn"
        assert all(a["to_ids"] is False for a in obj["Attribute"])
        assert obj["ObjectReference"][0]["referenced_uuid"] == UUID
    return objects


@pytest.fixture
def get():
    with patch.object(ripestat.requests, "get") as mock:
        yield mock


def test_discovery():
    assert ripestat.handler(False) is False
    assert ripestat.introspection() == {"input": ["ip-src", "ip-dst", "AS"], "format": "misp_standard"}
    assert ripestat.version()["config"] == ["sourceapp"]


@pytest.mark.parametrize(
    "kind,address,prefix",
    [
        ("ip-dst", "193.0.6.139", "193.0.0.0/21"),
        ("ip-src", "2001:67c:2e8::1", "2001:67c:2e8::/48"),
    ],
)
def test_address_lookup(get, kind, address, prefix):
    get.side_effect = [response({"asns": [3333], "prefix": prefix}), overview()]
    (obj,) = assert_result(ripestat.handler(query(kind, address)), 1)
    assert values(obj) == {"asn": "AS3333", "description": "RIPE-NCC-AS", "subnet-announced": prefix}
    assert "announced: true" in obj["comment"]
    first, second = get.call_args_list
    assert first.args == ("https://stat.ripe.net/data/network-info/data.json",)
    assert first.kwargs == {
        "params": {"resource": address, "sourceapp": "misp-modules"},
        "headers": {"Accept": "application/json"},
        "timeout": 30,
        "allow_redirects": False,
    }
    assert second.args == ("https://stat.ripe.net/data/as-overview/data.json",)
    assert second.kwargs["params"]["resource"] == "AS3333"


def test_multiple_origins_are_preserved_and_deduplicated(get):
    get.side_effect = [
        response({"asns": [3333, "3333", 3334], "prefix": "193.0.0.0/21"}),
        overview(),
        overview("3334", "Second holder"),
    ]
    objects = assert_result(ripestat.handler(query()), 2)
    assert {values(obj)["asn"] for obj in objects} == {"AS3333", "AS3334"}
    assert get.call_count == 3


@pytest.mark.parametrize("value,resource", [("AS3333", "3333"), ("3333", "AS3333"), (" as003333 ", 3333)])
def test_as_lookup(get, value, resource):
    get.return_value = overview(resource, announced=False)
    (obj,) = assert_result(ripestat.handler(query("AS", value, {"sourceapp": "my_project-1"})), 1)
    assert values(obj) == {"asn": "AS3333", "description": "RIPE-NCC-AS"}
    assert "announced: false" in obj["comment"]
    assert get.call_args.kwargs["params"] == {"resource": "AS3333", "sourceapp": "my_project-1"}
    assert get.call_count == 1


@pytest.mark.parametrize("prefix", ["193.0.0.0/21", "2001:67c:2e8::/48"])
def test_prefix_lookup(get, prefix):
    get.return_value = response(
        {
            "resource": prefix,
            "asns": [
                {"asn": 3333, "holder": "RIPE-NCC-AS"},
                {"asn": 3334, "holder": None},
                {"asn": 3333, "holder": "RIPE-NCC-AS"},
            ],
        }
    )
    objects = assert_result(ripestat.handler(query("ip-src", prefix)), 2)
    assert values(objects[0]) == {"asn": "AS3333", "description": "RIPE-NCC-AS", "subnet-announced": prefix}
    assert "description" not in values(objects[1])
    assert get.call_count == 1
    assert get.call_args.args == ("https://stat.ripe.net/data/prefix-overview/data.json",)
    assert get.call_args.kwargs["params"]["resource"] == prefix


def test_less_specific_prefix_uses_actual_response_prefix(get):
    get.return_value = response(
        {"resource": "193.0.0.0/21", "is_less_specific": True, "asns": [{"asn": 3333, "holder": "RIPE-NCC-AS"}]}
    )
    (obj,) = assert_result(ripestat.handler(query("ip-dst", "193.0.6.139/24")), 1)
    assert get.call_args.kwargs["params"]["resource"] == "193.0.6.0/24"
    assert values(obj)["subnet-announced"] == "193.0.0.0/21"


@pytest.mark.parametrize(
    "kind,value,data",
    [
        ("ip-dst", "192.0.2.1", {"asns": [], "prefix": None}),
        ("ip-src", "192.0.2.0/24", {"resource": "192.0.2.0/24", "asns": []}),
    ],
)
def test_no_routing_data(get, kind, value, data):
    get.return_value = response(data)
    assert_result(ripestat.handler(query(kind, value)), 0)
    assert get.call_count == 1


@pytest.mark.parametrize(
    "raw", ["{", "[]", "null", "{}", '{"attribute": []}', '{"attribute": {"type": "AS", "value": "3333"}}']
)
def test_invalid_envelope(get, raw):
    assert "error" in ripestat.handler(raw)
    get.assert_not_called()


@pytest.mark.parametrize(
    "kind,value",
    [
        ("domain", "example.com"),
        ("AS", "AS-1"),
        ("AS", "AS4294967296"),
        ("AS", "1.5"),
        ("ip-src", "invalid"),
        ("ip-dst", "1.2.3.4/33"),
        ("ip-dst", ""),
        ("AS", 3333),
    ],
)
def test_invalid_attribute(get, kind, value):
    assert "error" in ripestat.handler(query(kind, value))
    get.assert_not_called()


@pytest.mark.parametrize("config", [{"sourceapp": "bad identifier"}, {"sourceapp": 33}, "invalid"])
def test_invalid_config(get, config):
    assert "error" in ripestat.handler(query(config=config))
    get.assert_not_called()


@pytest.mark.parametrize("status", [301, 400, 404, 429, 500, 503])
def test_http_errors(get, status):
    get.return_value = response({}, http=status)
    assert f"HTTP {status}" in ripestat.handler(query())["error"]
    assert get.call_count == 1


@pytest.mark.parametrize("exc", [requests.Timeout, requests.ConnectionError])
def test_transport_failure(get, exc):
    get.side_effect = exc("transport error")
    assert "failed or timed out" in ripestat.handler(query())["error"]


def test_non_json(get):
    get.return_value = response({})
    get.return_value.json.side_effect = ValueError("invalid")
    assert "invalid JSON" in ripestat.handler(query())["error"]


@pytest.mark.parametrize("status", ["error", "maintenance"])
def test_api_failure_status(get, status):
    get.return_value = response({}, status=status)
    assert "error" in ripestat.handler(query())


@pytest.mark.parametrize("payload", [[], None, {"status": "ok", "data": []}, {"data": {}}])
def test_invalid_response_envelope(get, payload):
    get.return_value = response({})
    get.return_value.json.return_value = payload
    assert "error" in ripestat.handler(query())


@pytest.mark.parametrize(
    "data",
    [
        {"asns": {}, "prefix": "193.0.0.0/21"},
        {"asns": [True], "prefix": "193.0.0.0/21"},
        {"asns": [3333], "prefix": "192.0.2.0/24"},
        {"asns": [3333], "prefix": None},
        {"asns": [3333], "prefix": "2001:db8::/32"},
    ],
)
def test_invalid_network_data(get, data):
    get.return_value = response(data)
    assert "error" in ripestat.handler(query())


@pytest.mark.parametrize(
    "data",
    [
        {"resource": "3334"},
        {"resource": "3333", "holder": []},
        {"resource": "3333", "announced": "false"},
    ],
)
def test_invalid_as_data(get, data):
    get.return_value = response(data)
    assert "error" in ripestat.handler(query("AS", "3333"))


@pytest.mark.parametrize(
    "data",
    [
        {"resource": "192.0.2.0/24", "asns": []},
        {"resource": "193.0.0.0/21", "asns": [3333]},
        {"resource": "193.0.0.0/21", "asns": [{"holder": "unknown"}]},
    ],
)
def test_invalid_prefix_data(get, data):
    get.return_value = response(data)
    assert "error" in ripestat.handler(query("ip-src", "193.0.0.0/21"))


def test_secondary_lookup_error_returns_no_partial_results(get):
    get.side_effect = [response({"asns": [3333, 3334], "prefix": "193.0.0.0/21"}), overview(), response({}, http=503)]
    result = ripestat.handler(query())
    assert "error" in result
    assert "results" not in result
