import base64
import hashlib
import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import malbeacon as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {"apikey": "test-service-secret"}


def query(kind="domain", value="example.com", config=None, data=None):
    attribute = {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "original context"}
    if data is not None:
        attribute["data"] = data
    return json.dumps({"attribute": attribute, "config": CONFIG if config is None else config})


def response(payload=None, status=200, xml=None, content=None):
    result = Mock(status_code=status, headers={})
    result.json.return_value = payload
    result.content = (
        content if content is not None else xml.encode() if xml is not None else json.dumps(payload).encode()
    )
    return result


def handle(payload=None, xml=None, **kwargs):
    with patch.object(module.requests, "request", return_value=response(payload, xml=xml)) as request:
        result = module.handler(query(**kwargs))
    return result, request


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {item["object_relation"]: item["value"] for item in obj["Attribute"]}


def contexts(result):
    return [json.loads(values(obj)["text"]) for obj in objects(result, "annotation")]


def assert_source(result):
    source = next(item for item in result["results"]["Attribute"] if item["uuid"] == UUID)
    assert source["to_ids"] is True
    assert source["comment"] == "original context"
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
    "raw", ["{", "[]", "null", "{}", '{"attribute":[]}', '{"attribute":{"type":"ip-src","value":"1.1.1.1"}}']
)
def test_invalid_request_never_calls_service(raw):
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(raw)
    request.assert_not_called()


@pytest.mark.parametrize("value", ["", "  ", 5, ["example.com"]])
def test_invalid_value_never_calls_service(value):
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(value=value))
    request.assert_not_called()


def test_unsupported_type_never_calls_service():
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(kind="comment"))
    request.assert_not_called()


def test_missing_config_never_calls_service():
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(config={}))
    request.assert_not_called()


@pytest.mark.parametrize("status", [401, 403, 429, 500, 302])
def test_http_errors_are_actionable_and_redacted(status):
    with patch.object(module.requests, "request", return_value=response({"error": SECRET}, status=status)):
        result = module.handler(query())
    assert str(status) in result["error"]
    assert SECRET not in result["error"]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_connection_failures_are_redacted(failure):
    with patch.object(module.requests, "request", side_effect=failure("credentials=" + SECRET)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("status", [404, 204])
def test_empty_lookup_preserves_source(status):
    with patch.object(module.requests, "request", return_value=response(status=status)):
        result = module.handler(query())
    assert_source(result)
    assert not result["results"]["Object"]


def test_malformed_service_body_is_reported():
    reply = response(content=b"not-valid-xml")
    reply.json.side_effect = ValueError(SECRET)
    with patch.object(module.requests, "request", return_value=reply):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


def test_beacon_context_and_deduplicated_infrastructure():
    row = {
        "actorip": "1.1.1.1",
        "actorhostname": "actor.example",
        "c2domain": "c2.example",
        "c2hostname": "NA",
        "tstamp": "2025-01-02 03:04:05",
        "tags": "example,beacon",
    }
    result, request = handle([row, row])
    assert_source(result)
    assert contexts(result)[0]["tstamp"] == row["tstamp"]
    assert len(objects(result, "annotation")) == 2
    assert len(result["results"]["Attribute"]) == 4
    assert request.call_args.args == ("GET", "https://api.malbeacon.com/v1/c2/c2/example.com")
    assert request.call_args.kwargs["headers"] == {"X-Api-Key": SECRET}


def test_limit_is_reported_and_ipv6_is_encoded():
    result, request = handle(
        [{"actorip": "NA"}, {"actorip": "NA"}], kind="ip-src", value="2001:db8::1", config=dict(CONFIG, max_results=1)
    )
    assert len(objects(result, "annotation")) == 2
    assert request.call_args.args[1].endswith("2001%3Adb8%3A%3A1")


def test_service_message_is_not_imported_as_beacon():
    result, _ = handle({"message": SECRET})
    assert "error" in result
    assert SECRET not in result["error"]


def test_transport_is_bounded_and_credentials_are_absent_from_url():
    with patch.object(module.requests, "request", return_value=response(status=404)) as request:
        module.handler(query())
    assert request.call_count >= 1
    for call in request.call_args_list:
        assert SECRET not in call.args[1]
        assert call.kwargs["timeout"] == 30
        assert call.kwargs["verify"] is True
        assert call.kwargs["allow_redirects"] is False
        assert SECRET not in json.dumps(call.kwargs.get("params", {}))


@pytest.mark.parametrize(
    "value,kind", [("185.70.186.153", "ip-dst"), ("2001:db8::1", "ip-dst"), ("C2.EXAMPLE.COM.", "domain")]
)
def test_c2_values_keep_their_actual_indicator_type(value, kind):
    result, _ = handle([{"c2domain": value}])
    assert_source(result)
    added = [item for item in result["results"]["Attribute"] if item["uuid"] != UUID]
    assert [(item["type"], item["value"]) for item in added] == [(kind, value.lower().rstrip("."))]


def test_ip_c2_deduplicates_with_the_correct_type():
    result, _ = handle([{"c2domain": "185.70.186.153"}, {"c2domain": "185.70.186.153", "actorip": "1.1.1.1"}])
    added = [item for item in result["results"]["Attribute"] if item["uuid"] != UUID]
    assert [(item["type"], item["value"]) for item in added] == [("ip-dst", "185.70.186.153"), ("ip-src", "1.1.1.1")]
