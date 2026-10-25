import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import team_cymru_scout_search as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"


def query(kind="text", value="port:443", config=None):
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


def stix_bundle():
    from stix2 import TLP_AMBER, Bundle, IPv4Address, ObservedData

    address = IPv4Address(value="8.8.8.8")
    observation = ObservedData(
        first_observed="2025-01-01T00:00:00Z",
        last_observed="2025-01-02T00:00:00Z",
        number_observed=2,
        object_refs=[address.id],
        object_marking_refs=[TLP_AMBER.id],
    )
    return json.loads(Bundle(address, observation, TLP_AMBER).serialize())


def test_stix_intelligence_conversion_preserves_markings():
    result, get = handle(stix_bundle())
    assert_source(result)
    attributes = result["results"]["Attribute"]
    found = next(x for x in attributes if x["value"] == "8.8.8.8")
    tags = found.get("Tag", []) + result["results"].get("Tag", [])
    assert any(x["name"] == "tlp:amber" for x in tags)
    assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer " + SECRET
    assert get.call_args.kwargs["timeout"] == 30


def test_malformed_stix_is_rejected_without_crashing():
    result, _ = handle({"type": "bundle", "objects": [{"type": "ipv4-addr", "id": "bad", "value": "bad"}]})
    assert "error" in result


def test_empty_bundle_preserves_source():
    result, _ = handle({"type": "bundle", "objects": []})
    assert_source(result)
    assert result["results"]["Object"] == []


def test_query_is_forwarded_as_an_explicit_search():
    text = "port:443 AND country:FR"
    result, get = handle({}, value=text, config={"apikey": SECRET, "days": "30"})
    assert_source(result)
    assert get.call_args.args[0] == "https://taxii.cymru.com/api/scout/search"
    assert get.call_args.kwargs["params"] == {"query": text, "days": 30}


@pytest.mark.parametrize("days", [0, -1, "abc", True, 91])
def test_invalid_search_window_never_calls_service(days):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(config={"apikey": SECRET, "days": days}))
    get.assert_not_called()


def extension_definition():
    return (
        {
            "type": "x-example-optional",
            "spec_version": "2.1",
            "id": "x-example-optional--a087b5de-68cc-4a94-bb22-a9c99b6fb0e6",
            "created": "2025-01-01T00:00:00Z",
            "modified": "2025-01-01T00:00:00Z",
            "name": "Example optional intelligence",
        },
    )


def test_optional_unsupported_stix_does_not_discard_supported_intelligence():
    bundle = stix_bundle()
    bundle["objects"].extend(extension_definition())
    result, _ = handle(bundle)
    assert_source(result)
    assert any(item["value"] == "8.8.8.8" for item in result["results"]["Attribute"])
    assert any(item["type"] == "text" and "partial" in item["value"] for item in result["results"]["Attribute"])
    tags = result["results"].get("Tag", [])
    tags += [tag for item in result["results"]["Attribute"] for tag in item.get("Tag", [])]
    assert any(tag["name"] == "tlp:amber" for tag in tags)


def test_bundle_with_only_unsupported_intelligence_reports_an_error():
    from stix2 import Bundle

    bundle = json.loads(Bundle().serialize())
    bundle["objects"] = list(extension_definition())
    result, _ = handle(bundle)
    assert "error" in result
