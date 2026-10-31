import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import lastinfosec as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {"apikey": "test-service-secret"}
KIND, VALUE = ("domain", "example.com")


def query(kind=KIND, value=VALUE, config=None, data=None):
    attribute = {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source context"}
    if data is not None:
        attribute["data"] = data
    return json.dumps({"attribute": attribute, "config": CONFIG if config is None else config})


def response(payload=None, status=200):
    result = Mock(status_code=status, headers={})
    result.json.return_value = payload
    return result


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def assert_source(result):
    assert "results" in result, result
    original = next(a for a in result["results"]["Attribute"] if a["uuid"] == UUID)
    assert original["to_ids"] is True
    assert original["comment"] == "source context"
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False for a in obj["Attribute"])
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(raw):
    assert "error" in module.handler(raw)


@pytest.mark.parametrize("value", ["", "  ", 5, []])
def test_invalid_value(value):
    assert "error" in module.handler(query(value=value))


def test_unsupported_type():
    assert "error" in module.handler(query(kind="comment"))


@pytest.mark.parametrize("status", [301, 401, 403, 429, 500])
def test_service_errors_are_redacted(status):
    with patch.object(module.requests, "request", return_value=response({"error": SECRET}, status)) as request:
        result = module.handler(query())
    assert str(status) in result["error"]
    assert SECRET not in str(result)
    for call in request.call_args_list:
        assert call.kwargs["verify"] is True
        assert call.kwargs["allow_redirects"] is False
        assert call.kwargs["timeout"] == 30


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_transport_errors_are_redacted(failure):
    with patch.object(module.requests, "request", side_effect=failure(SECRET)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in str(result)


def test_invalid_json_is_redacted():
    reply = response()
    reply.json.side_effect = ValueError(SECRET)
    with patch.object(module.requests, "request", return_value=reply):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in str(result)


def test_missing_configuration_never_calls_service():
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(config={}))
    request.assert_not_called()


def bundle(domain):
    return {
        "type": "bundle",
        "id": "bundle--5cf34a6a-7d92-4b54-930c-7cf14770b333",
        "objects": [
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": "observed-data--3fa21376-13b5-4dc5-a18d-830ab773f1af",
                "created": "2025-01-01T00:00:00Z",
                "modified": "2025-01-01T00:00:00Z",
                "first_observed": "2025-01-01T00:00:00Z",
                "last_observed": "2025-01-01T00:00:00Z",
                "number_observed": 1,
                "object_refs": ["domain-name--8460557f-2f52-461d-a195-14cc3bc34a7e"],
            },
            {
                "type": "domain-name",
                "spec_version": "2.1",
                "id": "domain-name--8460557f-2f52-461d-a195-14cc3bc34a7e",
                "value": domain,
            },
        ],
    }


def test_post_contract_and_conversion():
    with patch.object(
        module.requests, "request", return_value=response({"message": [bundle("example.org")]})
    ) as request:
        result = module.handler(query())
    assert_source(result)
    assert request.call_args.args == ("POST", "https://api.client.lastinfosec.com/v2/stix21/search/")
    assert request.call_args.kwargs["json"] == {"value": "example.com"}
    assert request.call_args.kwargs["params"] == {"api_key": SECRET, "platform": "misp"}
    assert any(a["value"] == "example.org" and a["to_ids"] is False for a in result["results"]["Attribute"])


def test_all_bundles_converted():
    second = bundle("example.net")
    second["id"] = "bundle--c19f87c3-c005-4327-83cb-e37ed32227a2"
    second["objects"][0]["id"] = "observed-data--c19f87c3-c005-4327-83cb-e37ed32227a2"
    second["objects"][0]["object_refs"] = ["domain-name--c19f87c3-c005-4327-83cb-e37ed32227a2"]
    second["objects"][1]["id"] = "domain-name--c19f87c3-c005-4327-83cb-e37ed32227a2"
    with patch.object(module.requests, "request", return_value=response({"message": [bundle("example.org"), second]})):
        result = module.handler(query())
    assert_source(result)
    assert {a["value"] for a in result["results"]["Attribute"]} >= {"example.org", "example.net"}


@pytest.mark.parametrize("status", [404, 422])
def test_no_match(status):
    with patch.object(module.requests, "request", return_value=response(status=status)):
        result = module.handler(query())
    assert_source(result)
    assert not result["results"]["Object"]


def test_partial_bundle_keeps_supported_data_and_markings():
    from stix2 import TLP_AMBER, Bundle, IPv4Address, ObservedData

    address = IPv4Address(value="8.8.8.8")
    observation = ObservedData(
        first_observed="2025-01-01T00:00:00Z",
        last_observed="2025-01-02T00:00:00Z",
        number_observed=1,
        object_refs=[address.id],
        object_marking_refs=[TLP_AMBER.id],
    )
    data = json.loads(Bundle(address, observation, TLP_AMBER).serialize())
    data["objects"].append(
        {
            "type": "x-example-optional",
            "spec_version": "2.1",
            "id": "x-example-optional--a087b5de-68cc-4a94-bb22-a9c99b6fb0e6",
            "created": "2025-01-01T00:00:00Z",
            "modified": "2025-01-01T00:00:00Z",
            "name": "optional",
        }
    )
    with patch.object(module.requests, "request", return_value=response({"message": [data]})):
        result = module.handler(query())
    assert_source(result)
    imported = next(a for a in result["results"]["Attribute"] if a["value"] == "8.8.8.8")
    assert imported["to_ids"] is False
    assert any(a["type"] == "text" and "partial" in a["value"] for a in result["results"]["Attribute"])
    tags = imported.get("Tag", []) + result["results"].get("Tag", [])
    assert any(tag["name"] == "tlp:amber" for tag in tags)


def test_invalid_sibling_bundle_keeps_valid_results():
    with patch.object(
        module.requests, "request", return_value=response({"message": [bundle("example.org"), {"type": "invalid"}]})
    ):
        result = module.handler(query())
    assert_source(result)
    assert any(a["value"] == "example.org" for a in result["results"]["Attribute"])
    assert any("failed_bundles" in values(obj)["text"] for obj in objects(result, "annotation"))
