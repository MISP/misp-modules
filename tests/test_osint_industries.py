import base64
import hashlib
import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import osint_industries as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {"apikey": "test-service-secret"}


def query(kind="email-src", value="test@example.com", config=None, data=None):
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


def account(registered=True):
    return {
        "module": "example",
        "spec_format": {
            "registered": {"value": registered},
            "username": {"value": "alice"},
            "id": {"value": "42"},
            "profile_url": {"value": "https://example.com/alice"},
        },
    }


def test_exact_nonpremium_post_creates_account_and_keeps_provenance():
    result, request = handle([account()])
    assert_source(result)
    assert values(objects(result, "user-account")[0])["username"] == "alice"
    assert values(objects(result, "user-account")[0])["user-id"] == "42"
    assert contexts(result)[0]["module"] == "example"
    assert request.call_args.args == ("POST", "https://api.osint.industries/v2/request")
    body = request.call_args.kwargs["json"]
    assert body["type"] == "email" and body["query"] == "test@example.com"
    assert body["exact_match"] is True and body["premium"] is False


def test_unregistered_account_remains_context_without_a_profile_object():
    result, _ = handle([account(False)])
    assert not objects(result, "user-account")
    assert len(objects(result, "annotation")) == 1
    assert len(result["results"]["Attribute"]) == 1


@pytest.mark.parametrize(
    "kind,value,selector",
    [
        ("phone-number", "+33123456789", "phone"),
        ("github-username", "alice", "username"),
        ("btc", "1ExampleWallet", "wallet"),
    ],
)
def test_selectors(kind, value, selector):
    result, request = handle([], kind=kind, value=value)
    assert_source(result)
    assert request.call_args.kwargs["json"]["type"] == selector


@pytest.mark.parametrize("kind,value", [("email-src", "invalid"), ("phone-number", "abcd")])
def test_invalid_identity_never_calls_service(kind, value):
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(kind=kind, value=value))
    request.assert_not_called()


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


def test_lookup_timeout_meets_the_live_api_minimum():
    _, request = handle([])
    assert request.call_args.kwargs["json"]["timeout"] == 25
    assert request.call_args.kwargs["timeout"] > request.call_args.kwargs["json"]["timeout"]


def test_live_typed_field_array_creates_account_and_profile_pivots():
    row = {
        "module": "example",
        "spec_format": [
            {"key": "registered", "type": "bool", "value": True},
            {"key": "username", "type": "str", "value": "alice"},
            {"key": "id", "type": "str", "value": "42"},
            {"key": "profile_url", "type": "str", "value": "https://example.com/alice"},
        ],
    }
    result, _ = handle([row])
    assert_source(result)
    assert values(objects(result, "user-account")[0])["username"] == "alice"
    assert any(item["value"] == "https://example.com/alice" for item in result["results"]["Attribute"])
    assert contexts(result)[0] == row


def test_normalized_data_is_accepted_and_takes_precedence():
    row = {
        "module": "example",
        "spec_format": [{"name": "Username", "value": "masked"}],
        "data": {"registered": True, "username": "alice", "user_id": "42", "profile_url": "https://example.com/alice"},
    }
    result, _ = handle([row])
    assert values(objects(result, "user-account")[0])["username"] == "alice"
    assert values(objects(result, "user-account")[0])["user-id"] == "42"


def test_normalized_data_without_spec_format_is_supported():
    result, _ = handle([{"module": "example", "data": {"registered": False, "username": "alice"}}])
    assert_source(result)
    assert not objects(result, "user-account")


def test_false_registration_in_typed_fields_does_not_create_an_account():
    result, _ = handle(
        [
            {
                "module": "example",
                "spec_format": [{"name": "Registered", "value": "false"}, {"name": "Username", "value": "alice"}],
            }
        ]
    )
    assert not objects(result, "user-account")
