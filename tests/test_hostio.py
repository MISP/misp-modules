import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import hostio as module

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


def test_domain_report_dns_and_context():
    data = {
        "domain": "example.com",
        "dns": {
            "a": ["1.1.1.1"],
            "aaaa": ["2606:4700:4700::1111"],
            "mx": ["10 mail.example.com."],
            "ns": ["ns.example.com."],
        },
        "web": {"rank": 0, "title": "Example"},
        "ipinfo": {},
        "related": {},
    }
    with patch.object(module.requests, "request", return_value=response(data)) as request:
        result = module.handler(query())
    assert_source(result)
    record = values(objects(result, "dns-record")[0])
    assert record["mx-record"] == "mail.example.com"
    assert record["aaaa-record"] == "2606:4700:4700::1111"
    assert json.loads(values(objects(result, "annotation")[0])["text"])["web"]["rank"] == 0
    assert request.call_args.kwargs["headers"]["Authorization"] == "Bearer " + SECRET
    assert request.call_args.args == ("GET", "https://host.io/api/full/example.com")


def test_ip_domain_page_is_bounded_and_marks_more_results():
    with patch.object(
        module.requests,
        "request",
        return_value=response({"ip": "1.1.1.1", "total": 20, "domains": ["example.com", "example.org"]}),
    ) as request:
        result = module.handler(query(kind="ip-dst", value="1.1.1.1", config={"apikey": SECRET, "max_results": 1}))
    assert_source(result)
    assert len(objects(result, "domain-ip")) == 1
    assert len(objects(result, "annotation")) == 1
    assert request.call_count == 1
    assert request.call_args.kwargs["params"] == {"limit": 1, "page": 0}


@pytest.mark.parametrize("status", [404, 204])
def test_no_match(status):
    with patch.object(module.requests, "request", return_value=response(status=status)):
        result = module.handler(query())
    assert_source(result)
    assert not result["results"]["Object"]


@pytest.mark.parametrize("limit,page_size", [(2, 5), (50, 100)])
def test_requested_page_size_is_supported_and_capped_locally(limit, page_size):
    domains = [f"example{i}.com" for i in range(page_size)]
    with patch.object(
        module.requests, "request", return_value=response({"total": page_size + 1, "domains": domains})
    ) as request:
        result = module.handler(query(kind="ip-dst", value="1.1.1.1", config={"apikey": SECRET, "max_results": limit}))
    assert_source(result)
    assert request.call_args.kwargs["params"]["limit"] == page_size
    assert len(objects(result, "domain-ip")) == limit
    assert objects(result, "annotation")
