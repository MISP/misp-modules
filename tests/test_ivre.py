import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import ivre as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {"url": "https://ivre.example/cgi/view"}
KIND, VALUE = ("ip-dst", "1.1.1.1")


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


def test_structured_filter_and_open_ports_only():
    row = {
        "addr": "1.1.1.1",
        "hostnames": [{"name": "example.com", "domains": ["example.com"]}],
        "ports": [
            {"port": 443, "protocol": "tcp", "state_state": "open", "service_name": "https"},
            {"port": 22, "protocol": "tcp", "state_state": "closed"},
        ],
        "infos": {"as_num": 13335},
        "starttime": "2025-01-01T00:00:00",
    }
    with patch.object(module.requests, "request", return_value=response([row])) as request:
        result = module.handler(query())
    assert_source(result)
    assert values(objects(result, "ip-port")[0])["dst-port"] == "443"
    assert values(objects(result, "ip-port")[0])["protocol"] == "tcp"
    assert len(objects(result, "ip-port")) == 1
    assert json.loads(request.call_args.kwargs["params"]["f"]) == {"f": "host", "a": ["1.1.1.1"]}
    assert request.call_args.kwargs["params"]["q"] == "limit:26"


def test_domain_filter_no_query_injection():
    with patch.object(module.requests, "request", return_value=response([])) as request:
        result = module.handler(query(kind="domain", value="example.com"))
    assert_source(result)
    assert json.loads(request.call_args.kwargs["params"]["f"]) == {"f": "domain", "a": ["example.com"]}


@pytest.mark.parametrize(
    "url", ["http://ivre.example/cgi/view", "https://user:pass@ivre.example/view", "https://ivre.example/view?query=1"]
)
def test_rejects_invalid_endpoint(url):
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(config={"url": url}))
    request.assert_not_called()


def test_basic_auth_and_no_redirects():
    with patch.object(module.requests, "request", return_value=response([])) as request:
        result = module.handler(query(config=dict(CONFIG, username="user", password=SECRET)))
    assert_source(result)
    assert request.call_args.kwargs["auth"] == ("user", SECRET)


def test_missing_view_endpoint_is_configuration_error():
    with patch.object(module.requests, "request", return_value=response(status=404)):
        result = module.handler(query())
    assert "404" in result["error"]


def test_hostname_uses_exact_hostname_filter():
    with patch.object(module.requests, "request", return_value=response([])) as request:
        result = module.handler(query(kind="hostname", value="host.example.com"))
    assert_source(result)
    assert json.loads(request.call_args.kwargs["params"]["f"]) == {"f": "hostname", "a": ["host.example.com"]}


def test_open_port_zero_preserved_and_pseudo_port_skipped():
    data = [
        {
            "addr": "1.1.1.1",
            "ports": [{"port": 0, "protocol": "tcp", "state_state": "open"}, {"port": -1, "state_state": "open"}],
        }
    ]
    with patch.object(module.requests, "request", return_value=response(data)):
        result = module.handler(query())
    assert_source(result)
    assert len(objects(result, "ip-port")) == 1
    assert values(objects(result, "ip-port")[0])["dst-port"] == "0"
