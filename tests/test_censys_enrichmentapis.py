import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import censys_enrichmentapis as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"


def query(kind=None, value="example.com", config=None, **attribute_fields):
    attribute = {
        "type": kind or module.mispattributes["input"][0],
        "value": value,
        "uuid": UUID,
        "to_ids": True,
        "comment": "source context",
        **attribute_fields,
    }
    return json.dumps(
        {"attribute": attribute, "config": config if config is not None else {k: SECRET for k in module.REQUIRED}}
    )


def reply(payload=None, status=200):
    return Mock(status_code=status, headers={}, json=Mock(return_value=payload))


def assert_source(result):
    assert "results" in result, result
    source = next(a for a in result["results"]["Attribute"] if a["uuid"] == UUID)
    assert source["to_ids"] is True
    assert source["comment"] == "source context"
    for obj in result["results"]["Object"]:
        assert any(r["referenced_uuid"] == UUID for r in obj["ObjectReference"])
        assert all(a["to_ids"] is False for a in obj["Attribute"])


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj, relation):
    return [a["value"] for a in obj["Attribute"] if a["object_relation"] == relation]


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(raw):
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(raw)
    request.assert_not_called()


@pytest.mark.parametrize("status", [301, 401, 403, 429, 503])
def test_http_errors_are_sanitized(status):
    with patch.object(module.requests, "request", return_value=reply({"error": SECRET}, status)):
        with pytest.raises(module.ModuleError) as failure:
            module._call("GET", "https://service.example/report")
    assert str(status) in str(failure.value)
    assert SECRET not in str(failure.value)


def test_timeout_is_bounded_and_sanitized():
    with patch.object(module.requests, "request", side_effect=requests.Timeout(SECRET)) as request:
        with pytest.raises(module.ModuleError) as failure:
            module._call("POST", "https://service.example/submit")
    assert SECRET not in str(failure.value)
    assert request.call_count == 1
    assert request.call_args.kwargs["verify"] is True
    assert request.call_args.kwargs["allow_redirects"] is False
    assert request.call_args.kwargs["timeout"] == (5, 30)


@pytest.mark.parametrize("raw", [0, -1, True, "bad", 101])
def test_invalid_result_limit(raw):
    with pytest.raises(module.ModuleError):
        module._integer({"max_results": raw}, "max_results", 25)


def test_host_uses_enrichment_endpoint_and_organization():
    data = {
        "result": {"resource": {"ip": "192.0.2.1", "services": [{"port": 443, "transport_protocol": "TCP"}], "risk": 0}}
    }
    with patch.object(module.requests, "request", return_value=reply(data)) as request:
        result = module.handler(query(kind="ip-dst", value="192.0.2.1"))
    assert_source(result)
    assert request.call_args.args == ("GET", "https://api.platform.censys.io/v3/global/asset/enrichment/host/192.0.2.1")
    assert request.call_args.kwargs["params"] == {"organization_id": SECRET}
    assert values(objects(result, "network-connection")[0], "dst-port") == ["443"]


def test_domain_requests_two_web_properties_and_keeps_partial_results():
    with patch.object(
        module.requests,
        "request",
        side_effect=[reply(status=404), reply({"result": {"resource": {"hostname": "example.com"}}})],
    ) as request:
        result = module.handler(query(kind="domain"))
    assert_source(result)
    assert request.call_count == 2
    assert request.call_args.args[1].endswith("webproperty/example.com%3A443")
    assert len(objects(result, "annotation")) == 1


def test_ip_source_direction_is_preserved():
    with patch.object(
        module.requests, "request", return_value=reply({"result": {"resource": {"services": [{"port": 443}]}}})
    ):
        result = module.handler(query(kind="ip-src", value="192.0.2.1"))
    assert values(objects(result, "network-connection")[0], "ip-src") == ["192.0.2.1"]
