import base64
import hashlib
import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import qualys_cve as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {"url": "https://service.example", "username": "test-user", "password": "test-service-secret"}


def query(kind="vulnerability", value="CVE-2025-12345", config=None, data=None):
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


@pytest.mark.parametrize("status", [204])
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


def kb(cve="CVE-2025-12345", score="0"):
    return (
        '<?xml version="1.0"?><!DOCTYPE KNOWLEDGE_BASE_VULN_LIST_OUTPUT SYSTEM'
        ' "https://qualys.example/kb.dtd"><KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE><VULN_LIST><VULN><QID>1234</QID><TITLE>Example'
        " vulnerability</TITLE><CVE_LIST><CVE><ID>"
        + cve
        + "</ID></CVE></CVE_LIST><CVSS_V3><BASE>"
        + score
        + "</BASE></CVSS_V3><DIAGNOSIS>Diagnosis</DIAGNOSIS><SOLUTION>Patch</SOLUTION><SEVERITY_LEVEL>4</SEVERITY_LEVEL></VULN></VULN_LIST></RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>"
    )


def test_qualys_external_doctype_is_ignored_and_vulnerability_is_parsed():
    result, request = handle(xml=kb())
    assert_source(result)
    assert values(objects(result, "vulnerability")[0])["id"] == "CVE-2025-12345"
    assert float(values(objects(result, "vulnerability")[0])["cvss-score"]) == 0
    assert contexts(result)[0]["SOLUTION"] == "Patch"
    assert request.call_count == 1
    assert request.call_args.kwargs["params"]["cve"] == "CVE-2025-12345"
    assert request.call_args.kwargs["auth"] == ("test-user", SECRET)


def test_other_cves_are_not_imported():
    result, _ = handle(xml=kb(cve="CVE-2025-99999"))
    assert_source(result)
    assert not result["results"]["Object"]


def test_qualys_error_xml_is_reported():
    result, _ = handle(
        xml="<SIMPLE_RETURN><RESPONSE><CODE>1905</CODE><TEXT>Bad authentication</TEXT></RESPONSE></SIMPLE_RETURN>"
    )
    assert "error" in result


def test_invalid_cvss_is_reported():
    result, _ = handle(xml=kb(score="11"))
    assert "error" in result


def test_internal_entities_are_rejected():
    result, _ = handle(
        xml=(
            "<!DOCTYPE x [<!ENTITY example"
            ' "expanded">]><KNOWLEDGE_BASE_VULN_LIST_OUTPUT>&example;</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>'
        )
    )
    assert "error" in result


def test_invalid_cve_never_calls_service():
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(value="CVE-injection"))
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


def test_active_v4_knowledgebase_endpoint_is_used():
    result, request = handle(xml=kb())
    assert_source(result)
    assert request.call_args.args[1] == "https://service.example/api/4.0/fo/knowledge_base/vuln/"


def test_missing_endpoint_is_an_error_rather_than_an_empty_lookup():
    with patch.object(module.requests, "request", return_value=response(status=404)):
        result = module.handler(query())
    assert "404" in result["error"]


def test_successful_empty_knowledgebase_is_an_empty_lookup():
    result, _ = handle(
        xml="<KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE><VULN_LIST/></RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>"
    )
    assert_source(result)
    assert not result["results"]["Object"]
