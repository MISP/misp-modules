import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import eset_report as module

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


@pytest.mark.parametrize("raw", [0, -1, True, "bad", 101])
def test_invalid_result_limit(raw):
    with pytest.raises(module.ModuleError):
        module._integer({"max_results": raw}, "max_results", 25)


def test_pdf_is_streamed_and_becomes_a_file_attachment():
    response = Mock(status_code=200)
    response.iter_content.return_value = [b"%PDF-1.7\nreport"]
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    with patch.object(module.requests, "get", return_value=response) as request:
        result = module.handler(
            query(kind="link", value="https://eti.eset.com/reports/apt/123e4567-e89b-12d3-a456-426614174000/download")
        )
    assert_source(result)
    obj = objects(result, "file")[0]
    assert values(obj, "filename") == ["123e4567-e89b-12d3-a456-426614174000.pdf"]
    assert any(a.get("data") for a in obj["Attribute"])
    assert request.call_args.kwargs["allow_redirects"] is False


@pytest.mark.parametrize(
    "url",
    [
        "https://other.example/reports/apt/123e4567-e89b-12d3-a456-426614174000/download",
        "https://eti.eset.com@other.example/reports/apt/x/download",
        "https://eti.eset.com:8443/reports/apt/x/download",
    ],
)
def test_foreign_urls_are_rejected_without_authentication(url):
    with patch.object(module.requests, "get") as request:
        assert "error" in module.handler(query(kind="link", value=url))
    request.assert_not_called()


def test_portal_reference_uses_fixed_api_download_endpoint():
    response = Mock(status_code=200)
    response.iter_content.return_value = [b"%PDF-1.7\nreport"]
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    with patch.object(module.requests, "get", return_value=response) as request:
        result = module.handler(
            query(kind="link", value="https://www.eset.com/reports/apt/123e4567-e89b-12d3-a456-426614174000/download")
        )
    assert_source(result)
    assert (
        request.call_args.args[0]
        == "https://eti.eset.com/api/v2/apt-reports/123e4567-e89b-12d3-a456-426614174000/download/pdf"
    )
    assert request.call_args.kwargs["headers"]["Authorization"] == "Bearer " + SECRET


@pytest.mark.parametrize("chunks", [[b"<html>login</html>"], [b"%PDF-" + b"x" * 1048576]])
def test_non_pdf_and_oversized_reports_are_rejected(chunks):
    response = Mock(status_code=200)
    response.iter_content.return_value = chunks
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    with patch.object(module.requests, "get", return_value=response):
        result = module.handler(
            query(
                kind="link",
                value="https://eti.eset.com/reports/apt/123e4567-e89b-12d3-a456-426614174000/download",
                config={"api_token": SECRET, "max_size_mb": 1},
            )
        )
    assert "error" in result


def test_download_failure_does_not_expose_credentials():
    with patch.object(module.requests, "get", side_effect=requests.Timeout(SECRET)):
        result = module.handler(
            query(kind="link", value="https://eti.eset.com/reports/apt/123e4567-e89b-12d3-a456-426614174000/download")
        )
    assert "error" in result and SECRET not in str(result)


def test_documented_portal_link_and_complete_token():
    response = Mock(status_code=200)
    response.iter_content.return_value = [b"%PDF-1.7"]
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    with patch.object(module.requests, "get", return_value=response) as request:
        result = module.handler(
            query(
                kind="link",
                value="https://eti.eset.com/reports/apt/download/123e4567-e89b-12d3-a456-426614174000",
                config={"api_token": "whole|token"},
            )
        )
    assert_source(result)
    assert request.call_args.kwargs["headers"]["Authorization"] == "Bearer whole|token"
