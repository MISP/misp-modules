import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import kaspersky as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {"apikey": "test-service-secret"}
KIND, VALUE = ("sha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


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


def test_hash_report_preserves_size_zero_and_zone():
    data = {
        "LicenseInfo": {"LicenseExpired": False},
        "Zone": "Green",
        "FileGeneralInfo": {"Sha256": "a" * 64, "Md5": "b" * 32, "Size": 0, "Type": "PE"},
        "FileNames": [{"FileName": "example.exe"}],
        "DetectionsInfo": [],
    }
    with patch.object(module.requests, "request", return_value=response(data)) as request:
        result = module.handler(query())
    assert_source(result)
    assert values(objects(result, "file")[0])["size-in-bytes"] == "0"
    assert values(objects(result, "file")[1])["filename"] == "example.exe"
    assert json.loads(values(objects(result, "annotation")[0])["text"])["Zone"] == "Green"
    assert request.call_args.kwargs["headers"]["Authorization"] == "Bearer " + SECRET
    assert request.call_args.args[1].endswith("/api/hash/" + "a" * 64)


def test_domain_dns_resolutions():
    data = {"LicenseInfo": {}, "Zone": "Grey", "DomainGeneralInfo": {}, "DomainDnsResolutions": [{"Ip": "1.1.1.1"}]}
    with patch.object(module.requests, "request", return_value=response(data)):
        result = module.handler(query(kind="domain", value="example.com"))
    assert_source(result)
    assert values(objects(result, "domain-ip")[0])["ip"] == "1.1.1.1"


def test_url_is_encoded_as_single_path_value():
    with patch.object(
        module.requests, "request", return_value=response({"UrlGeneralInfo": {}, "LicenseInfo": {}})
    ) as request:
        result = module.handler(query(kind="url", value="https://example.com/a?x=1&y=2"))
    assert_source(result)
    assert request.call_args.args[1].endswith("/api/url/https%3A%2F%2Fexample.com%2Fa%3Fx%3D1%26y%3D2")


def test_mismatched_hash_rejected():
    with patch.object(module.requests, "request", return_value=response({"FileGeneralInfo": {"Sha256": "b" * 64}})):
        assert "error" in module.handler(query())


@pytest.mark.parametrize("name_field", ["FileName", "FileNames"])
def test_filename_response_variants(name_field):
    payload = {"FileGeneralInfo": {"Sha256": "a" * 64}, "FileNames": [{name_field: "sample.exe"}]}
    with patch.object(module.requests, "request", return_value=response(payload)):
        result = module.handler(query())
    assert_source(result)
    assert any(values(obj).get("filename") == "sample.exe" for obj in objects(result, "file"))


def test_url_downloaded_files_are_typed_and_bounded():
    payload = {"UrlGeneralInfo": {}, "FilesDownloaded": [{"Md5": "a" * 32, "Size": 0}, {"Md5": "b" * 32}]}
    with patch.object(module.requests, "request", return_value=response(payload)):
        result = module.handler(
            query(kind="url", value="https://example.com", config={"apikey": SECRET, "max_results": 1})
        )
    assert_source(result)
    assert len(objects(result, "file")) == 1
    assert values(objects(result, "file")[0])["md5"] == "a" * 32
    assert values(objects(result, "file")[0])["size-in-bytes"] == "0"
    assert len(objects(result, "annotation")) == 2
