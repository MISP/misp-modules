import base64
import io
import json
import sys
import zipfile
from unittest.mock import Mock, call

import pytest
from mwdblib.exc import MWDBError
from requests.exceptions import ConnectionError, Timeout

from misp_modules.modules.expansion import mwdb as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SHA256 = "a" * 64
SECRET = "test-mwdb-secret"
DATA = b"MZ sample bytes"


def query(config=None, **overrides):
    request = {
        "attachment": "sample.exe",
        "data": base64.b64encode(DATA).decode(),
        "attribute_uuid": UUID,
        "event_id": "42",
        "config": {"mwdb_apikey": SECRET, "mwdb_url": "https://mwdb.example/api"} | (config or {}),
    }
    request.update(overrides)
    return json.dumps(request)


@pytest.fixture
def service(monkeypatch):
    factory = Mock()
    factory.return_value.upload_file.return_value.id = SHA256
    monkeypatch.setattr(module, "MWDB", factory)
    return factory


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection() == {"input": ["attachment", "malware-sample"], "output": ["link"]}
    assert module.version()["config"] == module.moduleconfig
    assert "config" not in module.moduleinfo


def test_default_upload_succeeds_without_pymisp_configuration(service, monkeypatch):
    keys = Mock(side_effect=AssertionError("keys.py must not be loaded"))
    monkeypatch.setattr(module.runpy, "run_path", keys)
    result = module.handler(query())
    assert result["results"][0]["values"] == f"https://mwdb.example/file/{SHA256}"
    service.return_value.upload_file.assert_called_once_with("sample.exe", DATA, attributes=None, tags=[], public=True)
    service.return_value.upload_file.return_value.add_comment.assert_called_once_with(f"MISP attribute {UUID}")
    assert service.call_args.kwargs["config_path"] is None
    assert service.call_args.kwargs["obey_ratelimiter"] is False


@pytest.mark.parametrize("setting", [False, "false", "False", "no", "OFF", 0, "0"])
def test_false_settings_disable_public_sharing_and_metadata(service, monkeypatch, setting):
    keys = Mock(side_effect=AssertionError("metadata is disabled"))
    monkeypatch.setattr(module.runpy, "run_path", keys)
    result = module.handler(
        query(config={"mwdb_public": setting, "include_tags_event": setting, "include_tags_attribute": setting})
    )
    assert "results" in result
    assert service.return_value.upload_file.call_args.kwargs["public"] is False
    keys.assert_not_called()


@pytest.mark.parametrize("setting", [True, "true", "YES", "on", 1, "1"])
def test_true_public_setting(service, setting):
    assert "results" in module.handler(query(config={"mwdb_public": setting}))
    assert service.return_value.upload_file.call_args.kwargs["public"] is True


@pytest.mark.parametrize("setting", [None, ""])
def test_empty_settings_keep_defaults(service, setting):
    assert "results" in module.handler(query(config={"mwdb_public": setting, "include_tags_event": setting}))
    assert service.return_value.upload_file.call_args.kwargs["public"] is True


@pytest.mark.parametrize("name", ["mwdb_public", "include_tags_event", "include_tags_attribute"])
@pytest.mark.parametrize("setting", ["maybe", [], {}, 2])
def test_invalid_boolean_never_uploads(service, name, setting):
    assert name in module.handler(query(config={name: setting}))["error"]
    service.assert_not_called()


@pytest.mark.parametrize(
    "url,base",
    [
        ("https://mwdb.example", "https://mwdb.example"),
        ("https://mwdb.example/", "https://mwdb.example"),
        ("https://mwdb.example/api/", "https://mwdb.example"),
        ("https://mwdb.example/api", "https://mwdb.example"),
        ("http://localhost:3000/prefix/api/", "http://localhost:3000/prefix"),
        ("https://api.example/api-proxy/api/", "https://api.example/api-proxy"),
    ],
)
def test_url_normalization_preserves_hostname_and_path(service, url, base):
    result = module.handler(query(config={"mwdb_url": url}))
    assert service.call_args.kwargs["api_url"] == base + "/api/"
    assert result["results"][0]["values"] == base + "/file/" + SHA256


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        " ",
        42,
        "mwdb.example/api",
        "ftp://mwdb.example",
        "https:///api",
        "https://user:password@mwdb.example/api",
        "https://mwdb.example/api?key=secret",
        "https://mwdb.example/api#fragment",
        "https://mwdb.example:bad/api",
        "https://mwdb .example/api",
    ],
)
def test_invalid_url_never_uploads(service, url):
    assert "error" in module.handler(query(config={"mwdb_url": url}))
    service.assert_not_called()


@pytest.mark.parametrize("raw", ["{", "[]", "null", "42", "{}", '{"config": []}'])
def test_invalid_request_never_uploads(service, raw):
    assert "error" in module.handler(raw)
    service.assert_not_called()


@pytest.mark.parametrize("value", [None, "", " ", 42])
def test_missing_api_key(service, value):
    assert "API key" in module.handler(query(config={"mwdb_apikey": value}))["error"]
    service.assert_not_called()


@pytest.mark.parametrize(
    "changes",
    [
        {"attachment": ""},
        {"attachment": 42},
        {"data": None},
        {"data": ""},
        {"data": "%%%"},
        {"data": base64.b64encode(b"valid").decode() + "junk!"},
    ],
)
def test_bad_sample_never_uploads(service, changes):
    assert "error" in module.handler(query(**changes))
    service.assert_not_called()


def archive(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zipped:
        for name, contents in members:
            zipped.writestr(name, contents)
    return base64.b64encode(buffer.getvalue()).decode()


def malware_query(data):
    request = json.loads(query(data=data))
    request.pop("attachment")
    request["malware-sample"] = "original.exe|" + "b" * 32
    return json.dumps(request)


def test_malware_archive_skips_filename_metadata_and_directories(service):
    data = archive([("folder/", b""), ("sample.filename.txt", b"original.exe"), ("sample", DATA)])
    assert "results" in module.handler(malware_query(data))
    assert service.return_value.upload_file.call_args.args == ("original.exe", DATA)


@pytest.mark.parametrize("members", [[], [("sample.filename.txt", b"name")], [("one", b"1"), ("two", b"2")]])
def test_ambiguous_or_empty_archives_do_not_upload(service, members):
    assert "error" in module.handler(malware_query(archive(members)))
    service.assert_not_called()


def test_invalid_zip_does_not_upload(service):
    assert "error" in module.handler(malware_query(base64.b64encode(DATA).decode()))
    service.assert_not_called()


def test_corrupt_compressed_payload_does_not_upload(service):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr("sample", DATA)
    data = bytearray(buffer.getvalue())
    start = 30 + int.from_bytes(data[26:28], "little") + int.from_bytes(data[28:30], "little")
    data[start] = 7  # Invalid DEFLATE block type.
    assert "error" in module.handler(malware_query(base64.b64encode(data).decode()))
    service.assert_not_called()


def test_missing_sample_never_uploads(service):
    request = json.loads(query())
    request.pop("attachment")
    assert "error" in module.handler(json.dumps(request))
    service.assert_not_called()


def test_ambiguous_sample_kind_never_uploads(service):
    assert "error" in module.handler(query(**{"malware-sample": "sample.exe|md5"}))
    service.assert_not_called()


def test_modern_mwdb_attribute_uses_string_event_id(service):
    assert "results" in module.handler(query(config={"mwdb_misp_attribute": "misp"}, event_id=42))
    assert service.return_value.upload_file.call_args.kwargs["attributes"] == {"misp": "42"}


@pytest.mark.parametrize("event_id", [None, "", [], False])
def test_back_reference_requires_event_id_before_upload(service, event_id):
    assert "event_id" in module.handler(query(config={"mwdb_misp_attribute": "misp"}, event_id=event_id))["error"]
    service.assert_not_called()


def setup_misp(monkeypatch, tmp_path):
    (tmp_path / "keys.py").write_text(
        "misp_url = 'https://misp.example'\nmisp_key = 'test-misp-key'\nmisp_verifycert = True\n"
    )
    monkeypatch.setattr(module, "pymisp_keys_file", str(tmp_path))
    misp = Mock()
    misp.get_event.return_value = {
        "Event": {
            "info": "Test event",
            "Tag": [{"name": "tlp:amber"}, {"name": "duplicate"}, {"name": "misp-galaxy:malware=example"}],
        }
    }
    misp.get_attribute.return_value = {
        "Attribute": {"comment": "Source comment", "Tag": [{"name": "duplicate"}, {"name": "sample-tag"}]}
    }
    factory = Mock(return_value=misp)
    monkeypatch.setattr(module, "PyMISP", factory)
    return factory, misp


def test_tags_are_deduplicated_and_one_misp_client_is_used(service, monkeypatch, tmp_path):
    factory, misp = setup_misp(monkeypatch, tmp_path)
    before = sys.path.copy()
    result = module.handler(query(config={"include_tags_event": "true", "include_tags_attribute": "true"}))
    assert "results" in result
    factory.assert_called_once_with("https://misp.example", "test-misp-key", True, False)
    misp.get_event.assert_called_once_with("42")
    misp.get_attribute.assert_called_once_with(UUID)
    assert service.return_value.upload_file.call_args.kwargs["tags"] == ["tlp:amber", "duplicate", "sample-tag"]
    assert service.return_value.upload_file.return_value.add_comment.call_args_list == [
        call("Source comment"),
        call("Fetched from event 42 - Test event"),
    ]
    assert sys.path == before


def test_attribute_tags_without_event_tags(service, monkeypatch, tmp_path):
    _, misp = setup_misp(monkeypatch, tmp_path)
    assert "results" in module.handler(query(config={"include_tags_attribute": "yes"}))
    misp.get_event.assert_not_called()
    service.return_value.upload_file.return_value.add_comment.assert_called_once_with("Source comment")


@pytest.mark.parametrize("kind", ["event", "attribute"])
def test_misp_lookup_failure_prevents_upload(service, monkeypatch, tmp_path, kind):
    _, misp = setup_misp(monkeypatch, tmp_path)
    getattr(misp, "get_" + kind).return_value = {"errors": ["Not found"]}
    result = module.handler(query(config={"include_tags_" + kind: True}))
    assert "metadata" in result["error"]
    service.assert_not_called()


def test_missing_keys_file_prevents_upload(service, monkeypatch, tmp_path):
    monkeypatch.setattr(module, "pymisp_keys_file", str(tmp_path))
    assert "keys.py" in module.handler(query(config={"include_tags_event": True}))["error"]
    service.assert_not_called()


def test_invalid_keys_file_prevents_upload(service, monkeypatch, tmp_path):
    (tmp_path / "keys.py").write_text("misp_key = ")
    monkeypatch.setattr(module, "pymisp_keys_file", str(tmp_path))
    assert "keys.py" in module.handler(query(config={"include_tags_event": True}))["error"]
    service.assert_not_called()


@pytest.mark.parametrize("failure", [MWDBError, ConnectionError, Timeout])
def test_upload_failure_does_not_leak_secrets(service, failure):
    service.return_value.upload_file.side_effect = failure(SECRET)
    result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]
    service.return_value.upload_file.return_value.add_comment.assert_not_called()


@pytest.mark.parametrize("failure", [MWDBError, ConnectionError, Timeout])
def test_comment_failure_preserves_uploaded_sample_link(service, failure):
    service.return_value.upload_file.return_value.add_comment.side_effect = failure(SECRET)
    result = module.handler(query())
    assert "error" not in result
    assert result["results"][0]["values"].endswith(SHA256)
    assert "sample uploaded" in result["results"][0]["comment"]
    assert SECRET not in json.dumps(result)
    service.return_value.upload_file.assert_called_once()


def test_errors_are_not_shared_between_requests(service):
    first = module.handler(query(data="%%%"))
    saved = dict(first)
    module.handler(query(config={"mwdb_apikey": ""}))
    assert first == saved
    assert "results" in module.handler(query())


def test_password_protected_misp_archive(service):
    # A tiny ZipCrypto archive encrypted with the standard MISP password "infected".
    encoded = (
        "UEsDBAoACQAAAGuXW13fYY2fGwAAAA8AAAAGABwAc2FtcGxlVVQJAAOJ9OBqifTganV4CwABBOgDAAAE6AMAAJekwG1Vrue8"
        "B5bemihMs5uaRTztDVPkO2D7B1BLBwjfYY2fGwAAAA8AAABQSwECHgMKAAkAAABrl1td32GNnxsAAAAPAAAABgAYAAAAAAAB"
        "AAAAgIEAAAAAc2FtcGxlVVQFAAOJ9OBqdXgLAAEE6AMAAAToAwAAUEsFBgAAAAABAAEATAAAAGsAAAAAAA=="
    )
    assert "results" in module.handler(malware_query(encoded))
    assert service.return_value.upload_file.call_args.args == ("original.exe", DATA)


def test_real_mwdblib_serializes_upload_and_uses_id_without_fetching_md5(monkeypatch, tmp_path):
    import requests

    setup_misp(monkeypatch, tmp_path)

    def respond(method, url, **kwargs):
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({"id": SHA256}).encode()
        return response

    request = Mock(side_effect=respond)
    monkeypatch.setattr(requests.Session, "request", request)
    result = module.handler(
        query(
            config={
                "mwdb_apikey": "e30.eyJsb2dpbiI6InRlc3QifQ.signature",
                "mwdb_public": "false",
                "mwdb_misp_attribute": "misp",
                "include_tags_event": True,
            }
        )
    )
    assert result["results"][0]["values"] == f"https://mwdb.example/file/{SHA256}"
    upload = request.call_args_list[0]
    assert upload.args == ("post", "https://mwdb.example/api/file")
    assert upload.kwargs["files"]["file"] == ("sample.exe", DATA)
    options = json.loads(upload.kwargs["files"]["options"][1])
    assert options["upload_as"] == "*"
    assert options["attributes"] == [{"key": "misp", "value": "42"}]
    assert options["tags"] == [{"tag": "tlp:amber"}, {"tag": "duplicate"}]
    assert all(item.args[0] == "post" for item in request.call_args_list)
    assert len(request.call_args_list) == 3  # Upload plus two comments; no lazy hash lookup.
