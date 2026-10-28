import base64
import io
import json
import zipfile
from email import policy
from email.parser import BytesParser
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from misp_modules.modules.expansion import pandora_submit as module

DATA = b"MZ sample bytes"
TASK = "32876e4a-916d-4935-9e51-7b69a76718f8"
SEED = "access-seed"
SECRET = "test-pandora-secret"


def query(config=None, **changes):
    request = {"attachment": "sample.exe", "data": base64.b64encode(DATA).decode()}
    if config is not None:
        request["config"] = config
    request.update(changes)
    return json.dumps(request)


@pytest.fixture
def service(monkeypatch):
    response = Mock(status_code=200)
    response.json.return_value = {"success": True, "taskId": TASK, "seed": SEED}
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    post = Mock(return_value=response)
    monkeypatch.setattr(module.requests, "post", post)
    return post


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection() == {"input": ["attachment", "malware-sample"], "output": ["link"]}
    assert module.version()["module-type"] == ["expansion"]
    assert module.version()["config"] == module.moduleconfig
    assert "config" not in module.moduleinfo


@pytest.mark.parametrize("config", [None, {}, {"url": "", "apikey": "", "timeout": "", "validity": ""}])
def test_default_instance_without_configuration(service, config):
    result = module.handler(query(config))
    assert result["results"][0]["values"] == f"https://pandora.circl.lu/analysis/{TASK}/seed-{SEED}"
    service.assert_called_once_with(
        "https://pandora.circl.lu/submit",
        files={"file": ("sample.exe", DATA)},
        params={"validity": 0},
        headers={},
        timeout=30,
        allow_redirects=False,
    )
    service.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "url", ["https://pandora.example", "https://pandora.example/", "http://localhost:8080/prefix/"]
)
def test_custom_instance_authentication_and_options(service, url):
    result = module.handler(
        query({"url": url, "apikey": SECRET, "timeout": "60", "validity": "3600", "password": "archive-password"})
    )
    assert result["results"][0]["values"] == f"{url.rstrip('/')}/analysis/{TASK}/seed-{SEED}"
    assert service.call_args.args == (url.rstrip("/") + "/submit",)
    options = service.call_args.kwargs
    assert options["headers"] == {"Authorization": SECRET}
    assert options["params"] == {"validity": 3600, "password": "archive-password"}
    assert "data" not in options
    assert options["timeout"] == 60
    assert "verify" not in options  # requests keeps certificate verification enabled.


@pytest.mark.parametrize(
    "url",
    [
        " ",
        42,
        "pandora.example",
        "ftp://pandora.example",
        "https:///",
        "https://user:pass@pandora.example",
        "https://pandora.example?key=secret",
        "https://pandora.example#fragment",
        "https://pandora.example:bad",
        "https://pandora.example:0",
        "https://pandora .example",
        "https://pandora.example\\evil",
        "https://[bad",
    ],
)
def test_invalid_url_never_submits(service, url):
    assert "error" in module.handler(query({"url": url}))
    service.assert_not_called()


@pytest.mark.parametrize("raw", ["{", "[]", "null", "42", "{}", '{"config": []}', '{"config": null}'])
def test_invalid_request_never_submits(service, raw):
    assert "error" in module.handler(raw)
    service.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": "1.5"},
        {"timeout": 1.5},
        {"timeout": True},
        {"validity": -1},
        {"validity": "bad"},
        {"validity": []},
        {"validity": False},
        {"apikey": 42},
        {"apikey": "key\r\nheader"},
        {"password": ["bad"]},
    ],
)
def test_invalid_configuration_never_submits(service, config):
    assert "error" in module.handler(query(config))
    service.assert_not_called()


@pytest.mark.parametrize(
    "changes",
    [
        {"attachment": ""},
        {"attachment": 42},
        {"data": None},
        {"data": ""},
        {"data": "%%%"},
        {"data": "é"},
        {"data": base64.b64encode(b" \n").decode()},
        {"malware-sample": "sample.exe|md5"},
    ],
)
def test_invalid_sample_never_submits(service, changes):
    assert "error" in module.handler(query(**changes))
    service.assert_not_called()


def archive(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zipped:
        for name, contents in members:
            zipped.writestr(name, contents)
    return base64.b64encode(buffer.getvalue()).decode()


def malware_query(data, filename="original.exe"):
    return json.dumps({"malware-sample": filename + "|" + "b" * 32, "data": data})


@pytest.mark.parametrize("filename", ["original.exe", "archive|sample.exe", "archive|nested|sample.exe"])
def test_malware_archive_preserves_filename_and_skips_metadata(service, filename):
    data = archive([("folder/", b""), ("sample.filename.txt", filename.encode()), ("sample", DATA)])
    assert "results" in module.handler(malware_query(data, filename))
    assert service.call_args.kwargs["files"] == {"file": (filename, DATA)}


def test_password_protected_misp_archive(service):
    # ZipCrypto archive encrypted with the standard MISP password "infected".
    encoded = (
        "UEsDBAoACQAAAGuXW13fYY2fGwAAAA8AAAAGABwAc2FtcGxlVVQJAAOJ9OBqifTganV4CwABBOgDAAAE6AMAAJekwG1Vrue8"
        "B5bemihMs5uaRTztDVPkO2D7B1BLBwjfYY2fGwAAAA8AAABQSwECHgMKAAkAAABrl1td32GNnxsAAAAPAAAABgAYAAAAAAAB"
        "AAAAgIEAAAAAc2FtcGxlVVQFAAOJ9OBqdXgLAAEE6AMAAAToAwAAUEsFBgAAAAABAAEATAAAAGsAAAAAAA=="
    )
    assert "results" in module.handler(malware_query(encoded))
    assert service.call_args.kwargs["files"] == {"file": ("original.exe", DATA)}


@pytest.mark.parametrize("members", [[], [("sample.filename.txt", b"name")], [("one", b"1"), ("two", b"2")]])
def test_empty_or_ambiguous_archive_never_submits(service, members):
    assert "error" in module.handler(malware_query(archive(members)))
    service.assert_not_called()


def test_invalid_zip_never_submits(service):
    assert "error" in module.handler(malware_query(base64.b64encode(DATA).decode()))
    service.assert_not_called()


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 403, 429, 500])
def test_http_failures_are_not_retried_and_do_not_leak_response(service, status):
    service.return_value.status_code = status
    service.return_value.text = SECRET
    result = module.handler(query({"apikey": SECRET}))
    assert "error" in result
    assert SECRET not in json.dumps(result)
    service.assert_called_once()
    service.return_value.json.assert_not_called()


@pytest.mark.parametrize(
    "failure", [requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.SSLError]
)
def test_network_errors_are_not_retried_or_exposed(service, failure):
    service.side_effect = failure(SECRET)
    result = module.handler(query({"apikey": SECRET}))
    assert "error" in result
    assert SECRET not in json.dumps(result)
    service.assert_called_once()


@pytest.mark.parametrize(
    "response",
    [
        None,
        [],
        {},
        {"success": False, "error": SECRET},
        {"success": True},
        {"success": True, "taskId": TASK},
        {"success": True, "taskId": TASK, "seed": 42},
        {"success": True, "taskId": "", "seed": SEED},
    ],
)
def test_invalid_api_response(service, response):
    service.return_value.json.return_value = response
    result = module.handler(query())
    assert "error" in result
    assert SECRET not in json.dumps(result)


def test_non_json_response(service):
    service.return_value.json.side_effect = ValueError(SECRET)
    assert module.handler(query()) == {"error": "Pandora returned an invalid JSON response."}


def test_response_identifiers_are_escaped_and_link_stays_on_configured_instance(service):
    service.return_value.json.return_value = {
        "success": True,
        "taskId": "task/id",
        "seed": "seed?#",
        "link": "https://other.example/report",
    }
    result = module.handler(query({"url": "https://pandora.example/prefix"}))
    assert result["results"][0]["values"] == "https://pandora.example/prefix/analysis/task%2Fid/seed-seed%3F%23"


def test_errors_are_not_shared_between_requests(service):
    first = module.handler(query(data="%%%"))
    saved = dict(first)
    module.handler(query({"timeout": -1}))
    assert first == saved
    assert "results" in module.handler(query())


@pytest.mark.parametrize("password", [None, "", "archive-password", "päss &?=+#/%"])
def test_real_requests_multipart_serialization(monkeypatch, password):
    def respond(session, prepared, **options):
        assert prepared.method == "POST"
        parsed = urlsplit(prepared.url)
        assert (parsed.scheme, parsed.netloc, parsed.path) == ("https", "pandora.example", "/prefix/submit")
        params = {"validity": ["3600"]}
        if password:
            params["password"] = [password]
        assert parse_qs(parsed.query) == params
        assert prepared.headers["Authorization"] == SECRET
        assert options["timeout"] == 45
        assert options["verify"] is True or isinstance(options["verify"], str)  # An environment CA bundle is valid too.
        assert options["allow_redirects"] is False
        message = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: " + prepared.headers["Content-Type"].encode() + b"\r\n\r\n" + prepared.body
        )
        parts = {part.get_param("name", header="content-disposition"): part for part in message.iter_parts()}
        assert parts["file"].get_filename() == "sample.exe"
        assert parts["file"].get_payload(decode=True) == DATA
        assert set(parts) == {"file"}
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({"success": True, "taskId": TASK, "seed": SEED}).encode()
        return response

    monkeypatch.setattr(requests.Session, "send", respond)
    result = module.handler(
        query(
            {
                "url": "https://pandora.example/prefix",
                "apikey": SECRET,
                "timeout": 45,
                "validity": 3600,
                "password": password,
            }
        )
    )
    assert result["results"][0]["values"] == f"https://pandora.example/prefix/analysis/{TASK}/seed-{SEED}"
