import base64
import hashlib
import io
import json
import zipfile
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests
from pymisp import MISPEvent

import misp_modules
from misp_modules.modules.expansion import mobsf as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
CONTENT = b"mobile application fixture"
MD5 = hashlib.md5(CONTENT).hexdigest()
SECRET = "test-api-key"
CONFIG = {"url": "https://mobsf.example/mobile/", "apikey": SECRET}


def query(kind="md5", value=MD5, config=None, data=None):
    attribute = {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "original context"}
    if data is not None:
        attribute["data"] = data
    return json.dumps({"attribute": attribute, "config": CONFIG if config is None else config})


def response(payload, status=200):
    reply = Mock(status_code=status)
    reply.json.return_value = payload
    reply.__enter__ = Mock(return_value=reply)
    reply.__exit__ = Mock(return_value=False)
    return reply


def report(**kwargs):
    return {"md5": MD5, "sha1": "b" * 40, "sha256": "c" * 64, "file_name": "sample.apk", **kwargs}


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def assert_valid_result(result):
    assert "results" in result, result
    event = MISPEvent()
    event.from_dict(info="MobSF test enrichment", **deepcopy(result["results"]))
    source = next(a for a in event.attributes if str(a.uuid) == UUID)
    assert source.to_ids is True
    assert source.comment == "original context"
    for obj in event.objects:
        obj.to_dict(strict=True)
        assert all(a.to_ids is False for a in obj.attributes)
        assert any(str(ref.referenced_uuid) == UUID for ref in obj.references)
    return event


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig
    root = misp_modules.__path__[0]
    assert any(file.name == "mobsf.py" for _, file in misp_modules.iterate_modules(Path(root) / "modules"))


def test_android_report_and_network_indicators():
    payload = report(
        package_name="org.example.app",
        app_name="Example",
        size="3.5MB",
        domains={"example.org": {"bad": "no"}},
        urls=[{"urls": ["https://example.org/path", "https://example.org/path"], "path": "classes.dex"}],
        emails=[{"emails": ["contact@example.org"], "path": "classes.dex"}],
        permissions={"android.permission.INTERNET": {"status": "normal"}},
    )
    with patch.object(module.requests, "post", return_value=response(payload)) as post:
        result = module.handler(query())
    event = assert_valid_result(result)
    post.assert_called_once_with(
        "https://mobsf.example/mobile/api/v1/report_json",
        headers={"Authorization": SECRET},
        timeout=120,
        verify=True,
        allow_redirects=False,
        data={"hash": MD5},
    )
    sandbox = values(objects(result, "sandbox-report")[0])
    assert json.loads(sandbox["raw-report"]) == payload
    assert sandbox["on-premise-sandbox"] == "MobSF"
    assert sandbox["permalink"] == "https://mobsf.example/mobile/search?query=" + MD5
    assert values(objects(result, "android-app")[0])["appid"] == "org.example.app"
    assert values(objects(result, "file")[0])["sha256"] == "c" * 64
    assert "size-in-bytes" not in values(objects(result, "file")[0])
    extracted = {(a.type, a.value) for a in event.attributes if str(a.uuid) != UUID}
    assert extracted == {
        ("domain", "example.org"),
        ("url", "https://example.org/path"),
        ("email-dst", "contact@example.org"),
    }
    assert all(not a.to_ids for a in event.attributes if str(a.uuid) != UUID)


@pytest.mark.parametrize(
    "metadata",
    [
        {"bundle_id": "org.example.ios", "app_name": "iOS App", "app_version": "2.0", "file_name": "sample.ipa"},
        {"app_name": "Windows App", "app_version": "3.0", "file_name": "sample.appx"},
    ],
)
def test_ios_and_windows_reports(metadata):
    with patch.object(module.requests, "post", return_value=response(report(**metadata))):
        result = module.handler(query())
    assert_valid_result(result)
    app = values(objects(result, "software")[0])
    assert app["name"] == metadata["app_name"]
    assert app["version"] == metadata["app_version"]
    assert not objects(result, "android-app")


def test_attachment_upload_and_synchronous_scan():
    with patch.object(module.requests, "post", side_effect=[response({"hash": MD5}), response(report())]) as post:
        result = module.handler(query("attachment", "some/path/sample.apk", data=base64.b64encode(CONTENT).decode()))
    assert_valid_result(result)
    assert post.call_count == 2
    upload, scan = post.call_args_list
    assert upload.args[0].endswith("/upload")
    assert upload.kwargs["files"] == {"file": ("sample.apk", CONTENT)}
    assert scan.args[0].endswith("/scan")
    assert scan.kwargs["data"] == {"hash": MD5}


@pytest.mark.parametrize("task_id", ["queued-task", None])
def test_async_receipt_does_not_poll(task_id):
    with patch.object(
        module.requests,
        "post",
        side_effect=[
            response({"hash": MD5}),
            response({"task_id": task_id, "message": "Scan queued or already scheduled"}),
        ],
    ) as post:
        result = module.handler(query("attachment", "sample.ipa", data=base64.b64encode(CONTENT).decode()))
    assert_valid_result(result)
    assert post.call_count == 2
    assert values(objects(result, "file")[0])["md5"] == MD5
    sandbox = objects(result, "sandbox-report")[0]
    assert "queued" in sandbox["comment"]
    assert json.loads(values(sandbox)["raw-report"])["task_id"] == task_id


def archive(content=CONTENT, extra=False):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("sample.apk", content)
        handle.writestr("sample.apk.filename.txt", "sample.apk")
        if extra:
            handle.writestr("extra.apk", CONTENT)
    return base64.b64encode(data.getvalue()).decode()


def test_malware_sample_is_unpacked_and_original_filename_used():
    encoded = archive()
    with patch.object(module.requests, "post", side_effect=[response({"hash": MD5}), response(report())]) as post:
        result = module.handler(query("malware-sample", "sample|name.apk|" + MD5, data=encoded))
    assert result["results"]["Attribute"][0]["data"] == encoded
    assert_valid_result(result)
    assert post.call_args_list[0].kwargs["files"] == {"file": ("sample|name.apk", CONTENT)}


@pytest.mark.parametrize("data", [archive(extra=True), archive(b"wrong bytes"), "invalid base64", ""])
def test_invalid_malware_samples_do_not_upload(data):
    with patch.object(module.requests, "post") as post:
        assert "error" in module.handler(query("malware-sample", "sample.apk|" + MD5, data=data))
    post.assert_not_called()


def test_decompressed_size_limit_is_enforced():
    content = b"a" * (1024 * 1024 + 1)
    with patch.object(module.requests, "post") as post:
        result = module.handler(
            query("malware-sample", "sample.apk|" + MD5, config={**CONFIG, "max_size_mb": 1}, data=archive(content))
        )
    assert "error" in result
    post.assert_not_called()


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}', '{"attribute": {"type": "md5"}}'])
def test_invalid_envelope(raw):
    with patch.object(module.requests, "post") as post:
        assert "error" in module.handler(raw)
    post.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [
        {},
        None,
        [],
        {"url": CONFIG["url"]},
        {**CONFIG, "apikey": "\nsecret"},
        *(
            {**CONFIG, "url": v}
            for v in [
                "file:///tmp",
                "https://u:p@host",
                "https://host?key=x",
                "https://host/#x",
                "https://host:0",
                "https://host:bad",
                "https://ho st",
            ]
        ),
        *({**CONFIG, k: v} for k in ("timeout", "max_size_mb") for v in (0, -1, True, "bad", "1.5", 10000)),
    ],
)
def test_invalid_configuration_never_calls_service(config):
    raw = json.loads(query())
    raw["config"] = config
    with patch.object(module.requests, "post") as post:
        assert "error" in module.handler(json.dumps(raw))
    post.assert_not_called()


@pytest.mark.parametrize("kind,value", [("sha256", "a" * 64), ("md5", "bad"), ("md5", 5), ("md5", " ")])
def test_invalid_attribute(kind, value):
    with patch.object(module.requests, "post") as post:
        assert "error" in module.handler(query(kind, value))
    post.assert_not_called()


@pytest.mark.parametrize("status", [301, 401, 403, 404, 429, 500])
def test_http_errors_are_redacted(status):
    with patch.object(module.requests, "post", return_value=response({"error": SECRET}, status)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in str(result)


@pytest.mark.parametrize("error", [requests.Timeout, requests.ConnectionError])
def test_transport_errors_do_not_leak_credentials_or_retry(error):
    with patch.object(module.requests, "post", side_effect=error(SECRET)) as post:
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in str(result)
    post.assert_called_once()


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"error": SECRET},
        {"report": "Report not Found"},
        report(md5="a" * 32),
        report(sha256="bad"),
        report(domains=["wrong shape"]),
        report(urls={"bad": True}),
    ],
)
def test_invalid_reports(payload):
    with patch.object(module.requests, "post", return_value=response(payload)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in str(result)


def test_invalid_json_is_redacted():
    reply = response(None)
    reply.json.side_effect = ValueError(SECRET)
    with patch.object(module.requests, "post", return_value=reply):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in str(result)


def test_upload_hash_must_match_before_starting_analysis():
    with patch.object(module.requests, "post", return_value=response({"hash": "a" * 32})) as post:
        result = module.handler(query("attachment", "sample.apk", data=base64.b64encode(CONTENT).decode()))
    assert "error" in result
    post.assert_called_once()


def test_timeout_during_scan_is_not_retried():
    with patch.object(module.requests, "post", side_effect=[response({"hash": MD5}), requests.Timeout(SECRET)]) as post:
        result = module.handler(query("attachment", "sample.apk", data=base64.b64encode(CONTENT).decode()))
    assert post.call_count == 2
    assert "before submitting again" in result["error"]
    assert SECRET not in str(result)
