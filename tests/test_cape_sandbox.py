import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import cape_sandbox as module

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


def test_completed_report_yields_hashes_network_and_configuration():
    data = {
        "target": {"file": {"sha256": "a" * 64}},
        "network": {"hosts": [{"ip": "192.0.2.2"}], "dns": [{"request": "bad.example"}]},
        "CAPE": {"configs": [{"family": "example"}]},
    }
    with patch.object(module.requests, "request", return_value=reply(data)) as request:
        result = module.handler(query(kind="text", value="42", config={"api_url": "https://cape.example/apiv2"}))
    assert_source(result)
    assert request.call_args.args[1].endswith("/tasks/get/report/42/json/")
    assert len(objects(result, "domain-ip")) == 2
    assert objects(result, "file") and objects(result, "sandbox-report")


def test_sample_requires_explicit_submission_and_is_sent_once():
    import base64

    config = {"api_url": "https://cape.example/apiv2", "submit_samples": True}
    with patch.object(
        module.requests, "request", return_value=reply({"error": False, "data": {"task_ids": [42]}})
    ) as request:
        result = module.handler(
            query(kind="attachment", value="sample.bin", config=config, data=base64.b64encode(b"sample").decode())
        )
    assert_source(result)
    assert request.call_count == 1
    assert request.call_args.kwargs["files"]["file"] == ("sample.bin", b"sample")
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(
            query(
                kind="attachment", value="sample.bin", config={"api_url": "https://cape.example/apiv2"}, data="c2FtcGxl"
            )
        )
    request.assert_not_called()


def test_current_sample_zip_metadata_digest_and_pipe_filename():
    import base64, hashlib, io, zipfile

    payload = b"actual sample"
    digest = hashlib.md5(payload).hexdigest()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(digest, payload)
        archive.writestr(digest + ".filename.txt", "sample|name.exe")
    attribute = {
        "type": "malware-sample",
        "value": "sample|name.exe|" + digest,
        "data": base64.b64encode(output.getvalue()).decode(),
    }
    assert module._binary(attribute, {})[:2] == ("sample|name.exe", payload)
    attribute["value"] = "sample|name.exe|" + "0" * 32
    with pytest.raises(module.ModuleError):
        module._binary(attribute, {})
    assert (
        module._binary({"type": "attachment", "value": "sample|name.exe", "data": "c2FtcGxl"}, {})[0]
        == "sample|name.exe"
    )


def test_pivots_normalize_source_and_use_the_url_template():
    from pymisp import MISPEvent

    event = MISPEvent()
    attribute = {"type": "sha256", "value": "A" * 64, "uuid": UUID}
    module._pivot(event, attribute, "sha256", "a" * 64)
    assert not event.objects
    module._pivot(event, attribute, "url", "https://example.com/path")
    assert event.objects[0].name == "url"
    assert event.objects[0].attributes[0].object_relation == "url"


def test_sandbox_classification_matches_template_contract():
    from pymisp import MISPEvent

    event = MISPEvent()
    attribute = {"uuid": UUID}
    obj = module._sandbox(event, attribute, {"score": 0})
    fields = {a.object_relation: a.value for a in obj.attributes}
    assert fields["sandbox-type"] == "on-premise"
    assert fields["on-premise-sandbox"] == "cape"
    assert set(obj._definition.get("required", [])) <= set(fields)
    assert set(obj._definition["requiredOneOf"]) & set(fields)
