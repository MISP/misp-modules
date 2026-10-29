import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import dnstwist as module

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
    with patch("subprocess.run") as request:
        assert "error" in module.handler(raw)
    request.assert_not_called()


@pytest.mark.parametrize("raw", [0, -1, True, "bad", 101])
def test_invalid_result_limit(raw):
    with pytest.raises(module.ModuleError):
        module._integer({"max_results": raw}, "max_results", 25)


def test_local_generation_has_no_resolution_and_caps_results():
    import subprocess

    def run(command, **kwargs):
        kwargs["stdout"].write(
            json.dumps(
                [{"domain": "example.com"}, {"domain": "a.example", "fuzzer": "addition"}, {"domain": "b.example"}]
            ).encode()
        )
        return subprocess.CompletedProcess(command, 0)

    with patch("subprocess.run", side_effect=run) as run:
        result = module.handler(query(config={"max_results": 1}))
    assert_source(result)
    assert len(objects(result, "domain-ip")) == 1
    assert "-c" in run.call_args.args[0]
    assert "--registered" not in run.call_args.args[0]
    assert "shell" not in run.call_args.kwargs


def test_resolution_keeps_fuzzer_and_dns_evidence():
    import subprocess

    def run(command, **kwargs):
        kwargs["stdout"].write(
            json.dumps([{"domain": "a.example", "fuzzer": "addition", "dns_a": ["192.0.2.1"]}]).encode()
        )
        return subprocess.CompletedProcess(command, 0)

    with patch("subprocess.run", side_effect=run):
        result = module.handler(query(config={"resolve": True}))
    assert_source(result)
    assert values(objects(result, "domain-ip")[0], "ip") == ["192.0.2.1"]


def test_timeout_becomes_an_actionable_error():
    import subprocess

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("dnstwist", 30)):
        assert "timeout" in module.handler(query())["error"]
