import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import triage_query as module

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


def test_hash_search_retrieves_overview():
    responses = [
        reply({"data": [{"id": "240101-abcd12"}]}),
        reply({"analysis": {"score": 0}, "targets": [{"sha256": "b" * 64}], "extracted": []}),
    ]
    with patch.object(module.requests, "request", side_effect=responses) as request:
        result = module.handler(query(kind="sha256", value="a" * 64))
    assert_source(result)
    assert request.call_count == 2
    assert request.call_args.args[1] == "https://tria.ge/api/v1/samples/240101-abcd12/overview.json"
    assert objects(result, "sandbox-report")
    assert objects(result, "file")


def test_foreign_link_never_receives_credentials():
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(kind="link", value="https://other.example/240101-abcd12"))
    request.assert_not_called()


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
    assert fields["sandbox-type"] == "saas"
    assert fields["saas-sandbox"] == "hatching-triage"
    assert set(obj._definition.get("required", [])) <= set(fields)
    assert set(obj._definition["requiredOneOf"]) & set(fields)
