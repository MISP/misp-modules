import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import unpac_me as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"


def query(kind="sha256", value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source metadata"},
            "config": {"apikey": "test-api-secret"} if config is None else config,
        }
    )


def response(payload=None, status=200):
    result = Mock(status_code=status, headers={})
    result.json.return_value = payload
    result.iter_content.return_value = iter([b"sample bytes"])
    return result


def handle(payload, **kwargs):
    with patch.object(module.requests, "get", return_value=response(payload)) as get:
        result = module.handler(query(**kwargs))
    return result, get


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {item["object_relation"]: item["value"] for item in obj["Attribute"]}


def assert_source(result):
    source = next(item for item in result["results"]["Attribute"] if item["uuid"] == UUID)
    assert source["to_ids"] is True
    assert source["comment"] == "source metadata"
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
    "raw", ["{", "[]", "null", "{}", '{"attribute": []}', '{"attribute":{"type":"ip-dst","value":"1.1.1.1"}}']
)
def test_invalid_request_never_calls_service(raw):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(raw)
    get.assert_not_called()


def test_unsupported_type_never_calls_service():
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(kind="comment"))
    get.assert_not_called()


@pytest.mark.parametrize("value", ["", "   ", 123, ["example.com"]])
def test_invalid_values_never_call_service(value):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(value=value))
    get.assert_not_called()


@pytest.mark.parametrize("status", [401, 403, 429, 500, 302])
def test_http_failures_are_reported(status):
    with patch.object(module.requests, "get", return_value=response(status=status)):
        result = module.handler(query())
    assert str(status) in result["error"]
    assert SECRET not in result["error"]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_network_failures_do_not_leak_credentials(failure):
    with patch.object(module.requests, "get", side_effect=failure("url?apikey=" + SECRET)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("status", [404, 204])
def test_empty_service_response_preserves_source(status):
    with patch.object(module.requests, "get", return_value=response(status=status)):
        result = module.handler(query())
    assert_source(result)
    assert result["results"]["Object"] == []


def test_invalid_service_json_is_reported():
    reply = response()
    reply.json.side_effect = ValueError("invalid JSON " + SECRET)
    with patch.object(module.requests, "get", return_value=reply):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize("payload", [[], "wrong", 1])
def test_unexpected_service_shape_is_reported(payload):
    result, _ = handle(payload)
    assert "error" in result


def test_missing_configuration_never_calls_service():
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(config={}))
    get.assert_not_called()


def test_children_and_submission_provenance():
    parent, child = "a" * 64, "b" * 64
    payload = {
        "results": [
            {
                "sha256": parent,
                "submission_id": "submission-1",
                "status": "complete",
                "created": 1735689600,
                "children": [parent, child, child],
            }
        ]
    }
    result, get = handle(payload)
    assert_source(result)
    assert len(objects(result, "file")) == 1
    assert values(objects(result, "file")[0])["sha256"] == child
    assert objects(result, "file")[0]["ObjectReference"][0]["relationship_type"] == "derived-from"
    assert json.loads(values(objects(result, "annotation")[0])["text"])["status"] == "complete"
    assert get.call_args.args[0].endswith("/private/search/hash/" + parent)
    assert get.call_args.kwargs["headers"] == {"Authorization": "Key " + SECRET}


def test_queued_submission_is_returned_without_polling():
    result, get = handle({"results": [{"sha256": "a" * 64, "status": "queued", "children": []}]})
    assert_source(result)
    assert json.loads(values(objects(result, "annotation")[0])["text"])["status"] == "queued"
    assert get.call_count == 1


def test_child_limit_has_explicit_notice():
    payload = {"results": [{"sha256": "a" * 64, "children": ["b" * 64, "c" * 64]}]}
    result, _ = handle(payload, config={"apikey": SECRET, "max_results": "1"})
    assert len(objects(result, "file")) == 1
    assert any("result limit" in x["comment"] for x in objects(result, "annotation"))


@pytest.mark.parametrize(
    "row", [{"sha256": "b" * 64}, {"sha256": "a" * 64, "children": ["bad"]}, {"sha256": "a" * 64, "children": 2}]
)
def test_mismatched_sample_or_malformed_children(row):
    result, _ = handle({"results": [row]})
    assert "error" in result


def test_search_child_count_fetches_authenticated_private_results():
    search = {
        "results": [
            {"id": "submission-42", "sha256": "a" * 64, "children": 2, "status": "complete", "created": 1735689600}
        ]
    }
    report = {
        "id": "submission-42",
        "sha256": "a" * 64,
        "results": [
            {"hashes": {"sha256": "a" * 64}},
            {"hashes": {"sha256": "b" * 64}},
            {"hashes": {"sha256": "c" * 64}},
            {"hashes": {"sha256": "b" * 64}},
        ],
    }
    with patch.object(module.requests, "get", side_effect=[response(search), response(report)]) as get:
        result = module.handler(query())
    assert_source(result)
    assert [values(obj)["sha256"] for obj in objects(result, "file")] == ["b" * 64, "c" * 64]
    context = json.loads(values(objects(result, "annotation")[0])["text"])
    assert context["id"] == "submission-42" and context["children"] == 2
    assert get.call_args.args[0] == "https://api.unpac.me/api/v1/private/results/submission-42"
    assert get.call_args.kwargs["headers"] == {"Authorization": "Key " + SECRET}
    assert get.call_count == 2


def test_zero_children_preserves_id_without_fetching_results():
    result, get = handle(
        {"results": [{"id": "submission-42", "sha256": "a" * 64, "children": 0, "status": "complete"}]}
    )
    context = json.loads(values(objects(result, "annotation")[0])["text"])
    assert context["id"] == "submission-42" and context["children"] == 0
    assert get.call_count == 1 and not objects(result, "file")


def test_unavailable_child_results_keep_submission_context_without_polling():
    search = {"results": [{"id": "submission-42", "sha256": "a" * 64, "children": 1, "status": "unpacking"}]}
    with patch.object(module.requests, "get", side_effect=[response(search), response(status=404)]) as get:
        result = module.handler(query())
    assert_source(result)
    context = json.loads(values(objects(result, "annotation")[0])["text"])
    assert context["children"] == 1 and context["results_available"] is False
    assert get.call_count == 2


def test_mismatched_private_results_are_not_attached_to_the_source():
    search = {"results": [{"id": "submission-42", "sha256": "a" * 64, "children": 1}]}
    with patch.object(
        module.requests,
        "get",
        side_effect=[response(search), response({"id": "submission-42", "sha256": "b" * 64, "results": []})],
    ):
        assert "error" in module.handler(query())


@pytest.mark.parametrize("count", [-1, True, "2"])
def test_invalid_child_count_is_reported(count):
    result, _ = handle({"results": [{"id": "submission-42", "sha256": "a" * 64, "children": count}]})
    assert "error" in result
