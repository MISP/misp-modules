import json
from copy import deepcopy
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import mwdb_query as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"
CONFIG = {"mwdb_apikey": SECRET, "mwdb_url": "https://mwdb.example/api/"}
FILE = {
    "id": "c" * 64,
    "type": "file",
    "md5": "a" * 32,
    "sha1": "b" * 40,
    "sha256": "c" * 64,
    "sha512": "d" * 128,
    "file_name": "sample.exe",
    "file_size": 0,
    "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
    "upload_time": "2026-10-01T12:00:00+00:00",
    "tags": [{"tag": "family:example"}],
}


def query(kind="sha256", value=None, config=CONFIG):
    return json.dumps(
        {
            "attribute": {
                "type": kind,
                "value": FILE.get(kind, "example") if value is None else value,
                "uuid": UUID,
                "to_ids": True,
                "comment": "source context",
            },
            "config": config,
        }
    )


def response(data=FILE, status=200):
    reply = Mock(status_code=status)
    reply.json.return_value = deepcopy(data)
    return reply


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def assert_source(result):
    source = next(a for a in result["results"]["Attribute"] if a["uuid"] == UUID)
    assert source["to_ids"] is True
    assert source["comment"] == "source context"
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False for a in obj["Attribute"])
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])
    assert all(a["to_ids"] is False for a in result["results"]["Attribute"] if a["uuid"] != UUID)


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == ["mwdb_apikey", "mwdb_url"]
    assert module.version()["module-type"] == ["expansion"]


@pytest.mark.parametrize("kind", module.HASH_LENGTHS)
def test_lookup_each_hash_and_preserve_source(kind):
    with patch.object(module.requests, "get", return_value=response()) as get:
        result = module.handler(query(kind, FILE[kind].upper()))
    assert_source(result)
    get.assert_called_once_with(
        "https://mwdb.example/api/file/" + FILE[kind],
        headers={"Authorization": "Bearer " + SECRET},
        timeout=30,
        verify=True,
        allow_redirects=False,
    )
    file = objects(result, "file")[0]
    attrs = values(file)
    assert {kind: attrs[kind] for kind in module.HASH_LENGTHS} == {kind: FILE[kind] for kind in module.HASH_LENGTHS}
    assert attrs["filename"] == "sample.exe"
    assert attrs["size-in-bytes"] == "0"
    # libmagic file_type is free text, not a MIME type.
    assert "mimetype" not in attrs
    context = json.loads(values(objects(result, "annotation")[0])["text"])
    assert context == {"tags": ["family:example"], "file_type": FILE["file_type"], "upload_time": FILE["upload_time"]}
    link = next(a for a in result["results"]["Attribute"] if a["type"] == "link")
    assert link["value"] == "https://mwdb.example/file/" + FILE["sha256"]
    assert any(ref["referenced_uuid"] == link["uuid"] for ref in file["ObjectReference"])
    assert not file.get("Tag")


@pytest.mark.parametrize("url", ["https://mwdb.example/prefix/api", "https://mwdb.example/prefix/api/"])
def test_api_url_with_deployment_prefix(url):
    with patch.object(module.requests, "get", return_value=response()) as get:
        result = module.handler(query(config={**CONFIG, "mwdb_url": url}))
    assert get.call_args.args[0] == "https://mwdb.example/prefix/api/file/" + FILE["sha256"]
    assert next(a for a in result["results"]["Attribute"] if a["type"] == "link")["value"] == (
        "https://mwdb.example/prefix/file/" + FILE["sha256"]
    )


def test_not_found_preserves_source_without_enrichment():
    with patch.object(module.requests, "get", return_value=response(status=404)):
        result = module.handler(query())
    assert_source(result)
    assert result["results"]["Object"] == []
    assert len(result["results"]["Attribute"]) == 1


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute":[]}'])
def test_invalid_request_never_queries(raw):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(raw)
    get.assert_not_called()


@pytest.mark.parametrize(
    "kind,value",
    [
        ("url", "https://example.com"),
        ("md5", "a" * 31),
        ("sha1", "g" * 40),
        ("sha256", []),
        ("sha256", 3),
        ("sha256", "../" + "a" * 61),
    ],
)
def test_invalid_hash_never_queries(kind, value):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(kind, value))
    get.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [None, {}, [], {**CONFIG, "mwdb_apikey": ""}, {**CONFIG, "mwdb_apikey": "bad\nkey"}, {**CONFIG, "mwdb_apikey": 3}],
)
def test_missing_or_invalid_configuration(config):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(config=config))
    get.assert_not_called()


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "file:///api",
        "https://mwdb.example/",
        "https://user:secret@mwdb.example/api",
        "https://mwdb.example/api?key=secret",
        "https://mwdb.example/api#secret",
        "https://mwdb.example:bad/api",
    ],
)
def test_invalid_api_url_never_queries(url):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(query(config={**CONFIG, "mwdb_url": url}))
    get.assert_not_called()


@pytest.mark.parametrize("status", [204, 301, 302, 401, 403, 429, 500])
def test_api_errors_are_redacted(status):
    with patch.object(module.requests, "get", return_value=response({"error": SECRET}, status)):
        result = module.handler(query())
    assert str(status) in result["error"]
    assert SECRET not in result["error"]


@pytest.mark.parametrize("error", [requests.Timeout, requests.ConnectionError, requests.exceptions.InvalidHeader])
def test_transport_errors_are_redacted(error):
    with patch.object(module.requests, "get", side_effect=error(SECRET)):
        result = module.handler(query())
    assert "error" in result
    assert SECRET not in result["error"]


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {},
        {**FILE, "type": "static_config"},
        {**FILE, "sha256": "e" * 64},
        {**FILE, "id": "e" * 64},
        {**FILE, "md5": "bad"},
        {**FILE, "file_size": -1},
        {**FILE, "file_size": True},
        {**FILE, "file_name": []},
        {**FILE, "tags": "bad"},
        {**FILE, "tags": [{}]},
        {**FILE, "upload_time": []},
    ],
)
def test_malformed_responses(data):
    with patch.object(module.requests, "get", return_value=response(data)):
        assert "error" in module.handler(query())


def test_response_must_match_queried_hash():
    with patch.object(module.requests, "get", return_value=response()):
        result = module.handler(query("md5", "e" * 32))
    assert "different file hash" in result["error"]


def test_invalid_json_is_redacted():
    reply = response()
    reply.json.side_effect = ValueError(SECRET)
    with patch.object(module.requests, "get", return_value=reply):
        result = module.handler(query())
    assert result == {"error": "MWDB returned invalid JSON."}


def test_optional_metadata_may_be_absent():
    data = {k: v for k, v in FILE.items() if k in ("id", "type", "sha256")}
    with patch.object(module.requests, "get", return_value=response(data)):
        result = module.handler(query())
    assert_source(result)
    assert values(objects(result, "file")[0]) == {"sha256": FILE["sha256"]}
