import json
from importlib import resources
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests
from jsonschema import validate
from pymisp import MISPEvent, MISPObject

from misp_modules.modules.expansion import pgp_keyserver as pgp

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
FINGERPRINT = "FF274336B4530375102C9EB270909C9C006694EB"
SECOND = "CA572205C0024E06BA70BE89EAADCFFC22BD4CD5"
ARMOR = Path(__file__).with_name("test_files").joinpath("pgp", "public-key.asc").read_text().strip()
INDEX = (
    f"info:1:1\npub:{FINGERPRINT}:1:2048:1483716566:1800000000:r\n"
    "uid:CIRCL (cert) <info@circl.lu>:1483716566::\n"
    "uid:Alice%3A Ops <alice+tag@example.org>:1483716566::r\n"
    "uid:Alice%3A Ops <alice+tag@example.org>:1483716566::r\n"
    "uid:Anonymous%20UID%20%2B%20%C3%A9%25:1483716566::\n"
)


def _request(value="info@circl.lu", attribute_type="email", **config):
    return {
        "attribute": {"type": attribute_type, "value": value, "uuid": UUID},
        "config": config,
    }


def _response(text, status=200):
    result = Mock(status_code=status)
    result.__enter__ = Mock(return_value=result)
    result.__exit__ = Mock(return_value=False)
    result.iter_content.return_value = [text.encode()]
    if status >= 400:
        result.raise_for_status.side_effect = requests.HTTPError(response=result)
    return result


def _run(request=None, index=INDEX, downloads=None):
    session = Mock()
    session.get.side_effect = [_response(index), *(downloads if downloads is not None else [_response(ARMOR)])]
    manager = Mock()
    manager.__enter__ = Mock(return_value=session)
    manager.__exit__ = Mock(return_value=False)
    with patch.object(pgp.requests, "Session", return_value=manager):
        result = pgp.handler(json.dumps(_request() if request is None else request))
    return result, session


def _objects(result, name):
    assert "error" not in result, result
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def _values(obj, relation):
    return [attribute["value"] for attribute in obj["Attribute"] if attribute["object_relation"] == relation]


def test_default_lookup_returns_linked_keys_and_metadata_and_preserves_source():
    request = _request()
    request["attribute"].update(comment="Keep this", to_ids=True, Tag=[{"name": "tlp:clear"}])
    result, session = _run(request)
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == UUID
    assert source["comment"] == "Keep this"
    assert source["to_ids"] is True
    assert source["Tag"] == [{"name": "tlp:clear"}]
    key = _objects(result, "pgp-key")[0]
    meta = _objects(result, "pgp-meta")[0]
    assert _values(key, "key-id") == [FINGERPRINT[-16:]]
    assert _values(key, "fingerprint") == [FINGERPRINT]
    assert _values(key, "key") == [ARMOR]
    assert _values(key, "algorithm") == ["1"]
    assert _values(key, "key-length") == ["2048"]
    assert _values(key, "creation-time") == ["2017-01-06T15:29:26+00:00"]
    assert _values(key, "expiration-time") == ["2027-01-15T08:00:00+00:00"]
    assert _values(key, "flags") == ["r"]
    assert _values(meta, "key-id") == [FINGERPRINT[-16:]]
    assert _values(meta, "user-id-email") == ["info@circl.lu", "alice+tag@example.org"]
    assert _values(key, "uid") == [
        "CIRCL (cert) <info@circl.lu>",
        "Alice: Ops <alice+tag@example.org>",
        "Anonymous UID + é%",
    ]
    assert "Anonymous UID + é%" in _values(meta, "user-id-name")
    assert "Alice: Ops" in _values(meta, "user-id-name")
    assert any("HKP flags: r" in attribute["comment"] for attribute in meta["Attribute"] if "comment" in attribute)
    assert [(ref["referenced_uuid"], ref["relationship_type"]) for ref in key["ObjectReference"]] == [
        (UUID, "related-to")
    ]
    assert [(ref["referenced_uuid"], ref["relationship_type"]) for ref in meta["ObjectReference"]] == [
        (key["uuid"], "extracted-from")
    ]
    for obj in result["results"]["Object"]:
        assert obj["template_uuid"]
        assert all(attribute["to_ids"] is False for attribute in obj["Attribute"])
    first, second = session.get.call_args_list
    assert first.args == ("https://pgp.circl.lu/pks/lookup",)
    assert first.kwargs == {
        "params": {"op": "index", "options": "mr", "fingerprint": "on", "search": "info@circl.lu"},
        "timeout": 10,
        "stream": True,
    }
    assert second.kwargs["params"]["search"] == "0x" + FINGERPRINT
    event = MISPEvent()
    event.load(json.dumps({"Event": {"info": "PGP expansion test", **result["results"]}}))
    assert len(event.objects) == 2
    for obj in result["results"]["Object"]:
        custom = pgp._template(obj["name"]) if obj["name"] != "pgp-meta" else None
        restored = MISPObject(obj["name"], strict=True, misp_objects_template_custom=custom)
        restored.from_dict(**obj)
        restored.to_json()


@pytest.mark.parametrize(
    "value,expected",
    [
        ("006694eb", "0x006694EB"),
        ("0X70909C9C006694eb", "0x70909C9C006694EB"),
        ("ff27 4336 b453 0375 102c 9eb2 7090 9c9c 0066 94eb", "0x" + FINGERPRINT),
        ("A" * 64, "0x" + "A" * 64),
        (" Alice + Ops ", "Alice + Ops"),
        ("alice+tag@example.org", "alice+tag@example.org"),
    ],
)
def test_queries_are_normalized_without_losing_uid_text(value, expected):
    result, session = _run(_request(value, "text"))
    assert "error" not in result
    assert session.get.call_args_list[0].kwargs["params"]["search"] == expected


@pytest.mark.parametrize("attribute_type", pgp.mispattributes["input"])
def test_all_advertised_inputs_can_be_expanded(attribute_type):
    assert "error" not in _run(_request(attribute_type=attribute_type))[0]


@pytest.mark.parametrize("info", ["", "info::1\n", "info:1\n", "info:1:\n", "info\n"])
def test_optional_index_information_does_not_prevent_key_and_uid_expansion(info):
    index = info + f"pub:{FINGERPRINT}:1:2048:1483716566::\nuid:Alice <alice@example.org>:0::\n"
    result, session = _run(index=index)
    key = _objects(result, "pgp-key")[0]
    assert _values(key, "fingerprint") == [FINGERPRINT]
    assert _values(key, "key") == [ARMOR]
    assert _values(_objects(result, "pgp-meta")[0], "user-id-email") == ["alice@example.org"]
    assert "comment" not in key
    assert session.get.call_count == 2


@pytest.mark.parametrize(
    "public_record",
    [
        f"pub:{FINGERPRINT}:1:2048:1483716566:",
        f"pub:{FINGERPRINT}:1:2048:1483716566",
        f"pub:{FINGERPRINT}:1:2048",
        f"pub:{FINGERPRINT}:1",
        f"pub:{FINGERPRINT}",
    ],
)
@pytest.mark.parametrize(
    "uid_record",
    [
        "uid:Alice%20Ops <alice+tag@example.org>:1483716566:",
        "uid:Alice%20Ops <alice+tag@example.org>:1483716566",
        "uid:Alice%20Ops <alice+tag@example.org>",
    ],
)
def test_omitted_trailing_fields_preserve_public_key_and_uid_metadata(public_record, uid_record):
    result, session = _run(index=f"info:1:1\n{public_record}\n{uid_record}\n")
    key = _objects(result, "pgp-key")[0]
    meta = _objects(result, "pgp-meta")[0]
    assert _values(key, "key") == [ARMOR]
    assert _values(key, "fingerprint") == [FINGERPRINT]
    assert _values(key, "uid") == ["Alice Ops <alice+tag@example.org>"]
    assert _values(meta, "key-id") == [FINGERPRINT[-16:]]
    assert _values(meta, "user-id-name") == ["Alice Ops"]
    assert _values(meta, "user-id-email") == ["alice+tag@example.org"]
    assert not _values(key, "expiration-time")
    assert not _values(key, "flags")
    assert session.get.call_count == 2


def test_headerless_index_with_omitted_trailing_fields_returns_linked_objects():
    result, _ = _run(index=f"pub:{FINGERPRINT}\nuid:Alice <alice@example.org>\n")
    key = _objects(result, "pgp-key")[0]
    meta = _objects(result, "pgp-meta")[0]
    assert _values(key, "key") == [ARMOR]
    assert meta["ObjectReference"][0]["referenced_uuid"] == key["uuid"]


def test_short_id_collisions_remain_distinct_by_full_fingerprint():
    collision = "A" * 24 + FINGERPRINT[-16:]
    index = f"info:1:2\npub:{FINGERPRINT}:1:2048:1483716566::\npub:{collision}:1:2048:1483716566::\n"
    result, session = _run(index=index, downloads=[_response(ARMOR), _response(ARMOR)])
    keys = _objects(result, "pgp-key")
    assert [_values(key, "fingerprint")[0] for key in keys] == [FINGERPRINT, collision]
    assert len({key["uuid"] for key in keys}) == 2
    assert len(_objects(result, "pgp-meta")) == 2
    assert session.get.call_count == 3


@pytest.mark.parametrize("with_info", [True, False])
def test_custom_server_and_result_limit_are_applied_before_downloads(with_info):
    index = INDEX.replace("info:1:1", "info:1:2") + f"pub:{SECOND}:1:2048:0::\n"
    if not with_info:
        index = index.split("\n", 1)[1]
    result, session = _run(_request(keyserver="https://keys.example.org:8443/", timeout="2.5", max_results="1"), index)
    assert session.get.call_count == 2
    for call in session.get.call_args_list:
        assert call.args == ("https://keys.example.org:8443/pks/lookup",)
        assert call.kwargs["timeout"] == 2.5
    key = _objects(result, "pgp-key")[0]
    assert "1 of 2" in key["comment"]
    assert _values(key, "keyserver") == ["https://keys.example.org:8443"]


@pytest.mark.parametrize("with_info", [True, False])
def test_duplicate_records_merge_uids_without_duplicate_downloads(with_info):
    index = INDEX + f"pub:{FINGERPRINT}:1:2048:1483716566::\nuid:Second UID:0::\n"
    if not with_info:
        index = index.split("\n", 1)[1]
    result, session = _run(index=index)
    assert len(_objects(result, "pgp-key")) == 1
    assert "Second UID" in _values(_objects(result, "pgp-key")[0], "uid")
    assert "comment" not in _objects(result, "pgp-key")[0]
    assert session.get.call_count == 2


@pytest.mark.parametrize("identifier", ["006694EB", FINGERPRINT[-16:]])
def test_index_without_fingerprint_retains_metadata_and_skips_ambiguous_download(identifier):
    result, session = _run(index=f"info:1:1\npub:{identifier}:1:2048:0::\n")
    key = _objects(result, "pgp-key")[0]
    assert not _values(key, "key")
    assert "ambiguous key ID" in key["comment"]
    assert session.get.call_count == 1


def test_v6_fingerprint_uses_high_64_bits_for_key_id():
    fingerprint = "1234567890ABCDEF" + "A" * 48
    records, _ = pgp._parse_index(f"info:1:1\npub:{fingerprint}:27:256:0::\n")
    assert records[0]["key-id"] == "1234567890ABCDEF"


@pytest.mark.parametrize(
    "download",
    [
        requests.Timeout(),
        requests.ConnectionError(),
        _response("not found", 404),
        _response("unavailable", 503),
        _response("<html>not a key</html>"),
        _response(ARMOR + "\n" + ARMOR),
        _response("-----BEGIN PGP PRIVATE KEY BLOCK-----\nprivate\n-----END PGP PRIVATE KEY BLOCK-----"),
    ],
)
def test_download_failures_keep_index_metadata_and_relationships(download):
    result, _ = _run(downloads=[download])
    key = _objects(result, "pgp-key")[0]
    assert not _values(key, "key")
    assert "retrieval failed" in key["comment"]
    assert _values(key, "uid")
    assert _objects(result, "pgp-meta")[0]["ObjectReference"][0]["referenced_uuid"] == key["uuid"]


@pytest.mark.parametrize("index", ["info:1:0\n", ""])
def test_no_results_or_invalid_empty_index_returns_error(index):
    assert "error" in _run(index=index)[0]


@pytest.mark.parametrize(
    "index",
    [
        "<html>index</html>",
        "info:2:1\n",
        "info:2:1\n" + f"pub:{FINGERPRINT}:1:2048:0::\n",
        "info:1:bad\n",
        "info:1:1:extra\n",
        "info:1:1\n",
        "info:1:1\nuid:orphan:0::\n",
        "uid:orphan\n",
        "pub:bad\n",
        "pub\n",
        "info:1:1\npub:bad:1:2048:0::\n",
        f"pub:{FINGERPRINT}:1:2048:0:::extra\n",
        f"pub:{FINGERPRINT}\nuid:Alice:0:::extra\n",
        f"info:1:1\npub:{FINGERPRINT}:rsa:2048:0::\n",
        f"info:1:1\npub:{FINGERPRINT}:1:2048:bad::\n",
        f"info:1:1\npub:{FINGERPRINT}:1:2048:999999999999999999999999::\n",
        f"info:1:0\npub:{FINGERPRINT}:1:2048:0::\n",
        f"info:1:1\npub:{FINGERPRINT}:1:2048:0::\nuid:bad%FF:0::\n",
    ],
)
def test_malformed_index_fails_before_any_download(index):
    result, session = _run(index=index)
    assert "error" in result
    assert session.get.call_count == 1


@pytest.mark.parametrize(
    "config",
    [
        {"keyserver": "ftp://example.org"},
        {"keyserver": "https://user:pass@example.org"},
        {"keyserver": "https://example.org?op=get"},
        {"keyserver": "https://example.org#fragment"},
        {"keyserver": "https://example.org:0"},
        {"keyserver": "https://example.org:bad"},
        {"keyserver": 7},
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": "nan"},
        {"timeout": 61},
        {"max_results": 0},
        {"max_results": 101},
        {"max_results": "1.5"},
        {"max_results": True},
    ],
)
def test_invalid_config_is_rejected_before_network(config):
    request = _request()
    request["config"] = config
    with patch.object(pgp.requests, "Session") as session:
        assert "error" in pgp.handler(json.dumps(request))
    session.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"attribute": []},
        {"attribute": {"type": "text", "value": "foo"}},
        _request("", "text"),
        _request("bad\nUID", "text"),
        _request("0xZZZZ", "text"),
        _request("a" * 1025, "text"),
        _request(attribute_type="url"),
        {**_request(), "config": []},
        {**_request(), "attribute": {"type": "text", "value": "foo", "uuid": "bad"}},
    ],
)
def test_invalid_request_is_rejected_before_network(payload):
    with patch.object(pgp.requests, "Session") as session:
        assert "error" in pgp.handler(json.dumps(payload))
    session.assert_not_called()


def test_invalid_json_and_missing_request():
    assert pgp.handler() is False
    assert "error" in pgp.handler("{")


@pytest.mark.parametrize(
    "failure", [requests.Timeout(), requests.ConnectionError(), _response("error", 500), _response("", 404)]
)
def test_index_network_errors_are_returned_as_module_errors(failure):
    session = Mock()
    session.get.side_effect = failure if isinstance(failure, Exception) else [failure]
    manager = Mock()
    manager.__enter__ = Mock(return_value=session)
    manager.__exit__ = Mock(return_value=False)
    with patch.object(pgp.requests, "Session", return_value=manager):
        assert "error" in pgp.handler(json.dumps(_request()))


def test_stream_size_limit_is_enforced_and_response_is_closed():
    session = Mock()
    response = _response("", 200)
    response.iter_content.return_value = [b"abc", b"def"]
    session.get.return_value = response
    with pytest.raises(ValueError, match="size limit"):
        pgp._get(session, "https://example.org/pks/lookup", {}, 1, 5)
    response.__exit__.assert_called_once()


@pytest.mark.parametrize("name", ["pgp-key", "pgp-message", "pgp-sign"])
def test_templates_validate_and_match_the_misp_objects_submodule(name):
    template = pgp._template(name)
    root = Path(__file__).resolve().parents[1]
    upstream = root / "misp-objects" / "objects" / name / "definition.json"
    if upstream.exists():
        assert template == json.loads(upstream.read_text())
    schema = resources.files("pymisp").joinpath("data", "misp-objects", "schema_objects.json")
    validate(template, json.loads(schema.read_text()))
    obj = MISPObject(name, strict=True, misp_objects_template_custom=template)
    if name == "pgp-key":
        obj.add_attribute("key-id", FINGERPRINT[-16:])
        obj.add_attribute("key", ARMOR)
    elif name == "pgp-sign":
        obj.add_attribute("signature", "-----BEGIN PGP SIGNATURE-----\n\nExample\n-----END PGP SIGNATURE-----")
    else:
        obj.add_attribute("message", "-----BEGIN PGP MESSAGE-----\nExample artifact\n-----END PGP MESSAGE-----")
        meta = MISPObject("pgp-meta", strict=True)
        meta.add_attribute("key-id", FINGERPRINT[-16:])
        meta.add_reference(obj.uuid, "extracted-from")
        event = MISPEvent()
        event.add_object(obj)
        event.add_object(meta)
        assert json.loads(event.to_json())["Object"][1]["ObjectReference"][0]["referenced_uuid"] == str(obj.uuid)
    assert json.loads(obj.to_json())["template_uuid"] == template["uuid"]


def test_message_template_accepts_binary_artifact_as_attachment():
    obj = MISPObject("pgp-message", strict=True, misp_objects_template_custom=pgp._template("pgp-message"))
    obj.add_attribute("message-file", value="message.pgp", data="YWJj")
    assert json.loads(obj.to_json())["Attribute"][0]["data"] == "YWJj"


def test_module_advertises_configuration_and_standard_output():
    assert pgp.introspection()["format"] == "misp_standard"
    assert pgp.version()["config"] == ["keyserver", "timeout", "max_results", "extract_signatures", "max_signatures"]
