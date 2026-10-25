import json
from unittest.mock import Mock

import pytest

from misp_modules.modules.expansion import hygiene as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-service-secret"
CONFIG = {}
KIND, VALUE = ("domain", "example.com")


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


@pytest.fixture
def lists_path(tmp_path):
    for name, kind, entries in [
        ("cidr", "cidr", ["1.1.1.0/24"]),
        ("domain", "hostname", ["example.com"]),
        ("string", "string", ["a" * 64]),
    ]:
        folder = tmp_path / "lists" / name
        folder.mkdir(parents=True)
        (folder / "list.json").write_text(
            json.dumps({"name": name, "description": "Example list", "version": 1, "type": kind, "list": entries})
        )
    return str(tmp_path)


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("ip-dst", "1.1.1.1", "cidr"),
        ("domain", "sub.example.com", "domain"),
        ("url", "https://sub.example.com/path", "domain"),
        ("sha256", "a" * 64, "string"),
    ],
)
def test_local_smart_match(lists_path, kind, value, expected):
    result = module.handler(query(kind=kind, value=value, config={"warninglists_path": lists_path}))
    assert_source(result)
    match = values(objects(result, "warninglist-match")[0])
    assert match["warninglist-name"] == expected
    assert match["warninglist-version"] == "1"
    assert match["matching-mode"] == "smart"


@pytest.mark.parametrize(
    "kind,value", [("ip-dst", "1.1.2.1"), ("domain", "evil-example.com"), ("domain", "example.com.evil.test")]
)
def test_no_false_cidr_or_suffix_match(lists_path, kind, value):
    result = module.handler(query(kind=kind, value=value, config={"warninglists_path": lists_path}))
    assert_source(result)
    assert not objects(result, "warninglist-match")


def test_exact_mode_does_not_expand_cidr(lists_path):
    result = module.handler(
        query(kind="ip-dst", value="1.1.1.1", config={"warninglists_path": lists_path, "slow_search": "false"})
    )
    assert_source(result)
    assert not objects(result, "warninglist-match")


def test_missing_path_does_not_fall_back_to_bundled_lists(tmp_path):
    assert "error" in module.handler(query(config={"warninglists_path": str(tmp_path / "missing")}))


def test_bad_matching_mode():
    assert "error" in module.handler(query(config={"slow_search": "maybe"}))


def test_matching_attributes_are_enforced_before_limit(tmp_path):
    folder = tmp_path / "lists" / "email-only"
    folder.mkdir(parents=True)
    data = {
        "name": "Email only",
        "description": "Disposable email domains",
        "version": 1,
        "type": "substring",
        "list": ["example.com"],
        "matching_attributes": ["email-src", "email-dst"],
    }
    (folder / "list.json").write_text(json.dumps(data))
    config = {"warninglists_path": str(tmp_path), "max_results": 1}
    domain = module.handler(query(kind="domain", value="example.com", config=config))
    email = module.handler(query(kind="email-src", value="User@example.com", config=config))
    assert_source(domain)
    assert not objects(domain, "warninglist-match")
    assert values(objects(email, "warninglist-match")[0])["value"] == "User@example.com"


@pytest.mark.parametrize(
    "email,expected", [("User@EXAMPLE.COM", "User@example.com"), ("User@bücher.example", "User@xn--bcher-kva.example")]
)
def test_email_domain_normalization(tmp_path, email, expected):
    folder = tmp_path / "lists" / "domain"
    folder.mkdir(parents=True)
    (folder / "list.json").write_text(
        json.dumps(
            {
                "name": "Email domains",
                "description": "Example",
                "version": 1,
                "type": "substring",
                "list": [expected.split("@")[1]],
                "matching_attributes": ["email-src"],
            }
        )
    )
    result = module.handler(query(kind="email-src", value=email, config={"warninglists_path": str(tmp_path)}))
    assert_source(result)
    assert values(objects(result, "warninglist-match")[0])["value"] == expected
