import json
from types import SimpleNamespace
from unittest.mock import patch

from misp_modules.modules.expansion import socialscan

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


def _result(platform, success=True, valid=True, available=False):
    return SimpleNamespace(platform=platform, success=success, valid=valid, available=available)


def _run(attribute, results):
    query = json.dumps({"module": "socialscan", "attribute": attribute, "config": {}})
    with patch.object(socialscan, "sync_execute_queries") as mock_query:
        mock_query.return_value = results
        return socialscan.handler(query), mock_query


def _objects(result):
    return [obj for obj in result["results"]["Object"] if obj["name"] == "user-account"]


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def test_one_object_per_platform_with_an_account():
    attribute = {"type": "target-user", "value": "johndoe", "uuid": UUID}
    results = [_result("Twitter"), _result("GitHub"), _result("Reddit", available=True)]
    result, _ = _run(attribute, results)

    objects = _objects(result)
    assert len(objects) == 2
    account_types = {value for obj in objects for relation, value in _values(obj) if relation == "account-type"}
    assert account_types == {"Twitter", "GitHub"}
    assert ("username", "johndoe") in _values(objects[0])


def test_failed_and_invalid_platforms_produce_no_object():
    attribute = {"type": "target-user", "value": "johndoe", "uuid": UUID}
    results = [_result("Twitter", success=False), _result("GitHub", valid=False), _result("Reddit")]
    result, _ = _run(attribute, results)
    assert len(_objects(result)) == 1


def test_email_input_fills_email_and_user_id():
    attribute = {"type": "email-src", "value": "john@example.com", "uuid": UUID}
    result, _ = _run(attribute, [_result("Spotify")])
    values = _values(_objects(result)[0])
    assert ("email", "john@example.com") in values
    # user-account requires one of username / user-id / password
    assert ("user-id", "john@example.com") in values


def test_objects_reference_the_input_attribute():
    attribute = {"type": "target-user", "value": "johndoe", "uuid": UUID}
    result, _ = _run(attribute, [_result("Twitter")])
    references = _objects(result)[0]["ObjectReference"]
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in references] == [(UUID, "related-to")]


def test_github_username_only_queries_github():
    attribute = {"type": "github-username", "value": "johndoe", "uuid": UUID}
    _, mock_query = _run(attribute, [_result("GitHub")])
    assert mock_query.call_args.kwargs["platforms"] == [socialscan.Platforms.GITHUB]


def test_no_account_anywhere_returns_a_message():
    attribute = {"type": "target-user", "value": "johndoe", "uuid": UUID}
    result, _ = _run(attribute, [_result("Twitter", available=True)])
    assert "error" in result


def test_wrong_attribute_type_returns_error():
    attribute = {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "uuid": UUID}
    result, _ = _run(attribute, [_result("Twitter")])
    assert "error" in result


def test_introspection_and_version():
    assert socialscan.introspection() == socialscan.mispattributes
    assert socialscan.mispattributes["format"] == "misp_standard"
    assert socialscan.version()["name"] == "Socialscan Lookup"
