import json
from unittest.mock import patch

from misp_modules.modules.expansion import hibp

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"

_BREACHES = [
    {
        "Name": "Adobe",
        "Title": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "AddedDate": "2013-12-04T00:00:00Z",
        "ModifiedDate": "2022-05-15T23:52:49Z",
        "PwnCount": 152445165,
        "Description": "In October 2013, 153 million Adobe accounts were breached.",
        "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
        "IsVerified": True,
        "IsSensitive": False,
    },
    {
        "Name": "LinkedIn",
        "Title": "LinkedIn",
        "Domain": "linkedin.com",
        "BreachDate": "2012-05-05",
        "PwnCount": 164611595,
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
        "IsSensitive": False,
    },
]


class MockResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        if self.payload is None:
            raise ValueError("No JSON")
        return self.payload


def _run(attribute, payload=_BREACHES, status_code=200, config=None):
    query = json.dumps(
        {"module": "hibp", "attribute": attribute, "config": config if config is not None else {"api_key": "k"}}
    )
    with patch.object(hibp.requests, "get", return_value=MockResponse(payload, status_code)) as mock_get:
        return hibp.handler(query), mock_get


def _objects(result):
    return [obj for obj in result["results"]["Object"] if obj["name"] == "breach"]


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def test_one_breach_object_per_breach():
    attribute = {"type": "email-src", "value": "info@circl.lu", "uuid": UUID}
    result, _ = _run(attribute)
    breaches = _objects(result)
    assert len(breaches) == 2
    assert {value for obj in breaches for relation, value in _values(obj) if relation == "name"} == {
        "Adobe",
        "LinkedIn",
    }


def test_breach_object_carries_the_hibp_fields():
    attribute = {"type": "email-src", "value": "info@circl.lu", "uuid": UUID}
    result, _ = _run(attribute)
    adobe = next(obj for obj in _objects(result) if ("name", "Adobe") in _values(obj))
    values = _values(adobe)
    assert ("title", "Adobe") in values
    assert ("domain", "adobe.com") in values
    assert ("pwn-count", "152445165") in values
    assert ("verified", "True") in values
    assert ("sensitive", "False") in values
    assert ("source", "Have I Been Pwned") in values
    assert ("breach-date", "2013-10-04T00:00:00") in values
    assert {value for relation, value in values if relation == "data-classes"} == {
        "Email addresses",
        "Password hints",
        "Passwords",
        "Usernames",
    }


def test_missing_fields_are_skipped():
    attribute = {"type": "email-src", "value": "info@circl.lu", "uuid": UUID}
    result, _ = _run(attribute)
    linkedin = next(obj for obj in _objects(result) if ("name", "LinkedIn") in _values(obj))
    relations = {relation for relation, _ in _values(linkedin)}
    assert "added-date" not in relations
    assert "description" not in relations


def test_the_request_asks_for_the_full_response():
    attribute = {"type": "email-src", "value": "info@circl.lu", "uuid": UUID}
    _, mock_get = _run(attribute)
    assert mock_get.call_args.kwargs["params"] == {"truncateResponse": "false"}


def test_objects_reference_the_input_attribute():
    attribute = {"type": "email-src", "value": "info@circl.lu", "uuid": UUID}
    result, _ = _run(attribute)
    for misp_object in _objects(result):
        references = [(r["referenced_uuid"], r["relationship_type"]) for r in misp_object["ObjectReference"]]
        assert references == [(UUID, "related-to")]


def test_not_found_returns_an_error_dict():
    attribute = {"type": "email-src", "value": "info@circl.lu", "uuid": UUID}
    result, _ = _run(attribute, payload=None, status_code=404)
    assert isinstance(result, dict) and "error" in result


def test_empty_breach_list_returns_an_error_dict():
    attribute = {"type": "email-src", "value": "info@circl.lu", "uuid": UUID}
    result, _ = _run(attribute, payload=[])
    assert isinstance(result, dict) and "error" in result


def test_other_http_status_returns_an_error_dict():
    attribute = {"type": "email-src", "value": "info@circl.lu", "uuid": UUID}
    result, _ = _run(attribute, payload=None, status_code=401)
    assert isinstance(result, dict)
    assert result["error"] == "haveibeenpwned.com API not accessible (HTTP 401)"


def test_missing_api_key_returns_error():
    attribute = {"type": "email-src", "value": "info@circl.lu", "uuid": UUID}
    result, _ = _run(attribute, config={})
    assert result["error"] == "Have I Been Pwned authentication is incomplete (no API key)"


def test_wrong_attribute_type_returns_error():
    attribute = {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "uuid": UUID}
    result, _ = _run(attribute)
    assert "error" in result


def test_introspection_and_version():
    assert hibp.introspection() == hibp.mispattributes
    assert hibp.mispattributes["format"] == "misp_standard"
    assert hibp.version()["name"] == "Have I Been Pwned Lookup"
