import json
from unittest.mock import Mock, patch

from misp_modules.modules.expansion import xposedornot

FREE_PAYLOAD = {
    "BreachMetrics": {"risk": [{"risk_label": "Critical", "risk_score": 100}]},
    "ExposedBreaches": {
        "breaches_details": [
            {
                "breach": "Sysco",
                "domain": "sysco.com",
                "industry": "Food",
                "password_risk": "unknown",
                "verified": "Yes",
                "xposed_data": "Email addresses;Names;Phone numbers",
                "xposed_date": "2026",
                "xposed_records": "2699339",
            },
            {
                "breach": "Yahoo",
                "domain": "yahoo.com",
                "password_risk": "plaintextpassword",
                "verified": "Yes",
                "xposed_data": "Email addresses;Passwords",
                "xposed_date": "2013",
                "xposed_records": "3000000000",
            },
        ]
    },
}

PLUS_PAYLOAD = {
    "email": "user+tag@example.com",
    "breaches": [
        {
            "breach_id": "Sysco",
            "breached_date": "2026",
            "domain": "sysco.com",
            "password_risk": "unknown",
            "verified": "Yes",
            "xposed_data": "Email addresses;Names",
            "xposed_records": "2699339",
        }
    ],
}


class MockResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload

    def raise_for_status(self):
        return None


def _query(value="test@example.com", config=None):
    attribute = {"type": "email", "value": value, "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    return {"module": "xposedornot", "attribute": attribute, "config": config or {}}


def _objects(result, name):
    return [misp_object for misp_object in result["results"]["Object"] if misp_object["name"] == name]


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def test_xposedornot_free_api_returns_one_breach_object_per_breach():
    with patch.object(xposedornot.requests, "get", return_value=MockResponse(FREE_PAYLOAD)) as mocked_get:
        result = xposedornot.handler(json.dumps(_query()))

    mocked_get.assert_called_once_with(
        "https://api.xposedornot.com/v1/breach-analytics",
        params={"email": "test@example.com"},
        headers={"User-Agent": "misp-modules"},
        timeout=30,
    )
    breaches = _objects(result, "breach")
    assert {value for obj in breaches for relation, value in _values(obj) if relation == "name"} == {"Sysco", "Yahoo"}

    sysco = next(obj for obj in breaches if ("name", "Sysco") in _values(obj))
    values = _values(sysco)
    assert ("source", "XposedOrNot") in values
    assert ("domain", "sysco.com") in values
    assert ("pwn-count", "2699339") in values
    assert ("verified", "True") in values
    # one attribute per data class, not one semicolon-joined string
    assert {value for relation, value in values if relation == "data-classes"} == {
        "Email addresses",
        "Names",
        "Phone numbers",
    }
    # a bare year is anchored to its first day
    assert ("breach-date", "2026-01-01T00:00:00") in values
    # password_risk has no relation of its own
    assert ("description", "password storage risk: unknown") in values


def test_xposedornot_breach_objects_reference_the_input_attribute():
    with patch.object(xposedornot.requests, "get", return_value=MockResponse(FREE_PAYLOAD)):
        result = xposedornot.handler(json.dumps(_query()))
    for misp_object in result["results"]["Object"]:
        references = [(r["referenced_uuid"], r["relationship_type"]) for r in misp_object["ObjectReference"]]
        assert references == [("5b582d80-7a7e-4b6a-9f22-77656e72bb3b", "related-to")]


def test_xposedornot_risk_label_becomes_a_reputation_object():
    with patch.object(xposedornot.requests, "get", return_value=MockResponse(FREE_PAYLOAD)):
        result = xposedornot.handler(json.dumps(_query()))
    values = _values(_objects(result, "reputation")[0])
    assert ("source", "XposedOrNot") in values
    assert ("classification", "Critical") in values


def test_xposedornot_plus_api_used_when_key_configured_and_email_is_url_encoded():
    with patch.object(xposedornot.requests, "get", return_value=MockResponse(PLUS_PAYLOAD)) as mocked_get:
        result = xposedornot.handler(json.dumps(_query(value="User+Tag@Example.com", config={"api_key": "k"})))

    mocked_get.assert_called_once_with(
        "https://plus-api.xposedornot.com/v3/check-email/user%2Btag%40example.com",
        params={"detailed": "true"},
        headers={"User-Agent": "misp-modules", "x-api-key": "k"},
        timeout=30,
    )
    breaches = _objects(result, "breach")
    assert ("name", "Sysco") in _values(breaches[0])
    # the Plus API carries no risk label
    assert _objects(result, "reputation") == []


def test_xposedornot_clean_email_returns_informative_error():
    for payload, status_code in ((None, 404), ({"ExposedBreaches": {"breaches_details": []}}, 200)):
        with patch.object(xposedornot.requests, "get", return_value=MockResponse(payload, status_code)):
            result = xposedornot.handler(json.dumps(_query()))
        assert result == {"error": "No breach found on XposedOrNot for this email address."}


def test_xposedornot_rate_limit_mentions_optional_key():
    with patch.object(xposedornot.requests, "get", return_value=MockResponse(None, 429)):
        result = xposedornot.handler(json.dumps(_query()))
    assert "rate limit" in result["error"]
    assert "api_key" in result["error"]


def test_xposedornot_reports_http_error():
    response = Mock(payload=None)
    response.status_code = 500
    response.raise_for_status.side_effect = xposedornot.requests.exceptions.HTTPError(response=response)
    with patch.object(xposedornot.requests, "get", return_value=response):
        result = xposedornot.handler(json.dumps(_query()))
    assert result == {"error": "XposedOrNot API returned HTTP status 500."}


def test_xposedornot_rejects_invalid_input():
    assert xposedornot.handler(json.dumps({"module": "xposedornot"}))["error"].startswith(
        'This module requires an "attribute" field'
    )
    assert xposedornot.handler(json.dumps(_query(value="not-an-email"))) == {
        "error": "The provided attribute value is not a valid email address."
    }
