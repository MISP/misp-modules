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


def test_xposedornot_free_api_returns_breach_attributes():
    with patch.object(xposedornot.requests, "get", return_value=MockResponse(FREE_PAYLOAD)) as mocked_get:
        result = xposedornot.handler(json.dumps(_query()))

    mocked_get.assert_called_once_with(
        "https://api.xposedornot.com/v1/breach-analytics",
        params={"email": "test@example.com"},
        headers={"User-Agent": "misp-modules"},
        timeout=30,
    )
    attributes = result["results"]["Attribute"]
    values = [attribute["value"] for attribute in attributes]
    assert values[0] == "Email exposed in 2 data breaches (XposedOrNot), first: 2013, latest: 2026, risk: Critical"
    assert "Sysco" in values and "Yahoo" in values
    sysco = next(attribute for attribute in attributes if attribute["value"] == "Sysco")
    assert sysco["type"] == "text"
    assert "2,699,339 records" in sysco["comment"]
    assert "password risk: unknown" in sysco["comment"]


def test_xposedornot_plus_api_used_when_key_configured_and_email_is_url_encoded():
    with patch.object(xposedornot.requests, "get", return_value=MockResponse(PLUS_PAYLOAD)) as mocked_get:
        result = xposedornot.handler(json.dumps(_query(value="User+Tag@Example.com", config={"api_key": "k"})))

    mocked_get.assert_called_once_with(
        "https://plus-api.xposedornot.com/v3/check-email/user%2Btag%40example.com",
        params={"detailed": "true"},
        headers={"User-Agent": "misp-modules", "x-api-key": "k"},
        timeout=30,
    )
    values = [attribute["value"] for attribute in result["results"]["Attribute"]]
    assert "Sysco" in values


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
