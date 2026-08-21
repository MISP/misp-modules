import json
from unittest.mock import Mock, patch

from misp_modules.modules.expansion import ismalicious

HIT_PAYLOAD = {
    "malicious": True,
    "riskScore": {"score": 91},
    "categories": ["c2"],
    "sources": [{"name": "feed-a"}, {"name": "feed-b"}],
}


class MockResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise ismalicious.requests.exceptions.HTTPError(response=self)


def _query(value="1.2.3.4", type_="ip-src", config=None):
    attribute = {"type": type_, "value": value, "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    if config is None:
        config = {"api_key": "k"}
    return {"module": "ismalicious", "attribute": attribute, "config": config}


def test_ismalicious_returns_summary_attribute():
    with patch.object(ismalicious.requests, "get", return_value=MockResponse(HIT_PAYLOAD)) as mocked_get:
        result = ismalicious.handler(json.dumps(_query()))

    mocked_get.assert_called_once_with(
        "https://api.ismalicious.com/check",
        params={"query": "1.2.3.4", "enrichment": "standard"},
        headers={"User-Agent": "misp-modules", "X-API-KEY": "k", "Accept": "application/json"},
        timeout=30,
    )
    values = [attribute["value"] for attribute in result["results"]["Attribute"]]
    assert values == ["malicious=True score=91 categories=['c2'] sources=2"]
    assert result["results"]["Attribute"][0]["comment"] == "isMalicious reputation summary"


def test_ismalicious_uses_domain_side_of_composite_and_custom_api_url():
    query = _query(
        value="evil.example|1.2.3.4",
        type_="domain|ip",
        config={"api_key": "k", "api_url": "https://example.test/"},
    )
    with patch.object(ismalicious.requests, "get", return_value=MockResponse({"malicious": False})) as mocked_get:
        ismalicious.handler(json.dumps(query))

    mocked_get.assert_called_once_with(
        "https://example.test/check",
        params={"query": "evil.example", "enrichment": "standard"},
        headers={"User-Agent": "misp-modules", "X-API-KEY": "k", "Accept": "application/json"},
        timeout=30,
    )


def test_ismalicious_missing_api_key():
    with patch.object(ismalicious.requests, "get") as mocked_get:
        result = ismalicious.handler(json.dumps(_query(config={})))
    mocked_get.assert_not_called()
    assert result == {"error": "An isMalicious API key is required (set api_key in the module config)."}


def test_ismalicious_reports_http_error():
    response = Mock(payload=None)
    response.status_code = 500
    response.raise_for_status.side_effect = ismalicious.requests.exceptions.HTTPError(response=response)
    with patch.object(ismalicious.requests, "get", return_value=response):
        result = ismalicious.handler(json.dumps(_query()))
    assert result == {"error": "isMalicious API returned HTTP status 500."}


def test_ismalicious_rejects_invalid_input():
    assert ismalicious.handler(json.dumps({"module": "ismalicious"}))["error"].startswith(
        'This module requires an "attribute" field'
    )
    assert ismalicious.handler(json.dumps(_query(value="abc", type_="md5"))) == {"error": "Unsupported attribute type."}


def test_ismalicious_introspection_and_version():
    assert ismalicious.introspection() == ismalicious.mispattributes
    info = ismalicious.version()
    assert info["name"] == "isMalicious Lookup"
    assert "api_key" in info["config"]
    assert "expansion" in info["module-type"]
    assert "hover" in info["module-type"]
