import json
from unittest.mock import Mock, patch

from misp_modules.modules.expansion import ismalicious

HIT_PAYLOAD = {
    "malicious": True,
    "riskScore": {"score": 91, "level": "critical"},
    "sources": [
        {"name": "feed-a", "category": "c2"},
        {"name": "feed-b", "category": "botnet", "threatClass": "threat"},
        {"name": "feed-c", "category": "c2"},
    ],
}

EXPECTED_HEADERS = {
    "User-Agent": ismalicious.USER_AGENT,
    "X-API-KEY": "k",
    "Accept": "application/json",
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


def _summary(payload):
    with patch.object(ismalicious.requests, "get", return_value=MockResponse(payload)):
        result = ismalicious.handler(json.dumps(_query()))
    return [attribute["value"] for attribute in result["results"]["Attribute"]]


def test_ismalicious_returns_summary_attribute():
    with patch.object(ismalicious.requests, "get", return_value=MockResponse(HIT_PAYLOAD)) as mocked_get:
        result = ismalicious.handler(json.dumps(_query()))

    mocked_get.assert_called_once_with(
        "https://api.ismalicious.com/check",
        params={"query": "1.2.3.4", "enrichment": "standard"},
        headers=EXPECTED_HEADERS,
        timeout=30,
        allow_redirects=False,
    )
    values = [attribute["value"] for attribute in result["results"]["Attribute"]]
    assert values == ["malicious=True score=91 categories=['c2', 'botnet'] sources=3"]
    assert result["results"]["Attribute"][0]["comment"] == "isMalicious reputation summary"


def test_ismalicious_counts_threat_listings_only():
    payload = {
        "malicious": True,
        "riskScore": {"score": 70},
        "sources": [
            {"name": "honeypot", "category": "attack"},
            {"name": "azure-ip-ranges", "category": "infrastructure", "threatClass": "infrastructure"},
            {"name": "ad hosts", "category": "ads", "threatClass": "policy"},
            {"name": "known good", "category": "allowlist", "threatClass": "allowlist"},
            {"name": "feed-b", "categories": ["botnet", "attack"], "threatClass": "threat"},
        ],
    }
    assert _summary(payload) == ["malicious=True score=70 categories=['attack', 'botnet'] sources=2"]


def test_ismalicious_falls_back_to_primary_classification():
    payload = {
        "malicious": False,
        "riskScore": {"score": 12},
        "classification": {"primary": "unknown"},
        "sources": [{"name": "azure-ip-ranges", "category": "infrastructure", "threatClass": "infrastructure"}],
    }
    assert _summary(payload) == ["malicious=False score=12 categories=unknown sources=0"]


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
        headers=EXPECTED_HEADERS,
        timeout=30,
        allow_redirects=False,
    )


def test_ismalicious_user_agent_names_the_module_version():
    assert ismalicious.USER_AGENT == f"ismalicious-misp/{ismalicious.version()['version']} (+https://ismalicious.com)"


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


def test_ismalicious_reports_rejected_key_and_quota():
    with patch.object(ismalicious.requests, "get", return_value=MockResponse({"error": "Unauthorized"}, 401)):
        assert ismalicious.handler(json.dumps(_query())) == {
            "error": "isMalicious API rejected the API key (HTTP 401)."
        }
    with patch.object(ismalicious.requests, "get", return_value=MockResponse({"error": "Too Many Requests"}, 429)):
        assert ismalicious.handler(json.dumps(_query())) == {
            "error": "isMalicious API rate limit or quota exceeded (HTTP 429)."
        }


def test_ismalicious_does_not_follow_redirects():
    with patch.object(ismalicious.requests, "get", return_value=MockResponse(None, 301)):
        result = ismalicious.handler(json.dumps(_query(config={"api_key": "k", "api_url": "http://example.test"})))
    assert "redirect" in result["error"]


def test_ismalicious_reports_transport_failure():
    error = ismalicious.requests.exceptions.ConnectionError("refused")
    with patch.object(ismalicious.requests, "get", side_effect=error):
        result = ismalicious.handler(json.dumps(_query()))
    assert result["error"].startswith("isMalicious API request failed")


def test_ismalicious_rejects_invalid_input():
    assert ismalicious.handler(json.dumps({"module": "ismalicious"}))["error"].startswith(
        'This module requires an "attribute" field'
    )
    assert ismalicious.handler(json.dumps(_query(value="abc", type_="md5"))) == {"error": "Unsupported attribute type."}


def test_ismalicious_introspection_and_version():
    assert ismalicious.introspection() == ismalicious.mispattributes
    info = ismalicious.version()
    assert info["name"] == "isMalicious Lookup"
    assert info["logo"] == "ismalicious.png"
    assert "api_key" in info["config"]
    assert "expansion" in info["module-type"]
    assert "hover" in info["module-type"]
