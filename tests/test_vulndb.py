import json
from copy import deepcopy
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from misp_modules.modules.expansion import vulndb

CVE = "CVE-2024-12345"
CONFIG = {"apikey": "client-id", "apisecret": "client-secret"}
TOKEN = {"access_token": "test-bearer-token", "token_type": "Bearer"}
RECORD = {
    "vulndb_id": 12345,
    "title": "Example vulnerability",
    "description": "Vulnerability description",
    "solution": "Upgrade the product",
    "disclosure_date": "2024-01-01",
    "ext_references": [{"type": "Vendor Specific Advisory URL", "value": "https://example.org/advisory"}],
    "cvss_metrics": [{"score": 7.5, "calculated_cvss_base_score": 7.5, "source": "NVD"}],
    "vendors": [{"vendor": {"name": "Example vendor"}}],
    "products": [
        {
            "name": "Example product",
            "versions": [{"name": "1.0", "affected": "true", "cpe": [{"cpe": "cpe:/a:example:product:1.0"}]}],
        }
    ],
    "classifications": [{"longname": "Remote / Network Access"}],
}


def response(payload, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(payload).encode()
    result.headers["Content-Type"] = "application/json"
    return result


@pytest.fixture
def transport():
    # Exercise real requests preparation without making network calls.
    with patch.object(requests.Session, "send", autospec=True) as send:
        send.side_effect = [response(TOKEN), response({"results": [deepcopy(RECORD)]})]
        yield send


def run(config=None, vulnerability=CVE):
    return vulndb.handler(json.dumps({"vulnerability": vulnerability, "config": CONFIG if config is None else config}))


def values(result):
    return {item["types"]: item["values"] for item in result["results"]}


def test_oauth_client_credentials_and_flashpoint_lookup(transport):
    result = values(run())
    token_request = transport.call_args_list[0].args[1]
    lookup_request = transport.call_args_list[1].args[1]
    assert token_request.method == "POST"
    assert token_request.url == "https://vulndb.flashpoint.io/oauth/token"
    assert json.loads(token_request.body) == {
        "grant_type": "client_credentials",
        "client_id": CONFIG["apikey"],
        "client_secret": CONFIG["apisecret"],
    }
    assert token_request.headers["Content-Type"] == "application/json"
    assert lookup_request.method == "GET"
    assert urlsplit(lookup_request.url).path == f"/api/v1/vulnerabilities/{CVE}/find_by_cve_id"
    assert parse_qs(urlsplit(lookup_request.url).query) == {"show_cpe": ["true"]}
    assert lookup_request.headers["Authorization"] == "Bearer test-bearer-token"
    assert lookup_request.headers["Accept"] == "application/json"
    assert CONFIG["apisecret"] not in lookup_request.url
    assert lookup_request.body is None
    for call in transport.call_args_list:
        assert call.kwargs["timeout"] == 30
        assert call.kwargs["allow_redirects"] is False
        assert call.kwargs["verify"] is not False
    assert "Example vulnerability" in result["text"]
    assert "Vulnerability description" in result["text"]
    assert "Solution: Upgrade the product" in result["text"]
    assert "Disclosure date: 2024-01-01" in result["text"]
    assert "CVSS 7.5 (base: 7.5) (source: NVD)" in result["text"]
    assert any("Example product" in text for text in result["text"])
    assert any("Remote / Network Access" in text for text in result["text"])
    assert result["link"] == ["https://vulndb.flashpoint.io/vulnerabilities/12345", "https://example.org/advisory"]
    assert result["cpe"] == ["cpe:/a:example:product:1.0"]


@pytest.mark.parametrize("setting", [True, "true", "True", "TRUE"])
def test_discard_settings_keep_working(transport, setting):
    config = {**CONFIG, **{key: setting for key in vulndb.moduleconfig if key.startswith("discard_")}}
    result = values(run(config))
    assert result["text"] == ["Example vulnerability", "Vulnerability description", "Solution: Upgrade the product"]
    assert result["link"] == ["https://vulndb.flashpoint.io/vulnerabilities/12345"]
    assert "cpe" not in result
    assert not urlsplit(transport.call_args_list[1].args[1].url).query


@pytest.mark.parametrize(
    "config",
    [{}, None, {"apikey": "x"}, {"apisecret": "x"}, {**CONFIG, "apikey": ""}, {**CONFIG, "apisecret": " "}, []],
)
def test_missing_credentials_do_not_make_requests(transport, config):
    assert "error" in vulndb.handler(json.dumps({"vulnerability": CVE, "config": config}))
    transport.assert_not_called()


@pytest.mark.parametrize("query", ["{", "null", "[]", "{}", '{"vulnerability": 123}', '{"vulnerability": " "}'])
def test_invalid_input_does_not_make_requests(transport, query):
    assert "error" in vulndb.handler(query)
    transport.assert_not_called()


@pytest.mark.parametrize("stage", [0, 1])
@pytest.mark.parametrize(
    "status, message",
    [
        (400, "credentials"),
        (401, "credentials"),
        (403, "permissions"),
        (404, "No CVE"),
        (429, "rate limit"),
        (500, "HTTP response"),
        (302, "HTTP response"),
    ],
)
def test_http_errors_are_reported_without_secrets(transport, stage, status, message, caplog):
    replies = [response(TOKEN), response({"results": [RECORD]})]
    replies[stage] = response({"error": "client-secret test-bearer-token"}, status)
    transport.side_effect = replies
    result = run()
    assert message in result["error"]
    assert transport.call_count == stage + 1
    assert "client-secret" not in str(result) + caplog.text
    assert "test-bearer-token" not in str(result) + caplog.text


@pytest.mark.parametrize("stage", [0, 1])
@pytest.mark.parametrize("error, message", [(requests.Timeout, "timed out"), (requests.ConnectionError, "connect")])
def test_network_failures(transport, stage, error, message):
    transport.side_effect = [response(TOKEN)] * stage + [error("client-secret")]
    result = run()
    assert message in result["error"]
    assert "client-secret" not in result["error"]


@pytest.mark.parametrize("payload", [{}, {"access_token": ""}, {"access_token": None}, {"access_token": 123}, [], None])
def test_invalid_token_response_prevents_lookup(transport, payload):
    transport.side_effect = [response(payload)]
    assert run() == {"error": "Invalid response from VulnDB."}
    assert transport.call_count == 1


@pytest.mark.parametrize("stage", [0, 1])
def test_invalid_json_response(transport, stage):
    invalid = response({})
    invalid._content = b"<html>Not JSON</html>"
    transport.side_effect = [response(TOKEN)] * stage + [invalid]
    assert run() == {"error": "Invalid response from VulnDB."}


@pytest.mark.parametrize("payload", [{}, {"results": []}, {"results": None}, {"error": "not found"}])
def test_no_matching_cve(transport, payload):
    transport.side_effect = [response(TOKEN), response(payload)]
    assert run() == {"error": "No CVE information found."}


@pytest.mark.parametrize("payload", [None, [], {"results": [None]}, {"results": [{}]}])
def test_malformed_lookup_response(transport, payload):
    transport.side_effect = [response(TOKEN), response(payload)]
    assert run() == {"error": "Invalid response from VulnDB."}


def test_missing_optional_fields(transport):
    transport.side_effect = [response(TOKEN), response({"results": [{"title": "Title", "vulndb_id": 1}]})]
    assert values(run()) == {"text": ["Title"], "link": ["https://vulndb.flashpoint.io/vulnerabilities/1"], "cpe": []}


def test_module_contract():
    assert vulndb.handler() is False
    assert vulndb.introspection() == {"input": ["vulnerability"], "output": ["text", "link", "cpe"]}
    assert vulndb.version()["config"] == vulndb.moduleconfig
    assert vulndb.version()["references"] == ["https://vulndb.flashpoint.io/"]
