import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from misp_modules.modules.expansion import intel471

CONFIG = {"email": "analyst@example.org", "authkey": "test-api-key"}
HASH = "d41d8cd98f00b204e9800998ecf8427e"


def response(payload, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(payload).encode()
    return result


def run(payload, kind="domain", value="example.org", config=CONFIG, status=200):
    query = {kind: value}
    if config is not None:
        query["config"] = config
    with patch("pyintel471.api.requests.Session.send", return_value=response(payload, status)) as send:
        result = intel471.handler(json.dumps(query))
    return result, send


def freetext(result):
    assert result["results"][0]["types"] == ["freetext"]
    return result["results"][0]["values"]


@pytest.mark.parametrize("kind", intel471.mispattributes["input"])
def test_all_supported_attributes_use_global_text_search(kind):
    result, send = run({"newsTotalCount": 1, "news": [{"title": "example.org"}]}, kind=kind)
    request = send.call_args.args[0]
    url = urlsplit(request.url)
    assert request.method == "GET"
    assert url.scheme == "https"
    assert url.netloc == "api.intel471.com"
    assert url.path == "/v1/search"
    assert parse_qs(url.query) == {"text": ["example.org"]}
    assert json.loads(freetext(result))["news"][0]["title"] == "example.org"


@pytest.mark.parametrize(
    "value", ["https://example.org/a?x=1&y=2#fragment", "user+tag@example.org", "Jane Doe", "a%20b"]
)
def test_search_value_is_encoded_as_one_parameter(value):
    _, send = run({"reports": [{"title": value}]}, value=value)
    assert parse_qs(urlsplit(send.call_args.args[0].url).query) == {"text": [value]}


@pytest.mark.parametrize("collection", ["indicators", "events", "reports", "posts", "news", "credential_sets"])
def test_results_outside_iocs_are_not_reported_as_missing(collection):
    payload = {"iocTotalCount": 0, "iocs": [], collection: [{"value": "example.org"}]}
    result, _ = run(payload)
    assert json.loads(freetext(result))[collection] == payload[collection]


def test_nested_uids_are_removed_but_real_hashes_are_preserved():
    payload = {
        "iocTotalCount": 1,
        "iocs": [{"uid": HASH, "value": "example.org", "links": {"actors": [{"uid": HASH, "handle": "actor"}]}}],
        "indicatorTotalCount": 1,
        "indicators": [{"uid": HASH, "data": {"md5": HASH}, "threat": {"uid": HASH, "name": "malware"}}],
        "reports": [{"title": "report without uid or links"}],
    }
    result, _ = run(payload)
    cleaned = json.loads(freetext(result))
    assert cleaned["iocs"] == [{"value": "example.org", "links": {"actors": [{"handle": "actor"}]}}]
    assert cleaned["indicators"] == [{"data": {"md5": HASH}, "threat": {"name": "malware"}}]
    assert cleaned["reports"] == payload["reports"]


@pytest.mark.parametrize(
    "payload", [{}, {"iocTotalCount": 0}, {"iocTotalCount": 0, "iocs": [], "indicators": [], "news": None}]
)
def test_empty_search_returns_existing_message(payload):
    result, _ = run(payload)
    assert freetext(result) == "Nothing has been found."


@pytest.mark.parametrize(
    "config", [None, {}, {"email": "analyst@example.org"}, {"authkey": "key"}, {"email": "", "authkey": ""}]
)
def test_missing_authentication_does_not_query(config):
    result, send = run({}, config=config)
    assert result == {"error": "Intel 471 authentication is missing"}
    send.assert_not_called()


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_http_errors_are_not_reported_as_no_results(status):
    result, _ = run({"error": "private service details"}, status=status)
    assert "error" in result
    assert "private service details" not in result["error"]


@pytest.mark.parametrize("payload", [[], None, "invalid response"])
def test_invalid_response_shape_returns_error(payload):
    result, _ = run(payload)
    assert "error" in result


def test_invalid_json_returns_error():
    reply = response({})
    reply._content = b"not JSON"
    with patch("pyintel471.api.requests.Session.send", return_value=reply):
        result = intel471.handler(json.dumps({"domain": "example.org", "config": CONFIG}))
    assert "error" in result


def test_connection_error_returns_error():
    with patch("pyintel471.api.requests.Session.send", side_effect=requests.ConnectionError("private details")):
        result = intel471.handler(json.dumps({"domain": "example.org", "config": CONFIG}))
    assert "error" in result
    assert "private details" not in result["error"]


def test_discovery_and_unsupported_type():
    assert intel471.handler(False) is False
    assert intel471.introspection() == intel471.mispattributes
    assert intel471.version()["config"] == ["email", "authkey"]
    result, send = run({}, kind="unsupported")
    assert result == {"error": "Unsupported attributes type"}
    send.assert_not_called()
