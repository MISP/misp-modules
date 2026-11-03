import json
from unittest.mock import Mock

import pytest
import requests
from pymisp import MISPAttribute

from misp_modules.modules.expansion import flowintel


def query(config=None, **attribute):
    return json.dumps(
        {
            "attribute": {"type": "domain", "value": "example.org", **attribute},
            "config": {"url": "https://flowintel.example/analysis/", "apikey": "test-key", **(config or {})},
        }
    )


@pytest.fixture
def post(monkeypatch):
    mock = Mock(return_value=Mock(status_code=200, json=Mock(return_value={"cases": []})))
    monkeypatch.setattr(flowintel.requests, "post", mock)
    return mock


def test_case_links_and_request_contract(post):
    post.return_value.json.return_value = {
        "cases": [
            {"id": 12, "title": "Investigation", "completed": False},
            {"id": 12, "title": "Duplicate"},
            {"id": 24, "title": "Completed case", "completed": True},
        ]
    }
    result = flowintel.handler(query())
    attributes = result["results"]["Attribute"]
    assert [a["value"] for a in attributes] == [
        "https://flowintel.example/analysis/case/12",
        "https://flowintel.example/analysis/case/24",
    ]
    assert attributes[0]["comment"] == "Flowintel case #12: Investigation"
    for attribute in attributes:
        parsed = MISPAttribute()
        parsed.from_dict(**attribute)
        assert parsed.type == "link"
        assert parsed.category == "External analysis"
        assert parsed.to_ids is False
    post.assert_called_once_with(
        "https://flowintel.example/analysis/api/case/search/attribute",
        headers={"X-API-KEY": "test-key", "Accept": "application/json"},
        json={"value": "example.org"},
        verify=True,
        timeout=30,
        allow_redirects=False,
    )


def test_no_hits(post):
    assert flowintel.handler(query()) == {"results": {"Attribute": []}}


@pytest.mark.parametrize("setting, expected", [("false", False), (False, False), ("true", True), ("", True)])
def test_tls_and_timeout_configuration(post, setting, expected):
    flowintel.handler(query(config={"verify_ssl": setting, "timeout": "9"}))
    assert post.call_args.kwargs["verify"] is expected
    assert post.call_args.kwargs["timeout"] == 9


@pytest.mark.parametrize("value", ["sample.exe|" + "a" * 64, "literal_%", " value with spaces "])
def test_value_is_sent_verbatim(post, value):
    flowintel.handler(query(type="text", value=value))
    assert post.call_args.kwargs["json"] == {"value": value}


@pytest.mark.parametrize(
    "config",
    [
        {"url": ""},
        {"apikey": ""},
        {"url": "ftp://example.org"},
        {"url": "https://user:password@example.org"},
        {"url": "https://example.org?query=1"},
        {"url": "https://example.org#fragment"},
        {"url": "https://[invalid"},
        {"verify_ssl": "invalid"},
        {"timeout": "invalid"},
        {"timeout": "-1"},
        {"timeout": 0},
    ],
)
def test_invalid_configuration_does_not_send_requests(post, config):
    assert "error" in flowintel.handler(query(config=config))
    post.assert_not_called()


@pytest.mark.parametrize("payload", ["not JSON", "[]", "{}", '{"attribute": []}', '{"attribute": {}}'])
def test_invalid_requests(post, payload):
    assert "error" in flowintel.handler(payload)
    post.assert_not_called()


@pytest.mark.parametrize("attribute", [{"type": "attachment"}, {"value": ""}, {"value": "  "}, {"value": None}])
def test_invalid_attributes(post, attribute):
    assert "error" in flowintel.handler(query(**attribute))
    post.assert_not_called()


@pytest.mark.parametrize("status", [301, 400, 401, 403, 404, 500])
def test_http_failures_are_errors_not_misses(post, status):
    post.return_value.status_code = status
    result = flowintel.handler(query())
    assert "error" in result
    assert "results" not in result
    post.return_value.json.assert_not_called()


@pytest.mark.parametrize("exception", [requests.Timeout, requests.ConnectionError, requests.exceptions.SSLError])
def test_network_errors_do_not_expose_secrets(post, exception):
    post.side_effect = exception("secret in exception text")
    result = flowintel.handler(query())
    assert "error" in result
    assert "secret" not in result["error"]


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"cases": None},
        {"cases": [None]},
        {"cases": [{"id": "../evil"}]},
        {"cases": [{"id": True}]},
        {"cases": [{"id": 0}]},
    ],
)
def test_invalid_responses(post, payload):
    post.return_value = Mock(status_code=200, json=Mock(return_value=payload))
    assert "error" in flowintel.handler(query())


def test_invalid_json_response(post):
    post.return_value = Mock(status_code=200, json=Mock(side_effect=requests.exceptions.JSONDecodeError("bad", "", 0)))
    assert flowintel.handler(query()) == {"error": "Flowintel returned invalid JSON."}


def test_module_metadata():
    assert flowintel.handler() is False
    assert flowintel.introspection()["format"] == "misp_standard"
    assert flowintel.version()["config"] == flowintel.moduleconfig
    assert flowintel.version()["module-type"] == ["expansion", "hover"]
