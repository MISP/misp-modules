import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import xforceexchange

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
INPUTS = [
    ("ip-src", "192.0.2.1"),
    ("ip-dst", "192.0.2.1"),
    ("domain", "example.com"),
    ("hostname", "www.example.com"),
    ("url", "https://example.com/sample"),
    ("md5", "a" * 32),
    ("sha1", "b" * 40),
    ("sha256", "c" * 64),
    ("vulnerability", "CVE-2020-0001"),
]
ACCESS_DENIED = (
    "Access denied, please check if your authentication is valid and if you did not reach the limit of queries."
)
DNS = {"Passive": {"query": "example.com", "records": [{"value": "192.0.2.1"}]}}
MALWARE = {
    "malware": [
        {"filepath": "sample.exe", "md5": "a" * 32, "uri": "https://example.com/sample", "domain": "example.com"}
    ]
}


def query(kind, value):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID},
            "config": {"apikey": "test-key", "apipassword": "test-password"},
        }
    )


def response(payload=None, status=200):
    reply = Mock(status_code=status)
    reply.json.return_value = payload
    return reply


@pytest.mark.parametrize("kind,value", INPUTS)
@pytest.mark.parametrize(
    "status,error",
    [
        (403, ACCESS_DENIED),
        (404, "No result found for your query."),
        (429, "An error with the API has occurred."),
        (500, "An error with the API has occurred."),
    ],
)
def test_http_errors(kind, value, status, error):
    reply = response(status=status)
    with patch.object(xforceexchange.requests, "get", return_value=reply):
        result = xforceexchange.handler(query(kind, value))

    assert result == {"error": error}
    assert json.loads(json.dumps(result)) == result
    reply.json.assert_not_called()


@pytest.mark.parametrize("kind,value", INPUTS)
@pytest.mark.parametrize("exception", [requests.ConnectionError, requests.Timeout])
def test_request_errors_are_json_serializable(kind, value, exception):
    with patch.object(xforceexchange.requests, "get", side_effect=exception("Request failed")):
        result = xforceexchange.handler(query(kind, value))

    assert result == {"error": "Request failed"}
    assert json.loads(json.dumps(result)) == result


@pytest.mark.parametrize("kind,value", INPUTS)
def test_invalid_json_is_an_error(kind, value):
    reply = response()
    reply.json.side_effect = requests.exceptions.JSONDecodeError("Expecting value", "", 0)
    with patch.object(xforceexchange.requests, "get", return_value=reply):
        result = xforceexchange.handler(query(kind, value))

    assert result == {"error": "Invalid JSON response from Xforce Exchange."}
    assert json.loads(json.dumps(result)) == result


@pytest.mark.parametrize("kind,value", INPUTS)
def test_null_response_has_no_data(kind, value):
    with patch.object(xforceexchange.requests, "get", return_value=response()):
        assert xforceexchange.handler(query(kind, value)) == {"error": "No additional data found on Xforce Exchange."}


@pytest.mark.parametrize("payload", [{}, {"Passive": None}, {"Passive": {}}, {"Passive": {"records": []}}])
def test_empty_dns_response_has_no_data(payload):
    with patch.object(xforceexchange.requests, "get", return_value=response(payload)):
        assert xforceexchange.handler(query("domain", "example.com")) == {
            "error": "No additional data found on Xforce Exchange."
        }


@pytest.mark.parametrize("kind,value", INPUTS[:4])
def test_successful_dns_lookup(kind, value):
    dns = DNS
    if kind in ("ip-src", "ip-dst"):
        dns = {"Passive": {"query": value, "records": [{"value": "example.com"}]}}
    with patch.object(xforceexchange.requests, "get", return_value=response(dns)):
        result = xforceexchange.handler(query(kind, value))

    (obj,) = result["results"]["Object"]
    assert obj["name"] == "domain-ip"
    attributes = {attr["object_relation"]: attr["value"] for attr in obj["Attribute"]}
    assert attributes == {"domain": "example.com", "ip": "192.0.2.1"}
    assert result["results"]["Attribute"][0]["uuid"] == UUID


@pytest.mark.parametrize("kind,value", [INPUTS[0], INPUTS[1], INPUTS[4]])
def test_failed_dns_lookup_still_returns_malware(kind, value):
    with patch.object(xforceexchange.requests, "get", side_effect=[response(status=403), response(MALWARE)]) as get:
        result = xforceexchange.handler(query(kind, value))

    assert get.call_count == 2
    assert {obj["name"] for obj in result["results"]["Object"]} == {"file", "url"}
    assert result["results"]["Attribute"][0]["uuid"] == UUID
    assert "error" not in result


@pytest.mark.parametrize("kind,value", [INPUTS[0], INPUTS[1], INPUTS[4]])
def test_failed_malware_lookup_preserves_dns_results(kind, value):
    with patch.object(xforceexchange.requests, "get", side_effect=[response(DNS), response(status=500)]):
        result = xforceexchange.handler(query(kind, value))

    assert [obj["name"] for obj in result["results"]["Object"]] == ["domain-ip"]
    assert "error" not in result
