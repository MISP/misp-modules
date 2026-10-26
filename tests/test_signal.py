import json
from types import SimpleNamespace

import pytest
import requests

from misp_modules.modules.action_mod import signal


def workflow(**params):
    return {
        "params": {
            "signal_api_url": "http://localhost:8080/proxy/",
            "sender_number": "+33123456789",
            "recipients": "+33123456780, group.YWJjZA==",
            "message_template": "Event: {{ Event.info }}",
            **params,
        },
        "data": {"Event": {"info": "Example event"}},
    }


@pytest.fixture
def transport(monkeypatch):
    state = SimpleNamespace(calls=[], status=201, body={"timestamp": "1690000000000"}, error=None)

    def send(session, request, **kwargs):
        state.calls.append((request, kwargs))
        if state.error:
            raise state.error
        response = requests.Response()
        response.status_code = state.status
        response._content = (state.body if isinstance(state.body, str) else json.dumps(state.body)).encode()
        response.url = request.url
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    return state


def test_signal_http_contract(transport):
    assert signal.handler(json.dumps(workflow())) == {"data": True}
    request, options = transport.calls[0]
    assert request.method == "POST"
    assert request.url == "http://localhost:8080/proxy/v2/send"
    assert request.headers["Content-Type"] == "application/json"
    assert json.loads(request.body) == {
        "number": "+33123456789",
        "recipients": ["+33123456780", "group.YWJjZA=="],
        "message": "Event: Example event",
    }
    assert options["timeout"] == 30
    assert options["allow_redirects"] is False


def test_matching_data_and_json_fallback(transport):
    request = workflow()
    request["matchingData"] = {"Event": {"info": "Matched"}}
    del request["data"]
    assert signal.handler(json.dumps(request)) == {"data": True}
    assert json.loads(transport.calls[-1][0].body)["message"] == "Event: Matched"
    for template in ("", None):
        request["matchingData"] = {}
        if template is None:
            request["params"].pop("message_template", None)
        else:
            request["params"]["message_template"] = template
        assert signal.handler(json.dumps(request)) == {"data": True}
        assert json.loads(transport.calls[-1][0].body)["message"] == "```\n{}\n```"


@pytest.mark.parametrize("status", [200, 202, 204, 301, 302, 400, 401, 429, 500])
def test_unconfirmed_send_is_failure(transport, status):
    transport.status = status
    transport.body = {"timestamp": "1690000000000", "error": "+33123456789"}
    result = signal.handler(json.dumps(workflow()))
    assert result["data"] is False and "error" in result
    assert "+33123456789" not in json.dumps(result)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("body", [{}, [], None, {"timestamp": ""}, {"timestamp": True}, {"timestamp": 0}, "not JSON"])
def test_invalid_acknowledgement(transport, body):
    transport.body = body
    assert signal.handler(json.dumps(workflow()))["data"] is False


@pytest.mark.parametrize("timestamp", [1690000000000, "1690000000000"])
def test_timestamp_formats(transport, timestamp):
    transport.body = {"timestamp": timestamp}
    assert signal.handler(json.dumps(workflow())) == {"data": True}


@pytest.mark.parametrize(
    "errors",
    [
        {"+33123456780": "private recipient failure"},
        {"group.YWJjZA==": {"+33123456780": "private recipient failure"}},
        ["private recipient failure"],
    ],
)
def test_recipient_errors_fail_even_with_a_valid_timestamp(transport, errors):
    transport.body = {"timestamp": "1690000000000", "errors": errors}
    result = signal.handler(json.dumps(workflow()))
    assert result["data"] is False and "error" in result
    assert "+33123456780" not in json.dumps(result)
    assert "private recipient failure" not in json.dumps(result)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("errors", [{}, [], None])
def test_empty_recipient_errors_allow_success(transport, errors):
    transport.body = {"timestamp": "1690000000000", "errors": errors}
    assert signal.handler(json.dumps(workflow())) == {"data": True}


@pytest.mark.parametrize("error", [requests.Timeout("private response"), requests.ConnectionError("private response")])
def test_transport_errors_are_sanitized_without_retry(transport, error):
    transport.error = error
    result = signal.handler(json.dumps(workflow()))
    assert result["data"] is False
    assert "private response" not in json.dumps(result)
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "params",
    [
        {"signal_api_url": "localhost:8080"},
        {"signal_api_url": "ftp://localhost"},
        {"signal_api_url": "https://"},
        {"signal_api_url": "http://user:password@localhost"},
        {"signal_api_url": "http://localhost?token=private"},
        {"signal_api_url": "http://localhost#fragment"},
        {"signal_api_url": "http://localhost:invalid"},
        {"signal_api_url": "http://localhost:0"},
        {"signal_api_url": "http://localhost/\n"},
        {"signal_api_url": None},
        {"sender_number": "33123456789"},
        {"sender_number": None},
        {"recipients": ""},
        {"recipients": "+33123456780,"},
        {"recipients": "group."},
        {"recipients": "invalid"},
        {"recipients": []},
        {"message_template": []},
        {"message_template": "{% invalid %}"},
        {"message_template": "{{ missing }}"},
    ],
)
def test_invalid_configuration_fails_before_network(transport, params):
    assert signal.handler(json.dumps(workflow(**params)))["data"] is False
    assert transport.calls == []


@pytest.mark.parametrize("payload", ["not JSON", "null", "[]", "{}", '{"params": []}', '{"params": {}}'])
def test_malformed_request(transport, payload):
    assert signal.handler(payload)["data"] is False
    assert transport.calls == []
    assert signal.handler() is False
