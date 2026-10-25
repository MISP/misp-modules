import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import quote
from uuid import UUID

import pytest
import requests
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

import misp_modules
from misp_modules import __main__ as service
from misp_modules.modules.action_mod import matrix


def workflow(**params):
    return {
        "params": {
            "matrix_homeserver": "https://matrix.example.org",
            "bot_access_token": "test-secret-token",
            "room_id": "!room:example.org",
            "message_template": "Event: {{ Event.info }}",
            **params,
        },
        "data": {"Event": {"info": "Example event"}},
    }


@pytest.fixture
def transport(monkeypatch):
    """Inspect actual prepared requests without contacting a homeserver."""
    state = SimpleNamespace(calls=[], status=200, body={"event_id": "$event:example.org"}, error=None)

    def send(session, request, **kwargs):
        state.calls.append((request, kwargs))
        if state.error:
            raise state.error
        response = requests.Response()
        response.status_code = state.status
        response._content = (state.body if isinstance(state.body, str) else json.dumps(state.body)).encode()
        response.url = request.url
        response.request = request
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    return state


def test_sends_rendered_message_with_matrix_http_contract(transport):
    assert matrix.handler(json.dumps(workflow())) == {"data": True}
    request, options = transport.calls[0]
    assert request.method == "PUT"
    prefix = "https://matrix.example.org/_matrix/client/v3/rooms/%21room%3Aexample.org/send/m.room.message/"
    assert request.url.startswith(prefix)
    assert UUID(request.url.removeprefix(prefix)).version == 4
    assert request.headers["Authorization"] == "Bearer test-secret-token"
    assert request.headers["Content-Type"] == "application/json"
    assert "test-secret-token" not in request.url
    assert json.loads(request.body) == {"msgtype": "m.text", "body": "Event: Example event"}
    assert options["timeout"] == 30
    assert options["allow_redirects"] is False


def test_matching_data_takes_precedence_even_when_empty(transport):
    request = workflow()
    request["matchingData"] = {"Event": {"info": "Matched event"}}
    assert matrix.handler(json.dumps(request)) == {"data": True}
    assert json.loads(transport.calls[-1][0].body)["body"] == "Event: Matched event"
    request["matchingData"] = {}
    request["params"]["message_template"] = "{{ Event.info if Event is defined else 'No event' }}"
    assert matrix.handler(json.dumps(request)) == {"data": True}
    assert json.loads(transport.calls[-1][0].body)["body"] == "No event"


@pytest.mark.parametrize("omit_template", [False, True])
def test_json_fallback_uses_selected_workflow_data(transport, omit_template):
    request = workflow(message_template="")
    if omit_template:
        del request["params"]["message_template"]
    request["matchingData"] = [{"value": "example.org"}]
    del request["data"]
    assert matrix.handler(json.dumps(request)) == {"data": True}
    assert json.loads(transport.calls[0][0].body) == {
        "msgtype": "m.text",
        "body": '```\n[{"value": "example.org"}]\n```',
    }


@pytest.mark.parametrize("base", ["https://matrix.example.org:8448/prefix/", "http://localhost:8008/"])
def test_base_url_and_room_id_are_preserved_and_encoded(transport, base):
    room_id = "!room/with?#%+:example.org"
    assert matrix.handler(json.dumps(workflow(matrix_homeserver=base, room_id=room_id))) == {"data": True}
    assert transport.calls[0][0].url.startswith(
        f"{base.rstrip('/')}/_matrix/client/v3/rooms/{quote(room_id, safe='')}/send/m.room.message/"
    )


def test_separate_invocations_use_different_transaction_ids(transport):
    for _ in range(2):
        assert matrix.handler(json.dumps(workflow())) == {"data": True}
    assert transport.calls[0][0].url != transport.calls[1][0].url


@pytest.mark.parametrize("status", [301, 302, 400, 401, 403, 404, 429, 500])
def test_http_failure_never_reports_success_or_leaks_provider_body(transport, status):
    transport.status = status
    transport.body = {"error": "test-secret-token", "event_id": "$unexpected"}
    result = matrix.handler(json.dumps(workflow()))
    assert result["data"] is False and "error" in result
    assert "test-secret-token" not in json.dumps(result)
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "error", [requests.Timeout("test-secret-token"), requests.ConnectionError("test-secret-token")]
)
def test_transport_failure_is_sanitized_and_not_retried(transport, error):
    transport.error = error
    result = matrix.handler(json.dumps(workflow()))
    assert result["data"] is False and "error" in result
    assert "test-secret-token" not in json.dumps(result)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("body", [{}, {"event_id": ""}, {"event_id": 1}, [], None, "invalid JSON"])
def test_success_requires_an_event_acknowledgement(transport, body):
    transport.body = body
    result = matrix.handler(json.dumps(workflow()))
    assert result["data"] is False and "error" in result


@pytest.mark.parametrize(
    "params",
    [
        {"matrix_homeserver": "matrix.example.org"},
        {"matrix_homeserver": "ftp://matrix.example.org"},
        {"matrix_homeserver": "https://"},
        {"matrix_homeserver": "https://user:secret@matrix.example.org"},
        {"matrix_homeserver": "https://matrix.example.org?token=secret"},
        {"matrix_homeserver": "https://matrix.example.org#fragment"},
        {"matrix_homeserver": "https://matrix.example.org:invalid"},
        {"matrix_homeserver": "https://matrix.example.org:0"},
        {"matrix_homeserver": "https://matrix.example.org/\n"},
        {"matrix_homeserver": "https://matrix.example.org/ path"},
        {"matrix_homeserver": None},
        {"bot_access_token": ""},
        {"bot_access_token": "token\r\nInjected: header"},
        {"room_id": "#alias:example.org"},
        {"room_id": "!"},
        {"room_id": None},
        {"message_template": []},
        {"message_template": "{% invalid %}"},
    ],
)
def test_invalid_parameters_or_templates_fail_before_network(transport, params):
    result = matrix.handler(json.dumps(workflow(**params)))
    assert result["data"] is False and "error" in result
    assert transport.calls == []


@pytest.mark.parametrize("payload", ["not JSON", "null", "[]", "{}", '{"params": []}', '{"params": {}}'])
def test_malformed_requests_fail_without_network(transport, payload):
    assert matrix.handler(payload)["data"] is False
    assert transport.calls == []
    assert matrix.handler() is False


class TestMatrixHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous = service.MODULES_HANDLERS.copy()
        self.cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"matrix": matrix, "type:matrix": "action_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        modules_dir = Path(misp_modules.__file__).parent / "modules"
        assert any(
            kind.name == "action_mod" and module.name == "matrix.py"
            for kind, module in misp_modules.iterate_modules(modules_dir)
        )
        descriptor = json.loads(self.fetch("/modules").body)[0]
        assert descriptor["name"] == "matrix" and descriptor["type"] == "action_mod"
        assert descriptor["meta"]["config"]["support_filters"] is True
        assert descriptor["meta"]["config"]["blocking"] is False
        assert descriptor["mispattributes"] == matrix.introspection()
        response = Mock(status_code=200)
        response.json.return_value = {"event_id": "$sent"}
        with patch.object(matrix.requests, "put", return_value=response):
            result = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": "matrix", **workflow()}),
            )
        assert result.code == 200 and json.loads(result.body) == {"data": True}
