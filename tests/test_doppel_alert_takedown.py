import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.action_mod import doppel_alert_takedown as module


def query(**params):
    return json.dumps({"params": params})


def reply(data, status=200):
    return Mock(status_code=status, json=Mock(return_value=data))


def test_creation_uses_one_post_and_environment_authentication():
    with (
        patch.dict("os.environ", {"DOPPEL_API_KEY": "test-secret"}),
        patch.object(
            module.requests, "request", return_value=reply({"id": "ACM-1", "queue_state": "doppel_review"})
        ) as request,
    ):
        result = module.handler(query(action="create_alert", entity="https://bad.example"))
    assert result["data"]["alert_id"] == "ACM-1"
    assert request.call_count == 2
    assert request.call_args_list[0].args[0] == "POST"
    assert request.call_args_list[0].kwargs["json"] == {"entity": "https://bad.example"}
    assert "test-secret" not in str(result)


def test_takedown_checks_existing_state_and_requests_actioned():
    with (
        patch.dict("os.environ", {"DOPPEL_API_KEY": "test-secret"}),
        patch.object(
            module.requests,
            "request",
            side_effect=[
                reply({"id": "ACM-1", "queue_state": "needs_confirmation"}),
                reply({"id": "ACM-1", "queue_state": "actioned"}),
            ],
        ) as request,
    ):
        result = module.handler(
            query(action="request_takedown", alert_id="ACM-1", comment="Confirmed phishing investigation.")
        )
    assert result["data"]["request_performed"] is True
    assert request.call_args.args[0] == "PUT"
    assert request.call_args.kwargs["json"]["queue_state"] == "actioned"
    assert request.call_args.kwargs["params"] == {"id": "ACM-1"}


@pytest.mark.parametrize("state", ["actioned", "taken_down"])
def test_repeated_takedown_does_not_send_another_update(state):
    with (
        patch.dict("os.environ", {"DOPPEL_API_KEY": "test-secret"}),
        patch.object(module.requests, "request", return_value=reply({"id": "ACM-1", "queue_state": state})) as request,
    ):
        result = module.handler(query(action="request_takedown", alert_id="ACM-1"))
    assert result["data"]["request_performed"] is False
    assert request.call_count == 1


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"action": "bad"},
        {"action": "create_alert", "entity": "file:///etc/passwd"},
        {"action": "request_takedown", "alert_id": "ACM-1", "entity": "https://example.com"},
    ],
)
def test_invalid_parameters_do_not_call_service(params):
    with patch.object(module.requests, "request") as request:
        assert "error" in module.handler(query(**params))
    request.assert_not_called()


def test_transport_failure_is_not_retried():
    with (
        patch.dict("os.environ", {"DOPPEL_API_KEY": "test-secret"}),
        patch.object(module.requests, "request", side_effect=requests.Timeout("test-secret")) as request,
    ):
        result = module.handler(query(action="create_alert", entity="https://bad.example"))
    assert "error" in result and "test-secret" not in str(result)
    assert request.call_count == 1
    assert request.call_args.kwargs["timeout"] == (5, 30)
    assert request.call_args.kwargs["verify"] is True
    assert request.call_args.kwargs["allow_redirects"] is False


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection()["config"]["blocking"] is True
    assert module.version()["config"] == module.moduleconfig


def test_creation_fetches_state_and_preserves_provider_link():
    responses = [
        reply({"id": "ACM-1"}),
        reply({"id": "ACM-1", "queue_state": "doppel_review", "doppel_link": "https://vision.doppel.com/drp/ACM-1"}),
    ]
    with (
        patch.dict("os.environ", {"DOPPEL_API_KEY": "test-secret"}),
        patch.object(module.requests, "request", side_effect=responses),
    ):
        result = module.handler(query(action="create_alert", entity="https://bad.example"))
    assert result["data"]["queue_state"] == "doppel_review"
    assert result["data"]["link"] == "https://vision.doppel.com/drp/ACM-1"
