import json
from unittest.mock import MagicMock, patch

import pytest
import requests
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.modules.expansion import webarchive_save as module

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
URL = "https://example.org/report?a=1&b=2"
CONFIG = {"access_key": "test-access", "secret_key": "test-secret"}


@pytest.fixture
def session():
    with patch.object(module.requests, "Session") as factory:
        session = factory.return_value.__enter__.return_value
        yield session


def response(payload, status=200):
    result = MagicMock()
    result.__enter__.return_value = result
    result.status_code = status
    result.iter_content.return_value = [json.dumps(payload).encode()]
    return result


def run(session, statuses=(), config=None, value=URL, kind="url", **metadata):
    session.request.side_effect = [response({"job_id": "spn2-job_123"}), *[response(s) for s in statuses]]
    attribute = {"type": kind, "value": value, "uuid": UUID, **metadata}
    with patch.object(module.time, "sleep"):
        return module.handler(json.dumps({"attribute": attribute, "config": {**CONFIG, **(config or {})}}))


def receipt(result):
    assert "error" not in result, result
    annotation = result["results"]["Object"][0]
    assert annotation["name"] == "annotation"
    return json.loads(annotation["Attribute"][0]["value"])


def test_submit_is_one_post_with_receipt_and_preserved_context(session):
    result = run(session, to_ids=True, comment="Original context", Tag=[{"name": "tlp:clear"}])
    job = receipt(result)
    assert job["job_id"] == "spn2-job_123"
    assert job["status"] == "submitted"
    assert job["status_url"] == "https://web.archive.org/save/status/spn2-job_123"
    assert len(result["results"]["Object"]) == 1
    assert result["results"]["Attribute"][0]["to_ids"] is True
    assert result["results"]["Attribute"][0]["comment"] == "Original context"
    assert result["results"]["Object"][0]["ObjectReference"][0]["referenced_uuid"] == UUID
    session.headers.update.assert_called_once()
    assert session.headers.update.call_args.args[0]["Authorization"] == "LOW test-access:test-secret"
    session.request.assert_called_once()
    args, kwargs = session.request.call_args
    assert args == ("POST", module.BASE + "/save")
    assert kwargs["data"] == {"url": URL}
    assert kwargs["allow_redirects"] is False and kwargs["stream"] is True
    assert 29 <= kwargs["timeout"].total <= 30
    assert kwargs["timeout"].connect_timeout == 10
    assert "test-secret" not in json.dumps(result)


def test_pending_then_success_produces_capture(session):
    result = run(
        session,
        [{"status": "pending"}, {"status": "success", "timestamp": "20261117010203", "original_url": URL}],
        config={"poll_attempts": 3},
    )
    assert receipt(result)["status"] == "success"
    capture = result["results"]["Object"][1]
    assert capture["name"] == "page-capture"
    values = {a["object_relation"]: a["value"] for a in capture["Attribute"]}
    assert values["archive"] == "https://web.archive.org/web/20261117010203/" + URL
    assert values["capture-date"].startswith("2026-11-17T01:02:03")
    assert all(a["to_ids"] is False for obj in result["results"]["Object"] for a in obj["Attribute"])
    assert [c.args[0] for c in session.request.call_args_list] == ["POST", "GET", "GET"]


@pytest.mark.parametrize("state", ["pending", "error"])
def test_non_completed_jobs_do_not_fabricate_captures(session, state):
    result = run(session, [{"status": state}], config={"poll_attempts": 1})
    assert receipt(result)["status"] == state
    assert len(result["results"]["Object"]) == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "unknown"},
        {"status": "success"},
        {"status": "success", "timestamp": "20260230010203"},
        {"status": "pending", "job_id": "different"},
        [],
    ],
)
def test_invalid_polling_response_retains_receipt(session, payload):
    result = run(session, [payload], config={"poll_attempts": 1})
    assert "poll_error" in receipt(result)
    assert receipt(result)["job_id"] == "spn2-job_123"
    assert len(result["results"]["Object"]) == 1


def test_poll_transport_failure_does_not_lose_job_or_leak_secret(session):
    session.request.side_effect = [response({"job_id": "job"}), requests.Timeout("test-secret")]
    q = {"attribute": {"type": "url", "value": URL, "uuid": UUID}, "config": {**CONFIG, "poll_attempts": 1}}
    result = module.handler(json.dumps(q))
    assert receipt(result)["job_id"] == "job"
    assert "test-secret" not in json.dumps(result)


@pytest.mark.parametrize("failure", [requests.Timeout("test-secret"), requests.ConnectionError("test-access")])
def test_post_transport_error_does_not_retry_or_leak_credentials(session, failure):
    session.request.side_effect = failure
    result = module.handler(json.dumps({"attribute": {"type": "url", "value": URL, "uuid": UUID}, "config": CONFIG}))
    assert "unconfirmed" in result["error"]
    assert "test-secret" not in result["error"] and "test-access" not in result["error"]
    assert session.request.call_count == 1


@pytest.mark.parametrize("status", [302, 401, 429, 500, 503])
def test_submission_http_errors_are_not_success(session, status):
    session.request.return_value = response({}, status)
    result = module.handler(json.dumps({"attribute": {"type": "url", "value": URL, "uuid": UUID}, "config": CONFIG}))
    assert f"HTTP {status}" in result["error"]
    assert session.request.call_count == 1


@pytest.mark.parametrize("payload", [None, [], {}, {"job_id": "../evil"}, {"job_id": []}])
def test_invalid_submission_acknowledgement(session, payload):
    session.request.return_value = response(payload)
    result = module.handler(json.dumps({"attribute": {"type": "url", "value": URL, "uuid": UUID}, "config": CONFIG}))
    assert "error" in result
    assert session.request.call_count == 1


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:password@example.org",
        "https://example.org/\n",
        "https://example.org\\evil",
        "https://[::1",
        "https://example.org:0",
        "https://example.org:99999",
    ],
)
def test_invalid_target_never_submits(session, url):
    assert "error" in run(session, value=url)
    session.request.assert_not_called()


@pytest.mark.parametrize(
    "config", [{"access_key": ""}, {"secret_key": "\r\nsecret"}, {"timeout": True}, {"poll_attempts": 7}]
)
def test_bad_config_never_submits(session, config):
    assert "error" in run(session, config=config)
    session.request.assert_not_called()


@pytest.mark.parametrize("query", ["bad", "null", "[]", "{}", '{"attribute": []}'])
def test_invalid_request(query):
    assert "error" in module.handler(query)


def test_response_size_limit_and_fragment(session):
    with patch.object(module, "MAX_RESPONSE", 1):
        assert "exceeds" in run(session)["error"]
    session.request.reset_mock()
    assert receipt(run(session, value=URL + "#fragment", kind="link"))["url"] == URL
    assert module.handler() is False
    assert module.introspection()["input"] == ["url", "link"]
    assert module.version()["module-type"] == ["expansion"]


@pytest.mark.parametrize("caller_timeout,budget", [(None, 120), (20, 19)])
def test_slow_requests_share_budget_and_keep_accepted_receipt(session, caller_timeout, budget):
    clock = [0.0]
    timeouts = []

    def slow_request(method, url, **kwargs):
        remaining = kwargs["timeout"].total
        timeouts.append(remaining)
        duration = 100 if method == "POST" else 110
        clock[0] += min(duration, remaining)
        if duration >= remaining:
            raise requests.Timeout("slow response")
        return response({"job_id": "accepted"} if method == "POST" else {"status": "pending"})

    # Use a faster submission for the explicitly shorter caller timeout.
    def short_request(method, url, **kwargs):
        remaining = kwargs["timeout"].total
        timeouts.append(remaining)
        if method == "POST":
            clock[0] += 5
            return response({"job_id": "accepted"})
        clock[0] += remaining
        raise requests.Timeout("slow status response")

    session.request.side_effect = slow_request if caller_timeout is None else short_request
    query = {
        "attribute": {"type": "url", "value": URL, "uuid": UUID},
        "config": {**CONFIG, "timeout": 120, "poll_attempts": 6},
    }
    if caller_timeout is not None:
        query["timeout"] = caller_timeout
    with patch.object(module.time, "monotonic", side_effect=lambda: clock[0]):
        result = module.handler(json.dumps(query))
    assert clock[0] == budget
    assert timeouts == ([120, 20] if caller_timeout is None else [19, 14])
    job = receipt(result)
    assert job["job_id"] == "accepted" and job["status"] == "submitted"
    assert "poll_error" in job
    assert session.request.call_count == 2


def test_budget_exhaustion_before_polling_delay_returns_pending_receipt(session):
    clock = [0.0]

    def slow_request(method, url, **kwargs):
        clock[0] += 10 if method == "POST" else 19
        return response({"job_id": "accepted"} if method == "POST" else {"status": "pending"})

    session.request.side_effect = slow_request
    with (
        patch.object(module.time, "monotonic", side_effect=lambda: clock[0]),
        patch.object(module.time, "sleep") as sleep,
    ):
        result = module.handler(
            json.dumps(
                {"attribute": {"type": "url", "value": URL, "uuid": UUID}, "config": {**CONFIG, "poll_attempts": 6}}
            )
        )
    job = receipt(result)
    assert job["status"] == "pending" and job["job_id"] == "accepted"
    assert "time budget" in job["poll_error"]
    sleep.assert_not_called()
    assert session.request.call_count == 2


def test_expired_request_deadline_never_starts_network_call(session):
    with patch.object(module.time, "monotonic", return_value=30), pytest.raises(ValueError, match="time budget"):
        module.request_json(session, "GET", "/save/status/job", 30)
    session.request.assert_not_called()


def test_streaming_deadline_retains_accepted_receipt(session):
    clock = [0.0]
    status = response({})

    def chunks(size):
        clock[0] = 31
        yield b'{"status":"pending"}'

    status.iter_content.side_effect = chunks
    session.request.side_effect = [response({"job_id": "accepted"}), status]
    with patch.object(module.time, "monotonic", side_effect=lambda: clock[0]):
        result = module.handler(
            json.dumps(
                {"attribute": {"type": "url", "value": URL, "uuid": UUID}, "config": {**CONFIG, "poll_attempts": 1}}
            )
        )
    assert receipt(result)["job_id"] == "accepted"
    assert "time budget" in receipt(result)["poll_error"]


class TestWebarchiveSaveHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.patcher = patch.object(
            server, "MODULES_HANDLERS", {"webarchive_save": module, "type:webarchive_save": "expansion"}
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        return Application([(r"/modules", server.ListModules), (r"/query", server.QueryModule)])

    def test_submit_endpoint(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "webarchive_save"
        with patch.object(module.requests, "Session") as factory:
            factory.return_value.__enter__.return_value.request.return_value = response({"job_id": "queued"})
            result = self.fetch(
                "/query",
                method="POST",
                body=json.dumps(
                    {
                        "module": "webarchive_save",
                        "attribute": {"type": "url", "value": URL, "uuid": UUID},
                        "config": CONFIG,
                    }
                ),
            )
        assert result.code == 200
        assert receipt(json.loads(result.body))["status"] == "submitted"
