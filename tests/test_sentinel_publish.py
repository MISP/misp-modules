import copy
import json
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from urllib.parse import parse_qs

import pytest
import requests
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.action_mod import export_sentinel as wrapper
from misp_modules.modules.action_mod import sentinel_publish as publish

WORKSPACE = "22549473-0938-4938-8a04-225494730938"
TENANT = "c6a7d64d-8d28-4c7d-ae30-8efcbb28804d"
CLIENT = "fdb91a8a-e7bd-4c6e-b265-b286c3321879"
EVENT = "f1ef0409-c80a-4012-b401-b7d1050f4ed4"
ATTRIBUTE = "aa09819b-f2d8-4661-83ea-d4897cafebc8"


def attribute(kind="domain", value="example.org", **metadata):
    return {"uuid": ATTRIBUTE, "timestamp": "1767225600", "type": kind, "value": value, "to_ids": True, **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"uuid": EVENT, "Attribute": attributes or [], "Object": objects or [], **metadata}


def request(data=None, **params):
    return json.dumps(
        {"data": event([attribute()]) if data is None else data, "params": {"workspace_id": WORKSPACE, **params}}
    )


def run(data=None, **params):
    return publish.handler(request(data, **params))


def response(body=None, status=200, raw=None):
    result = requests.Response()
    result.status_code = status
    result.headers["Content-Type"] = "application/json"
    result._content = (b"" if body is None else json.dumps(body).encode()) if raw is None else raw
    return result


@pytest.fixture
def client(monkeypatch):
    session = MagicMock(spec=requests.Session)
    session.headers = {}
    session.__enter__.return_value = session

    def post(url, **kwargs):
        if "oauth2" in url:
            return response({"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600})
        return response()

    session.post.side_effect = post
    session.constructor = MagicMock(return_value=session)
    monkeypatch.setattr(publish.requests, "Session", session.constructor)
    monkeypatch.setenv("SENTINEL_TENANT_ID", TENANT)
    monkeypatch.setenv("SENTINEL_CLIENT_ID", CLIENT)
    monkeypatch.setenv("SENTINEL_CLIENT_SECRET", "client-secret")
    return session


def payloads(result):
    assert "error" not in result, result
    return [obj for batch in result["data"]["payloads"] for obj in batch["stixobjects"]]


def test_direct_contract_uses_correct_authority_scope_endpoint_and_empty_body_ack(client):
    result = run()
    assert result["data"]["uploaded"] == 1 and result["data"]["success"] is True
    assert result["result_key"] == "sentinel_publish"
    auth, upload = client.post.call_args_list
    assert auth.args == (f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",)
    assert auth.kwargs["data"] == {
        "grant_type": "client_credentials",
        "client_id": CLIENT,
        "client_secret": "client-secret",
        "scope": "https://management.azure.com/.default",
    }
    assert upload.args == (
        f"https://api.ti.sentinel.azure.com/workspaces/{WORKSPACE}/threat-intelligence-stix-objects:upload",
    )
    assert upload.kwargs["params"] == {"api-version": "2024-02-01-preview"}
    assert set(upload.kwargs["json"]) == {"sourcesystem", "stixobjects"}
    assert upload.kwargs["json"]["sourcesystem"] == "misp-modules"
    obj = upload.kwargs["json"]["stixobjects"][0]
    expiry = datetime.fromisoformat(obj["valid_until"].replace("Z", "+00:00"))
    assert abs((expiry - datetime.now(timezone.utc) - timedelta(days=30)).total_seconds()) < 5
    assert client.headers["Authorization"] == "Bearer access-token"
    assert all(
        call.kwargs["verify"] is True and call.kwargs["allow_redirects"] is False and call.kwargs["timeout"] == 15
        for call in [auth, upload]
    )
    client.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "kind,value,pattern",
    [
        ("domain", "EXAMPLE.org.", "[domain-name:value = 'example.org']"),
        ("hostname", "bücher.example", "[domain-name:value = 'xn--bcher-kva.example']"),
        ("ip-src", "192.0.2.1", "[ipv4-addr:value = '192.0.2.1']"),
        ("ip-dst", "2001:0DB8:0000::1", "[ipv6-addr:value = '2001:db8::1']"),
        ("url", "https://example.org/A?q=1", "[url:value = 'https://example.org/A?q=1']"),
        ("email-src", "User@EXAMPLE.org", "[email-addr:value = 'User@example.org']"),
        ("url", "https://example.org/a'b", "[url:value = 'https://example.org/a\\'b']"),
        ("url", "https://example.org/a\\b", "[url:value = 'https://example.org/a\\\\b']"),
        *[
            (kind, "A" * length, f"[file:hashes.'{algorithm}' = '" + "a" * length + "']")
            for kind, (algorithm, length) in publish.HASH_LENGTHS.items()
        ],
        *[
            (f"filename|{kind}", "a|b.exe|" + "a" * length, f"[file:hashes.'{algorithm}' = '" + "a" * length + "']")
            for kind, (algorithm, length) in publish.HASH_LENGTHS.items()
        ],
        ("malware-sample", "file.exe|" + "a" * 32, "[file:hashes.'MD5' = '" + "a" * 32 + "']"),
    ],
)
def test_supported_values_generate_valid_stix_patterns(kind, value, pattern):
    stix2 = pytest.importorskip("stix2")
    obj = payloads(run(event([attribute(kind, value)]), dry_run=True))[0]
    assert obj["pattern"] == pattern
    parsed = stix2.parse(obj)
    assert parsed.type == "indicator" and parsed.spec_version == "2.1"


def test_domain_ip_and_object_provenance_are_preserved_without_mutation():
    obj = {"uuid": "object-1", "name": "domain-ip", "Attribute": [attribute("domain|ip", "example.org|192.0.2.1")]}
    data = [{"Event": event(objects=[obj])}, {"Event": {"uuid": EVENT}, "Object": [obj]}, event(objects=[obj])]
    original = copy.deepcopy(data)
    result = run(data, dry_run=True)
    objects = payloads(result)
    assert len(objects) == 2
    assert all(
        len(item["sources"]) == 1 and item["sources"][0]["object"] == "object-1" for item in result["data"]["items"]
    )
    assert data == original


@pytest.mark.parametrize(
    "template,relation,value", [("file", "sha256", "a" * 64), ("domain-ip", "domain", "example.org")]
)
def test_existing_misp_object_templates_suffice(template, relation, value):
    obj = MISPObject(template, strict=True)
    obj.add_attribute(relation, value=value, to_ids=True, uuid=ATTRIBUTE, timestamp=1767225600)
    obj._validate()
    assert len(payloads(run(event(objects=[json.loads(obj.to_json())]), dry_run=True))) == 1


def test_source_revision_ids_and_created_are_stable_but_change_with_content_timestamp_or_namespace():
    first = payloads(run(dry_run=True))[0]
    again = payloads(run(dry_run=True, expiration_days=45, confidence=75))[0]
    assert first["id"] == again["id"] and first["created"] == again["created"] == "2026-01-01T00:00:00.000Z"
    assert first["modified"] <= again["modified"]
    assert again["confidence"] == 75 and again["valid_until"] > first["valid_until"]
    for data, params in [
        (event([attribute(value="other.example")]), {}),
        (event([attribute(timestamp="1767225601")]), {}),
        (event([attribute(uuid=str(uuid.uuid4()))]), {}),
        (event([attribute()]), {"source": "another publisher"}),
        (event([attribute()]), {"workspace_id": str(uuid.uuid4())}),
    ]:
        assert payloads(run(data, dry_run=True, **params))[0]["id"] != first["id"]


def test_tags_and_supported_tlp_markings_are_preserved_without_private_comments_or_samples():
    data = event(
        [attribute(Tag=[{"name": "tlp:green"}], comment="private-comment", data="private-sample")],
        Tag=[{"name": "event-tag"}],
        EventTag=[{"Tag": {"name": "tlp:amber"}}],
        info="private-title",
    )
    obj = payloads(run(data, dry_run=True))[0]
    assert obj["labels"] == ["event-tag", "tlp:amber", "tlp:green"]
    assert set(obj["object_marking_refs"]) == {publish.TLP_MARKINGS["tlp:green"], publish.TLP_MARKINGS["tlp:amber"]}
    assert not any(word in json.dumps(obj) for word in ["private-comment", "private-sample", "private-title"])


def test_dry_run_needs_no_credentials_or_requests_session(client, monkeypatch):
    for name in ["SENTINEL_TENANT_ID", "SENTINEL_CLIENT_ID", "SENTINEL_CLIENT_SECRET"]:
        monkeypatch.delenv(name)
    assert run(dry_run=True)["data"]["planned"] == 1
    client.constructor.assert_not_called()


def test_batches_are_limited_to_one_hundred_and_share_one_authentication(client):
    data = event(
        [
            attribute(value=f"host{index}.example", uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, str(index))))
            for index in range(205)
        ]
    )
    result = run(data)
    assert result["data"]["uploaded"] == 205
    assert [len(call.kwargs["json"]["stixobjects"]) for call in client.post.call_args_list[1:]] == [100, 100, 5]
    assert client.post.call_count == 4


@pytest.mark.parametrize(
    "body",
    [
        {"errors": [{"recordIndex": 0, "errorMessages": ["client-secret"]}]},
        {"errors": [{"recordIndex": 1, "errorMessages": ["access-token"]}]},
    ],
)
def test_http_200_partial_failures_are_mapped_by_record_index_without_exposing_messages(client, body):
    client.post.side_effect = [
        response({"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600}),
        response(body),
    ]
    result = run(event([attribute(), attribute(value="other.example", uuid=str(uuid.uuid4()))]))
    assert result["data"]["uploaded"] == 1 and result["data"]["failed"] == 1
    assert result["data"]["success"] is False and "partial" in result["error"]
    assert result["data"]["items"][body["errors"][0]["recordIndex"]]["status"] == "failed"
    assert "client-secret" not in json.dumps(result) and "access-token" not in json.dumps(result)


@pytest.mark.parametrize(
    "body",
    [
        {},
        [],
        {"unexpected": True},
        {"errors": {}},
        {"errors": [{}]},
        {"errors": [{"recordIndex": True, "errorMessages": ["bad"]}]},
        {"errors": [{"recordIndex": -1, "errorMessages": ["bad"]}]},
        {"errors": [{"recordIndex": 1, "errorMessages": ["bad"]}]},
        {"errors": [{"recordIndex": 0, "errorMessages": []}]},
        {"errors": [{"recordIndex": 0, "errorMessages": "bad"}]},
        {"errors": [{"recordIndex": 0, "errorMessages": ["bad"]}] * 2},
        {"errors": [], "warnings": ["bad"]},
    ],
)
def test_malformed_upload_acknowledgements_are_uncertain_failures(client, body):
    client.post.side_effect = [
        response({"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600}),
        response(body),
    ]
    result = run()
    assert result["data"]["failed"] == 1 and result["data"]["uploaded"] == 0
    assert "unknown" in result["data"]["items"][0]["error"]
    assert client.post.call_count == 2


def test_empty_validation_error_list_is_an_acknowledgement(client):
    client.post.side_effect = [
        response({"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600}),
        response({"errors": []}),
    ]
    assert run()["data"]["uploaded"] == 1


@pytest.mark.parametrize("status", [202, 204, 301, 302, 400, 401, 403, 404, 429, 500])
def test_upload_http_failure_stops_later_batches_without_retry_or_echoing_secrets(client, status):
    client.post.side_effect = [
        response({"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600}),
        response({"message": "client-secret"}, status),
    ]
    result = run(event([attribute(value=f"host{index}.example") for index in range(101)]))
    assert result["data"]["failed"] == 101 and result["data"]["uploaded"] == 0
    assert "not attempted" in result["data"]["items"][-1]["error"]
    assert "client-secret" not in json.dumps(result) and client.post.call_count == 2


@pytest.mark.parametrize(
    "failure",
    [
        requests.Timeout("client-secret"),
        requests.ConnectionError("access-token"),
        OSError("client-secret"),
        response(raw=b"not JSON"),
    ],
)
def test_unknown_write_outcomes_preserve_prior_success(client, failure):
    client.post.side_effect = [
        response({"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600}),
        response(),
        failure,
    ]
    result = run(event([attribute(value=f"host{index}.example") for index in range(101)]))
    assert result["data"]["uploaded"] == 100 and result["data"]["failed"] == 1
    assert "client-secret" not in json.dumps(result) and "access-token" not in json.dumps(result)


@pytest.mark.parametrize(
    "body",
    [
        {},
        [],
        {"access_token": "access-token"},
        {"access_token": "access-token", "token_type": "other", "expires_in": 3600},
        {"access_token": "access-token\r\nHeader: bad", "token_type": "Bearer", "expires_in": 3600},
        {"access_token": "access-token", "token_type": "Bearer", "expires_in": 10},
        {"access_token": "access-token", "token_type": "Bearer", "expires_in": True},
    ],
)
def test_invalid_token_responses_do_not_upload_or_expose_secrets(client, body):
    client.post.side_effect = [response(body)]
    result = run()
    assert "error" in result and result["data"]["success"] is False
    assert result["data"]["items"][0]["status"] == "not_attempted"
    assert "access-token" not in json.dumps(result) and client.post.call_count == 1


@pytest.mark.parametrize(
    "key,value",
    [
        ("SENTINEL_TENANT_ID", "bad"),
        ("SENTINEL_CLIENT_ID", "bad"),
        ("SENTINEL_CLIENT_SECRET", ""),
        ("SENTINEL_CLIENT_SECRET", "secret\r\n"),
    ],
)
def test_invalid_server_credentials_never_reach_network(client, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    assert "error" in run()
    client.post.assert_not_called()


@pytest.mark.parametrize(
    "params",
    [
        {"workspace_id": "bad/path"},
        {"workspace_id": "00000000-0000-0000-0000-000000000000"},
        {"source": "Microsoft Sentinel"},
        {"source": []},
        {"source": "a" * 65},
        {"expiration_days": 0},
        {"expiration_days": 366},
        {"confidence": -1},
        {"confidence": 101},
        {"confidence": True},
        {"dry_run": "maybe"},
    ],
)
def test_invalid_direct_configuration_precedes_network(client, params):
    assert "error" in run(**params)
    client.constructor.assert_not_called()


@pytest.mark.parametrize(
    "metadata",
    [
        {"uuid": None},
        {"uuid": "bad"},
        {"timestamp": None},
        {"timestamp": True},
        {"timestamp": "9999999999"},
        {"value": "bad..example"},
        {"value": "\ud800"},
    ],
)
def test_bad_source_identity_timestamp_or_value_is_skipped(client, metadata):
    result = run(event([attribute(**metadata)]))
    assert result["data"]["skipped"] == {"malformed value or identity/timestamp": 1}
    client.constructor.assert_not_called()


def test_deleted_non_ids_and_unsupported_constraints_are_excluded(client):
    data = [
        event(
            [attribute(deleted=True), attribute(to_ids="false"), attribute("ip-dst|port", "192.0.2.1|443")],
            [{"deleted": True, "Attribute": [attribute()]}],
        ),
        event([attribute()], deleted=True),
    ]
    assert run(data)["data"]["skipped"] == {"deleted or non-IDS": 2, "unsupported": 1}
    client.constructor.assert_not_called()


def test_limits_and_malformed_containers_are_checked_before_network(client, monkeypatch):
    assert "error" in run(event([attribute(value=f"host{index}.example") for index in range(1001)]))
    monkeypatch.setattr(publish, "MAX_BATCH_BYTES", 10)
    assert "error" in run()
    for payload in [None, "bad", [1], {"Event": "bad"}, {"Object": [1]}]:
        assert "error" in publish.handler(json.dumps({"data": payload, "params": {"workspace_id": WORKSPACE}}))
    client.constructor.assert_not_called()


def test_deadline_is_checked_after_authentication(client, monkeypatch):
    values = iter([0, publish.DEADLINE_SECONDS + 1])
    monkeypatch.setattr(publish.time, "monotonic", lambda: next(values))
    assert run()["data"]["failed"] == 1
    assert client.post.call_count == 1


@pytest.mark.parametrize("module", [publish, wrapper])
def test_request_validation_and_unapplied_filters(module):
    assert module.handler() is False
    for payload in [
        "invalid JSON",
        "[]",
        "null",
        json.dumps({"params": []}),
        json.dumps({"filteredItems": []}),
        json.dumps({"matchingData": []}),
    ]:
        assert "error" in module.handler(payload)


def test_wrapper_direct_mode_uses_same_publisher_and_does_not_spawn(client, monkeypatch):
    process = MagicMock()
    monkeypatch.setattr(wrapper.subprocess, "run", process)
    result = wrapper.handler(request(mode="direct"))
    assert result["data"]["uploaded"] == 1 and result["result_key"] == "sentinel_publish"
    process.assert_not_called()


@pytest.mark.parametrize(
    "params,data",
    [
        ({"mode": "unknown"}, {"Event": {"uuid": EVENT}}),
        ({"dry_run": True}, {"Event": {"uuid": EVENT}}),
        ({"misp2_venv": "relative"}, {"Event": {"uuid": EVENT}}),
        ({"misp2_script": "/bad\x00path"}, {"Event": {"uuid": EVENT}}),
        ({}, {"Event": {"uuid": "bad"}}),
        ({}, [{"Event": {"uuid": EVENT}}]),
    ],
)
def test_wrapper_invalid_mode_paths_or_input_never_execute(monkeypatch, params, data):
    process = MagicMock()
    monkeypatch.setattr(wrapper.subprocess, "run", process)
    assert "error" in wrapper.handler(json.dumps({"data": data, "params": params}))
    process.assert_not_called()


def test_missing_wrapper_installation_returns_a_workflow_error(monkeypatch):
    monkeypatch.setattr(wrapper.os.path, "isfile", lambda path: False)
    assert wrapper.handler(json.dumps({"data": {"Event": {"uuid": EVENT}}}))["data"] is False


def test_legacy_wrapper_default_calls_python_with_event_uuid_and_boolean_success(monkeypatch):
    monkeypatch.setattr(wrapper.os.path, "isfile", lambda path: True)
    process = MagicMock(return_value=MagicMock(returncode=0))
    monkeypatch.setattr(wrapper.subprocess, "run", process)
    result = wrapper.handler(
        json.dumps(
            {
                "data": {"Event": {"uuid": EVENT}},
                "params": {"misp2_venv": "/opt/env", "misp2_script": "/opt/app/script.py"},
            }
        )
    )
    assert result == {"data": True}
    assert process.call_args.args[0] == ["/opt/env/bin/python", "/opt/app/script.py", EVENT]
    assert process.call_args.kwargs["cwd"] == "/opt/app"
    assert process.call_args.kwargs["stdout"] == process.call_args.kwargs["stderr"] == subprocess.DEVNULL


@pytest.mark.parametrize(
    "outcome", [MagicMock(returncode=1), subprocess.TimeoutExpired("script", 240), OSError("client-secret")]
)
def test_wrapper_failures_signal_workflow_error_without_logging_provider_output(monkeypatch, capsys, outcome):
    monkeypatch.setattr(wrapper.os.path, "isfile", lambda path: True)
    process = MagicMock()
    if isinstance(outcome, Exception):
        process.side_effect = outcome
    else:
        process.return_value = outcome
    monkeypatch.setattr(wrapper.subprocess, "run", process)
    result = wrapper.handler(json.dumps({"data": {"Event": {"uuid": EVENT}}, "params": {}}))
    assert result["data"] is False and "error" in result and "client-secret" not in json.dumps(result)
    assert capsys.readouterr().out == ""


def test_real_wrapper_process_remains_compatible(tmp_path):
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").symlink_to(sys.executable)
    script = tmp_path / "script.py"
    script.write_text("import sys\nfrom pathlib import Path\nPath('received.txt').write_text(sys.argv[1])\n")
    result = wrapper.handler(
        json.dumps(
            {"data": {"Event": {"uuid": EVENT}}, "params": {"misp2_venv": str(venv), "misp2_script": str(script)}}
        )
    )
    assert result == {"data": True} and (tmp_path / "received.txt").read_text() == EVENT


def test_actual_requests_wire_contract_has_form_auth_and_json_upload(monkeypatch):
    captured = []

    def send(self, req, **kwargs):
        captured.append(req)
        if "oauth2" in req.url:
            assert "Authorization" not in req.headers
            assert parse_qs(req.body)["client_secret"] == ["client-secret"]
            result = response({"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600})
        else:
            assert (
                req.headers["Authorization"] == "Bearer access-token"
                and req.headers["Content-Type"] == "application/json"
            )
            assert "api-version=2024-02-01-preview" in req.url
            assert len(json.loads(req.body)["stixobjects"]) == 1
            result = response()
        result.request, result.url = req, req.url
        return result

    for name, value in [
        ("SENTINEL_TENANT_ID", TENANT),
        ("SENTINEL_CLIENT_ID", CLIENT),
        ("SENTINEL_CLIENT_SECRET", "client-secret"),
    ]:
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    assert run()["data"]["uploaded"] == 1 and len(captured) == 2


class TestSentinelPublishHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {
                "sentinel_publish": publish,
                "type:sentinel_publish": "action_mod",
                "export_sentinel": wrapper,
                "type:export_sentinel": "action_mod",
            }
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_direct_mode_query(self):
        descriptors = {item["name"]: item for item in json.loads(self.fetch("/modules").body)}
        assert set(descriptors) == {"sentinel_publish", "export_sentinel"}
        assert descriptors["sentinel_publish"]["meta"]["config"]["blocking"] is True
        for name in descriptors:
            payload = json.loads(request(mode="direct", dry_run=True))
            payload["module"] = name
            result = self.fetch(
                "/query", method="POST", headers={"Content-Type": "application/json"}, body=json.dumps(payload)
            )
            assert result.code == 200 and json.loads(result.body)["data"]["planned"] == 1
