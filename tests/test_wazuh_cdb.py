import base64
import copy
import hashlib
import json
import re
from unittest.mock import MagicMock

import pytest
import requests
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.lib import wazuh_cdb as conversion
from misp_modules.modules.action_mod import wazuh_cdb_publish as publish
from misp_modules.modules.export_mod import wazuh_cdb_export as export


def attribute(kind="ip-dst", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "to_ids": True, "uuid": "attribute-1", **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"uuid": "event-1", "Attribute": attributes or [], "Object": objects or [], **metadata}


def run_export(data=None, **config):
    return export.handler(json.dumps({"data": event([attribute()]) if data is None else data, "config": config}))


def run(data=None, **params):
    return publish.handler(
        json.dumps(
            {"data": event([attribute()]) if data is None else data, "params": {"filename": "misp-ipv4", **params}}
        )
    )


def response(body=None, status=200, text="header.payload.signature"):
    result = MagicMock(spec=requests.Response)
    result.status_code, result.text = status, text
    result.json.return_value = body
    return result


def acknowledgement(**changes):
    return {
        "error": 0,
        "data": {
            "affected_items": ["etc/lists/misp-ipv4"],
            "total_affected_items": 1,
            "total_failed_items": 0,
            "failed_items": [],
            **changes,
        },
    }


def reload_acknowledgement(names=("manager",), **changes):
    return {
        "error": 0,
        "data": {
            "affected_items": [{"name": name, "msg": "Ruleset reload request sent successfully."} for name in names],
            "total_affected_items": len(names),
            "total_failed_items": 0,
            "failed_items": [],
            **changes,
        },
    }


@pytest.fixture
def client(monkeypatch):
    session = MagicMock(spec=requests.Session)
    session.__enter__.return_value = session
    session.request.side_effect = [response(), response(acknowledgement())]
    session.constructor = MagicMock(return_value=session)
    monkeypatch.setattr(publish.requests, "Session", session.constructor)
    monkeypatch.setenv("WAZUH_URL", "https://wazuh.example:55000")
    monkeypatch.setenv("WAZUH_USERNAME", "test-user")
    monkeypatch.setenv("WAZUH_PASSWORD", "test-password")
    monkeypatch.delenv("WAZUH_API_TOKEN", raising=False)
    monkeypatch.delenv("WAZUH_CA_BUNDLE", raising=False)
    return session


@pytest.mark.parametrize(
    "kind,value,selected,expected",
    [
        ("ip-src", "192.0.2.1", "ipv4", "192.0.2.1:\n"),
        ("ip-dst", "2001:0DB8:0000::1", "ipv6", '"2001:db8::1":\n'),
        ("ip-dst", "::ffff:192.0.2.1", "ipv6", '"::ffff:c000:201":\n'),
        ("domain", "EXAMPLE.org.", "domain", "example.org:\n"),
        ("hostname", "bücher.example", "domain", "xn--bcher-kva.example:\n"),
        ("domain|ip", "EXAMPLE.org|192.0.2.1", "domain", "example.org:\n"),
        ("domain|ip", "example.org|192.0.2.1", "ipv4", "192.0.2.1:\n"),
        ("domain|ip", "example.org|2001:db8::1", "ipv6", '"2001:db8::1":\n'),
        ("malware-sample", "a.exe|" + "A" * 32, "md5", "a" * 32 + ":\n"),
        *[(kind, "A" * length, kind, "a" * length + ":\n") for kind, length in conversion.HASH_LENGTHS.items()],
        *[
            (f"filename|{kind}", "a|b.exe|" + "A" * length, kind, "a" * length + ":\n")
            for kind, length in conversion.HASH_LENGTHS.items()
        ],
    ],
)
def test_export_matches_cdb_contract(kind, value, selected, expected):
    result = run_export(event([attribute(kind, value)]), indicator_type=selected)
    content = base64.b64decode(result["data"]).decode("ascii")
    assert content == expected
    # Wazuh 4.14.1's upload validation contract, including restrictions on quoted keys:
    # https://github.com/wazuh/wazuh/blob/v4.14.1/framework/wazuh/core/cdb_list.py
    validator = re.compile(r'(?:^"([\w\-: ]+?)"|^[^:"\s]+):(?:"([\w\-: ]*?)"$|[^:\"]*$)')
    assert all(validator.fullmatch(line) for line in content.splitlines())
    assert result["summary"]["count"] == 1 and result["summary"]["skipped"] == {}
    assert (
        result["sources"][expected.split('"')[1] if expected.startswith('"') else expected[:-2]][0]["misp_type"] == kind
    )


def test_export_standard_bare_legacy_object_deduplication_provenance_and_order():
    obj = {"uuid": "object-1", "Attribute": [attribute(uuid="object-attribute")]}
    data = [
        {"Event": event([attribute(value="192.0.2.2")], [obj])},
        event([attribute()]),
        {"Event": {"uuid": "legacy-event"}, "Attribute": [attribute(uuid="legacy-attribute")]},
    ]
    original = copy.deepcopy(data)
    result = run_export(data)
    assert base64.b64decode(result["data"]) == b"192.0.2.1:\n192.0.2.2:\n"
    refs = result["sources"]["192.0.2.1"]
    assert len(refs) == 3 and refs[0]["object"] == "object-1" and refs[2]["event"] == "legacy-event"
    assert data == original


@pytest.mark.parametrize(
    "template,relation,selected,value",
    [("file", "sha256", "sha256", "a" * 64), ("domain-ip", "domain", "domain", "example.org")],
)
def test_existing_object_templates(template, relation, selected, value):
    obj = MISPObject(template, strict=True)
    obj.add_attribute(relation, value=value, to_ids=True)
    result = run_export(event(objects=[json.loads(obj.to_json())]), indicator_type=selected)
    assert base64.b64decode(result["data"]).decode() == value + ":\n"


def test_filters_and_include_non_ids_option():
    data = event(
        [
            attribute(),
            attribute(value="192.0.2.2", to_ids="0"),
            attribute(value="192.0.2.3", deleted="1"),
            attribute("ip-src", "2001:db8::1"),
            attribute("text", "192.0.2.4"),
            attribute(value="bad"),
        ],
        [{"deleted": True, "Attribute": [attribute(value="192.0.2.5")]}],
    )
    result = run_export([data, event([attribute(value="192.0.2.6")], deleted=True)])
    assert base64.b64decode(result["data"]) == b"192.0.2.1:\n"
    assert result["summary"]["skipped"] == {
        "deleted or non-IDS": 2,
        "other indicator type": 1,
        "unsupported": 1,
        "malformed": 1,
    }
    assert base64.b64decode(run_export(data, include_non_ids="true")["data"]) == b"192.0.2.1:\n192.0.2.2:\n"


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-src", "192.0.2.0/24"),
        ("ip-dst", "999.0.2.1"),
        ("ip-src", "fe80::1%eth0"),
        ("ip-dst", "192.0.2.1\nkey:value"),
        ("domain", 'example.org":value'),
        ("domain", "a..example"),
        ("domain", "bad\ud800.example"),
        ("domain", "example.org\u2028key:value"),
        ("sha256", "g" * 64),
        ("domain|ip", "example.org|invalid"),
        ("filename|md5", "a.exe|invalid"),
        ("url", "https://example.org/path"),
        ("ip-dst", None),
        ("ip-dst", ""),
    ],
)
def test_invalid_or_unrepresentable_values_never_reach_wazuh(client, kind, value):
    selected = (
        "ipv6"
        if value == "fe80::1%eth0"
        else "domain" if kind == "domain" else "sha256" if kind == "sha256" else "ipv4"
    )
    result = run(event([attribute(kind, value)]), indicator_type=selected, overwrite=True)
    assert "error" in result
    client.constructor.assert_not_called()


@pytest.mark.parametrize(
    "data",
    [None, [], {}, {"Event": None}, {"Attribute": None}, {"Object": [None]}, {"Object": [{"Attribute": [None]}]}],
)
def test_invalid_or_empty_input_is_rejected_before_network(client, data):
    for module, options in [(export, {"config": {}}), (publish, {"params": {"filename": "misp-ipv4"}})]:
        assert "error" in module.handler(json.dumps({"data": data, **options}))
    client.constructor.assert_not_called()


@pytest.mark.parametrize("raw", ["{", "[]", '"string"', "null"])
def test_invalid_requests(raw):
    assert "error" in export.handler(raw)
    assert "error" in publish.handler(raw)
    assert export.handler() is False and publish.handler() is False


@pytest.mark.parametrize("selected", ["url", "all", [], {}, 0, False])
def test_invalid_type_is_rejected(client, selected):
    assert "error" in run(indicator_type=selected)
    assert "error" in run_export(indicator_type=selected)
    client.constructor.assert_not_called()


@pytest.mark.parametrize(
    "filename", [None, "", "../other", "etc/lists/a", "a.cdb", "a.txt", "a?x=1", "a%2fb", "a\nb", "é", "a" * 129, []]
)
def test_invalid_filenames(client, filename):
    assert "error" in run(filename=filename)
    client.constructor.assert_not_called()


def test_limits_are_checked_before_network(client, monkeypatch):
    monkeypatch.setattr(conversion, "MAX_VALUES", 1)
    assert "error" in run(event([attribute(), attribute(value="192.0.2.2")]))
    monkeypatch.setattr(conversion, "MAX_BYTES", 2)
    assert "2 bytes" in run()["error"]
    client.constructor.assert_not_called()


def test_byte_limit_accepts_exact_boundary_and_rejects_one_byte_over(client, monkeypatch):
    monkeypatch.setattr(conversion, "MAX_BYTES", len(b"192.0.2.1:\n"))
    assert run(dry_run=True)["data"]["status"] == "planned"
    monkeypatch.setattr(conversion, "MAX_BYTES", len(b"192.0.2.1:\n") - 1)
    assert f"{conversion.MAX_BYTES:,} bytes" in run(dry_run=True)["error"]
    client.constructor.assert_not_called()


def test_byte_limit_accommodates_maximum_count_of_long_domain_keys(monkeypatch):
    # 100,000 distinct 253-character DNS names produce 25.5 MB of source text.
    suffix = "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
    values = {f"{index:05d}" + "a" * 58 + suffix: [] for index in range(100000)}
    monkeypatch.setattr(conversion, "collect", lambda *args, **kwargs: (values, {}))
    content, summary, _ = conversion.build([], {"indicator_type": "domain"})
    assert len(content) == 25500000 and len(content) <= conversion.MAX_BYTES
    assert summary["count"] == 100000


def test_dry_run_has_no_network_or_credentials_and_matches_export(client, monkeypatch):
    monkeypatch.delenv("WAZUH_URL")
    monkeypatch.delenv("WAZUH_USERNAME")
    monkeypatch.delenv("WAZUH_PASSWORD")
    result = run(dry_run="true", overwrite="true")
    content = base64.b64decode(run_export()["data"])
    assert result["data"]["content"].encode() == content
    assert result["data"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert result["data"]["status"] == "planned" and result["data"]["success"] is True
    assert result["data"]["overwrite"] is True and result["data"]["activation"] == "pending"
    client.constructor.assert_not_called()


@pytest.mark.parametrize("field", ["dry_run", "overwrite", "include_non_ids"])
def test_invalid_booleans(client, field):
    assert "error" in run(**{field: "maybe"})
    client.constructor.assert_not_called()


def test_action_rejects_non_ids_override_and_filter_extraction(client):
    assert "error" in run(include_non_ids=True)
    for key in ["matchingData", "filteredItems"]:
        result = publish.handler(
            json.dumps({"data": event([attribute()]), "params": {"filename": "misp-ipv4"}, key: []})
        )
        assert "error" in result
    client.constructor.assert_not_called()


@pytest.mark.parametrize("overwrite", [False, True])
def test_login_and_upload_contract(client, overwrite):
    result = run(overwrite=overwrite)
    assert result["data"]["success"] is True and result["data"]["status"] == "uploaded"
    assert result["data"]["activation"] == "pending"
    calls = client.request.call_args_list
    assert len(calls) == 2
    assert calls[0].args == ("POST", "https://wazuh.example:55000/security/user/authenticate")
    assert calls[0].kwargs["auth"] == ("test-user", "test-password") and calls[0].kwargs["params"] == {"raw": "true"}
    assert calls[1].args == ("PUT", "https://wazuh.example:55000/lists/files/misp-ipv4")
    assert calls[1].kwargs["params"] == {"overwrite": str(overwrite).lower()}
    assert calls[1].kwargs["data"] == b"192.0.2.1:\n"
    assert calls[1].kwargs["headers"] == {
        "Content-Type": "application/octet-stream",
        "Authorization": "Bearer header.payload.signature",
    }
    assert "auth" not in calls[1].kwargs
    assert all(
        call.kwargs["verify"] is True and call.kwargs["allow_redirects"] is False and call.kwargs["timeout"] == (5, 30)
        for call in calls
    )
    assert "test-password" not in json.dumps(result) and "header.payload.signature" not in json.dumps(result)
    client.__exit__.assert_called_once()


def test_provided_jwt_skips_login_and_uses_custom_ca(client, monkeypatch):
    monkeypatch.setenv("WAZUH_API_TOKEN", "supplied.jwt.token")
    monkeypatch.setenv("WAZUH_CA_BUNDLE", "/etc/certs/wazuh.pem")
    client.request.side_effect = [response(acknowledgement())]
    assert run()["data"]["success"] is True
    client.request.assert_called_once()
    assert client.request.call_args.args[0] == "PUT"
    assert client.request.call_args.kwargs["verify"] == "/etc/certs/wazuh.pem"
    assert client.request.call_args.kwargs["headers"]["Authorization"] == "Bearer supplied.jwt.token"


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "http://wazuh.example",
        "https://u:p@wazuh.example",
        "https://wazuh.example/api",
        "https://wazuh.example/?x=y",
        "https://wazuh.example/#x",
        "https://wazuh.example:bad",
        "https://wazuh.example:65536",
        "https://wazuh.example\n",
    ],
)
def test_invalid_origins_never_receive_credentials(client, monkeypatch, origin):
    monkeypatch.setenv("WAZUH_URL", origin)
    assert "error" in run()
    client.constructor.assert_not_called()


@pytest.mark.parametrize("token", ["invalid", "header.payload.signature\r\nHeader:x", "token with spaces"])
def test_invalid_server_jwt(client, monkeypatch, token):
    monkeypatch.setenv("WAZUH_API_TOKEN", token)
    result = run()
    assert "error" in result and token not in json.dumps(result)
    client.constructor.assert_not_called()


@pytest.mark.parametrize("text", ["", "invalid-token", '{"error": 1}', "secret\r\nHeader: x"])
def test_bad_authentication_token_prevents_upload(client, text):
    client.request.side_effect = [response(text=text)]
    result = run()
    assert "error" in result and result["data"]["status"] == "not_uploaded"
    assert client.request.call_count == 1


@pytest.mark.parametrize("status", [202, 204, 301, 302, 400, 401, 403, 404, 413, 429, 500])
@pytest.mark.parametrize("during_login", [False, True])
def test_http_failures_do_not_leak_responses_or_retry(client, status, during_login):
    bad = response({"message": "test-password"}, status, text="test-password")
    client.request.side_effect = [bad] if during_login else [response(), bad]
    result = run()
    assert "error" in result and result["data"]["success"] is False
    assert "test-password" not in json.dumps(result)
    assert client.request.call_count == (1 if during_login else 2)
    assert result["data"]["status"] == ("not_uploaded" if during_login else "unknown")


@pytest.mark.parametrize(
    "failure", [requests.Timeout("test-password"), requests.ConnectionError("test-password"), OSError("test-password")]
)
def test_transport_error_has_uncertain_outcome_without_retry(client, failure):
    client.request.side_effect = [response(), failure]
    result = run()
    assert "error" in result and result["data"]["status"] == "unknown"
    assert "test-password" not in json.dumps(result) and client.request.call_count == 2
    client.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        {},
        {"error": 1000},
        {**acknowledgement(), "error": True},
        {**acknowledgement(), "error": 2},
        acknowledgement(total_failed_items=1, failed_items=[{"error": {"code": 1905}}]),
        acknowledgement(failed_items=[{}]),
        acknowledgement(total_affected_items=0),
        acknowledgement(total_affected_items=True),
        acknowledgement(total_failed_items=False),
        acknowledgement(affected_items=["etc/lists/foreign"]),
        acknowledgement(affected_items=["misp-ipv4"]),
    ],
)
def test_wazuh_errors_and_incomplete_or_mismatched_acknowledgements_are_failures(client, body):
    client.request.side_effect = [response(), response(body)]
    result = run()
    assert "error" in result and result["data"]["success"] is False and result["data"]["status"] == "unknown"


def test_invalid_json_acknowledgement_is_sanitized(client):
    bad = response()
    bad.json.side_effect = ValueError("test-password")
    client.request.side_effect = [response(), bad]
    result = run()
    assert "error" in result and "test-password" not in json.dumps(result)


def test_actual_requests_wire_contract(monkeypatch):
    calls = []

    def send(self, request, **kwargs):
        calls.append(request)
        if request.method == "POST":
            assert request.path_url == "/security/user/authenticate?raw=true"
            assert request.headers["Authorization"].startswith("Basic ")
            content = b"header.payload.signature"
        else:
            assert request.path_url == "/lists/files/misp-ipv4?overwrite=false"
            assert request.headers["Authorization"] == "Bearer header.payload.signature"
            assert request.headers["Content-Type"] == "application/octet-stream"
            assert request.body == b"192.0.2.1:\n"
            content = json.dumps(acknowledgement()).encode()
        assert kwargs["verify"]
        result = requests.Response()
        result.status_code, result._content, result.request = 200, content, request
        return result

    monkeypatch.setenv("WAZUH_URL", "https://wazuh.example:55000/")
    monkeypatch.setenv("WAZUH_USERNAME", "test-user")
    monkeypatch.setenv("WAZUH_PASSWORD", "test-password")
    monkeypatch.delenv("WAZUH_API_TOKEN", raising=False)
    monkeypatch.delenv("WAZUH_CA_BUNDLE", raising=False)
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    assert run()["data"]["status"] == "uploaded"
    assert [call.method for call in calls] == ["POST", "PUT"]


@pytest.mark.parametrize("mode,names", [("manager", ["manager"]), ("cluster", ["master-node", "worker-node"])])
def test_reload_after_successful_upload_uses_correct_endpoint_and_same_connection(client, monkeypatch, mode, names):
    monkeypatch.setenv("WAZUH_CA_BUNDLE", "/etc/certs/wazuh.pem")
    client.request.side_effect = [response(), response(acknowledgement()), response(reload_acknowledgement(names))]
    result = run(reload=mode)
    assert result["data"]["success"] is True and result["data"]["status"] == "uploaded"
    assert result["data"]["activation"] == "reload_requested" and result["data"]["reload_nodes"] == names
    assert result["data"]["reload_warning_nodes"] == []
    assert result["data"]["reload"] == mode
    calls = client.request.call_args_list
    assert len(calls) == 3
    assert calls[2].args == ("PUT", f"https://wazuh.example:55000/{mode}/analysisd/reload")
    assert calls[2].kwargs["headers"] == {"Authorization": "Bearer header.payload.signature"}
    assert "data" not in calls[2].kwargs and "auth" not in calls[2].kwargs and "params" not in calls[2].kwargs
    assert all(
        call.kwargs["verify"] == "/etc/certs/wazuh.pem" and call.kwargs["allow_redirects"] is False for call in calls
    )
    assert "confirm completion" in result["warnings"][0]
    assert "header.payload.signature" not in json.dumps(result)


@pytest.mark.parametrize("mode", ["manager", "cluster"])
def test_reload_is_not_attempted_in_dry_run(client, mode):
    result = run(reload=mode, dry_run=True)
    assert result["data"]["reload"] == mode and result["data"]["status"] == "planned"
    assert result["data"]["activation"] == "pending"
    client.constructor.assert_not_called()


@pytest.mark.parametrize("mode", ["true", "all", "MANAGER", True, [], {}, 0])
def test_invalid_reload_mode_is_rejected_before_network(client, mode):
    assert "reload must be" in run(reload=mode)["error"]
    client.constructor.assert_not_called()


@pytest.mark.parametrize("mode", [None, "", "none"])
def test_explicit_upload_only_mode_preserves_previous_behavior(client, mode):
    result = run(reload=mode)
    assert result["data"]["success"] is True and result["data"]["activation"] == "pending"
    assert client.request.call_count == 2


@pytest.mark.parametrize(
    "failed_upload", [response({"error": 1905}), response(status=403), requests.Timeout("test-password")]
)
def test_reload_is_never_attempted_after_failed_upload(client, failed_upload):
    client.request.side_effect = [response(), failed_upload]
    result = run(reload="manager")
    assert "error" in result and result["data"]["status"] == "unknown"
    assert result["data"]["activation"] == "pending" and client.request.call_count == 2


@pytest.mark.parametrize(
    "failure",
    [
        response(status=403),
        response(status=404),
        response(status=429),
        response(status=500),
        requests.Timeout("test-password"),
        requests.ConnectionError("test-password"),
    ],
)
def test_reload_failure_preserves_upload_and_never_retries(client, failure):
    client.request.side_effect = [response(), response(acknowledgement()), failure]
    result = run(reload="cluster")
    assert result["data"]["status"] == "uploaded" and result["data"]["activation"] == "unknown"
    assert result["data"]["success"] is False and "Upload succeeded, but analysisd reload failed" in result["error"]
    assert "test-password" not in json.dumps(result) and client.request.call_count == 3
    client.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        {},
        {"error": 1000},
        {**reload_acknowledgement(), "error": True},
        reload_acknowledgement(total_failed_items=1, failed_items=[{"id": ["worker-node"], "error": {"code": 1914}}]),
        reload_acknowledgement(failed_items=[{}]),
        reload_acknowledgement(names=[]),
        reload_acknowledgement(total_affected_items=2),
        reload_acknowledgement(total_affected_items=True),
        reload_acknowledgement(total_failed_items=False),
        reload_acknowledgement(affected_items=[None]),
        reload_acknowledgement(affected_items=[{"name": "manager"}]),
        reload_acknowledgement(affected_items=[{"name": "", "msg": "Ruleset reload request sent successfully."}]),
        reload_acknowledgement(
            affected_items=[{"name": "manager", "msg": "Failed to send the ruleset reload request."}]
        ),
        reload_acknowledgement(affected_items=[{"name": "manager", "msg": ""}]),
        reload_acknowledgement(names=["master-node", "master-node"]),
    ],
)
def test_bad_reload_acknowledgement_reports_failure_after_upload(client, body):
    client.request.side_effect = [response(), response(acknowledgement()), response(body)]
    result = run(reload="cluster")
    assert result["data"]["status"] == "uploaded" and result["data"]["activation"] == "unknown"
    assert result["data"]["success"] is False and "error" in result


def test_manager_reload_rejects_acknowledgement_of_multiple_nodes(client):
    client.request.side_effect = [
        response(),
        response(acknowledgement()),
        response(reload_acknowledgement(["master", "worker"])),
    ]
    assert "error" in run(reload="manager")


def test_invalid_reload_json_does_not_leak_and_keeps_uploaded_status(client):
    bad = response()
    bad.json.side_effect = ValueError("test-password")
    client.request.side_effect = [response(), response(acknowledgement()), bad]
    result = run(reload="manager")
    assert result["data"]["status"] == "uploaded" and "test-password" not in json.dumps(result)
    assert "error" in result


def test_successful_reload_with_ruleset_warnings_reports_affected_nodes_without_echoing_messages(client):
    body = reload_acknowledgement(affected_items=[{"name": "manager", "msg": "ruleset warning: test-password"}])
    client.request.side_effect = [response(), response(acknowledgement()), response(body)]
    result = run(reload="manager")
    assert result["data"]["success"] is True and result["data"]["activation"] == "reload_requested"
    assert result["data"]["reload_warning_nodes"] == ["manager"]
    assert "ruleset reload warnings" in result["warnings"][-1] and "test-password" not in json.dumps(result)


@pytest.mark.parametrize("mode", ["manager", "cluster"])
def test_actual_requests_reload_wire_contract(monkeypatch, mode):
    calls = []

    def send(self, request, **kwargs):
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer header.payload.signature"
        if len(calls) == 1:
            assert request.path_url == "/lists/files/misp-ipv4?overwrite=false"
            assert request.body == b"192.0.2.1:\n"
            body = acknowledgement()
        else:
            assert request.method == "PUT" and request.path_url == f"/{mode}/analysisd/reload"
            assert request.body is None
            body = reload_acknowledgement(["manager"] if mode == "manager" else ["master", "worker"])
        result = requests.Response()
        result.status_code, result._content, result.request = 200, json.dumps(body).encode(), request
        return result

    monkeypatch.setenv("WAZUH_URL", "https://wazuh.example:55000")
    monkeypatch.setenv("WAZUH_API_TOKEN", "header.payload.signature")
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    result = run(reload=mode)
    assert result["data"]["activation"] == "reload_requested" and len(calls) == 2


class TestWazuhHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {
                "wazuh_cdb_export": export,
                "type:wazuh_cdb_export": "export_mod",
                "wazuh_cdb_publish": publish,
                "type:wazuh_cdb_publish": "action_mod",
            }
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_both_query_contracts(self):
        descriptors = {item["name"]: item for item in json.loads(self.fetch("/modules").body)}
        assert set(descriptors) == {"wazuh_cdb_export", "wazuh_cdb_publish"}
        assert descriptors["wazuh_cdb_export"]["mispattributes"]["outputFileExtension"] == "txt"
        assert descriptors["wazuh_cdb_publish"]["meta"]["config"]["blocking"] is True
        for name in descriptors:
            result = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps(
                    {
                        "module": name,
                        "data": [event([attribute()])],
                        "params": {"filename": "misp-ipv4", "dry_run": True},
                    }
                ),
            )
            assert result.code == 200
            body = json.loads(result.body)
            assert "error" not in body
            if name.endswith("export"):
                assert base64.b64decode(body["data"]) == b"192.0.2.1:\n"
            else:
                assert body["data"]["status"] == "planned"
