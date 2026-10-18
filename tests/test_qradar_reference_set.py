import base64
import copy
import csv
import io
import json
from unittest.mock import MagicMock

import pytest
import requests
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.lib import qradar_reference_set as conversion
from misp_modules.modules.action_mod import qradar_reference_set_publish as publish
from misp_modules.modules.export_mod import qradar_reference_set_export as export


def attribute(kind="ip-dst", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "uuid": "attribute-1", "to_ids": True, **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"uuid": "event-1", "Attribute": attributes or [], "Object": objects or [], **metadata}


def export_values(data=None, **config):
    result = export.handler(json.dumps({"data": event([attribute()]) if data is None else data, "config": config}))
    assert "error" not in result, result
    text = base64.b64decode(result["data"]).decode("utf-8")
    values = json.loads(text) if config.get("format") == "json" else [row[0] for row in csv.reader(io.StringIO(text))]
    return values, result


def run(data=None, **params):
    return publish.handler(
        json.dumps(
            {
                "data": event([attribute()]) if data is None else data,
                "params": {"reference_set_id": "42", "domain_id": "7", **params},
            }
        )
    )


def response(body, status=200):
    result = MagicMock(spec=requests.Response)
    result.status_code = status
    result.json.return_value = body
    return result


@pytest.fixture
def client(monkeypatch):
    session = MagicMock(spec=requests.Session)
    session.headers = {}

    def request(method, url, **kwargs):
        if method == "GET":
            return response(
                {
                    "id": 42,
                    "name": "MISP IPv4",
                    "entry_type": "IP",
                    "expiry_type": "LAST_SEEN",
                    "time_to_live": 86400000,
                }
            )
        return response({**kwargs["json"], "id": 901, "delete_entry": False}, 201)

    session.request.side_effect = request
    session.constructor = MagicMock(return_value=session)
    monkeypatch.setattr(publish.requests, "Session", session.constructor)
    monkeypatch.setenv("QRADAR_URL", "https://qradar.example")
    monkeypatch.setenv("QRADAR_API_TOKEN", "test-token")
    monkeypatch.delenv("QRADAR_CA_BUNDLE", raising=False)
    return session


@pytest.mark.parametrize(
    "kind,value,selected,expected",
    [
        ("ip-src", "192.0.2.1", "ipv4", "192.0.2.1"),
        ("ip-dst", "2001:0DB8:0000::1", "ipv6", "2001:db8::1"),
        ("domain", "EXAMPLE.org.", "domain", "example.org"),
        ("hostname", "bücher.example", "domain", "xn--bcher-kva.example"),
        ("url", 'https://example.org:8443/A?q="x",Y=1', "url", 'https://example.org:8443/A?q="x",Y=1'),
        *[(kind, "A" * length, kind, "a" * length) for kind, length in conversion.HASH_LENGTHS.items()],
        *[
            (f"filename|{kind}", "a|b.exe|" + "A" * length, kind, "a" * length)
            for kind, length in conversion.HASH_LENGTHS.items()
        ],
        ("malware-sample", "a.exe|" + "A" * 32, "md5", "a" * 32),
        ("domain|ip", "EXAMPLE.org|192.0.2.1", "domain", "example.org"),
        ("domain|ip", "example.org|192.0.2.1", "ipv4", "192.0.2.1"),
        ("domain|ip", "example.org|2001:db8::1", "ipv6", "2001:db8::1"),
    ],
)
@pytest.mark.parametrize("output_format", ["csv", "json"])
def test_export_normalizes_supported_types_and_serializes_plain_values(kind, value, selected, expected, output_format):
    values, result = export_values(event([attribute(kind, value)]), indicator_type=selected, format=output_format)
    assert values == [expected]
    assert result["summary"]["count"] == 1
    assert result["sources"][expected][0]["misp_type"] == kind


def test_standard_legacy_bare_object_deduplication_and_nonmutation():
    obj = {"uuid": "object-1", "name": "domain-ip", "Attribute": [attribute(uuid="object-attribute")]}
    standard = event([attribute()], [obj])
    legacy = {"Event": {"uuid": "event-2"}, "Attribute": [attribute(uuid="legacy-attribute")]}
    data = [{"Event": standard}, standard, legacy]
    original = copy.deepcopy(data)
    values, result = export_values(data)
    assert values == ["192.0.2.1"]
    refs = result["sources"][values[0]]
    assert len(refs) == 3 and refs[1]["object"] == "object-1"
    assert data == original


@pytest.mark.parametrize(
    "template,relation,value,selected",
    [
        ("file", "sha256", "a" * 64, "sha256"),
        ("domain-ip", "domain", "example.org", "domain"),
    ],
)
def test_existing_object_templates_are_accepted(template, relation, value, selected):
    obj = MISPObject(template, strict=True)
    obj.add_attribute(relation, value=value, to_ids=True)
    obj._validate()
    values, result = export_values(event(objects=[json.loads(obj.to_json())]), indicator_type=selected)
    assert values == [value] and result["sources"][value][0]["object"] == obj.uuid


def test_csv_has_no_header_and_is_deterministic():
    data = event([attribute(value="192.0.2.2"), attribute(), attribute()])
    values, result = export_values(data)
    assert values == ["192.0.2.1", "192.0.2.2"]
    assert base64.b64decode(result["data"]) == b"192.0.2.1\n192.0.2.2\n"


def test_empty_selection_exports_empty_csv_or_json_array():
    assert export_values([])[0] == []
    assert base64.b64decode(export_values([])[1]["data"]) == b""
    assert export_values([], format="json")[0] == []


def test_only_selected_type_and_ids_are_included_and_deleted_data_is_never_included():
    data = [
        event(
            [
                attribute(to_ids="false"),
                attribute(deleted="1"),
                attribute("domain", "example.org"),
                attribute("ip-dst|port", "192.0.2.1|443"),
                attribute("email-src", "test@example.org"),
            ],
            [{"deleted": True, "Attribute": [attribute()]}],
        ),
        event([attribute()], deleted=True),
    ]
    values, result = export_values(data)
    assert values == []
    assert result["summary"]["skipped"] == {"deleted or non-IDS": 2, "other indicator type": 1, "unsupported": 2}
    assert len(result["warnings"]) == 3
    assert export_values(data, include_non_ids="true")[0] == ["192.0.2.1"]


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-dst", "192.0.2.0/24"),
        ("ip-dst", "999.2.3.4"),
        ("ip-src", "fe80::1%eth0"),
        ("domain", "bad'name.example"),
        ("domain", "a..example"),
        ("domain", "a" * 64 + ".example"),
        ("domain", ".".join(["a" * 63] * 4)),
        ("domain", "example.org.."),
        ("domain", "bad\ud800.example"),
        ("domain", "example.org\n"),
        ("url", "https://example.org:bad/"),
        ("url", "https://example.org:65536/"),
        ("url", "example.org/path"),
        ("url", "https://example.org/a b"),
        ("url", "https://example.org/a\x00b"),
        ("md5", "bad"),
        ("sha256", "g" * 64),
        ("filename|md5", "a.exe|bad"),
        ("domain|ip", "example.org|not-ip"),
        ("domain|ip", "bad..example|192.0.2.1"),
        ("domain", None),
        ("ip-dst", ""),
    ],
)
def test_invalid_supported_values_are_skipped_before_network(client, kind, value):
    result = run(event([attribute(kind, value)]))
    assert result["data"]["skipped"] == {"malformed": 1}
    client.constructor.assert_not_called()


@pytest.mark.parametrize(
    "value,expected",
    [
        (True, True),
        (1, True),
        ("TRUE", True),
        ("1", True),
        (False, False),
        ("0", False),
        ("false", False),
        (None, False),
        ("", False),
    ],
)
def test_misp_boolean_encodings(value, expected):
    values, _ = export_values(event([attribute(to_ids=value)]))
    assert bool(values) is expected


@pytest.mark.parametrize(
    "config",
    [
        [],
        {"indicator_type": "all"},
        {"indicator_type": []},
        {"format": "xml"},
        {"format": False},
        {"include_non_ids": "maybe"},
        {"include_non_ids": 2},
    ],
)
def test_export_rejects_bad_configuration(config):
    assert "error" in export.handler(json.dumps({"data": [], "config": config}))


@pytest.mark.parametrize(
    "data",
    [None, "bad", [1], {"Event": "bad"}, event(attributes=[1]), {"Object": {}}, event([attribute(to_ids="maybe")])],
)
def test_both_modules_reject_malformed_input(data):
    assert "error" in export.handler(json.dumps({"data": data}))
    assert "error" in publish.handler(json.dumps({"data": data, "params": {"reference_set_id": 42, "domain_id": 7}}))


@pytest.mark.parametrize("module", [export, publish])
def test_request_contract(module):
    assert module.handler() is False
    for payload in ["invalid JSON", "[]", "null"]:
        assert "error" in module.handler(payload)


def test_publish_checks_set_and_sends_current_api_contract(client):
    result = run()
    assert result["data"]["created"] == 1 and result["data"]["success"] is True
    assert result["result_key"] == "qradar_reference_set_publish"
    lookup, create = client.request.call_args_list
    assert lookup.args == ("GET", "https://qradar.example/api/reference_data_collections/sets/42")
    assert create.args == ("POST", "https://qradar.example/api/reference_data_collections/set_entries")
    assert create.kwargs["json"] == {
        "collection_id": 42,
        "domain_id": 7,
        "source": "misp-modules",
        "value": "192.0.2.1",
    }
    assert client.headers == {"SEC": "test-token", "Version": "20.0", "Accept": "application/json"}
    assert (
        create.kwargs["verify"] is True and create.kwargs["allow_redirects"] is False and create.kwargs["timeout"] == 15
    )
    assert not any(
        field in create.kwargs["json"] for field in ["id", "delete_entry", "first_seen", "last_seen", "notes"]
    )
    client.close.assert_called_once()


def test_existing_values_are_reported_as_updated_by_http_status(client):
    client.request.side_effect = [
        response({"id": 42, "entry_type": "IP"}),
        response({"id": 901, "collection_id": 42, "domain_id": 7, "source": "misp-modules", "value": "192.0.2.1"}),
    ]
    result = run()
    assert result["data"]["updated"] == 1 and result["data"]["created"] == 0


@pytest.mark.parametrize(
    "selected,entry_type,value",
    [
        ("domain", "ALN", "example.org"),
        ("domain", "ALNIC", "example.org"),
        ("url", "ALN", "https://example.org/CaseSensitive"),
        ("ipv6", "ALN", "2001:db8::1"),
        *[
            (kind, entry_type, "a" * length)
            for kind, length in conversion.HASH_LENGTHS.items()
            for entry_type in ["ALN", "ALNIC"]
        ],
    ],
)
def test_compatible_set_types_publish(client, selected, entry_type, value):
    kind = "ip-src" if selected == "ipv6" else selected
    payload = {"collection_id": 42, "domain_id": 7, "source": "misp-modules", "value": value}
    client.request.side_effect = [response({"id": 42, "entry_type": entry_type}), response({**payload, "id": 901}, 201)]
    assert run(event([attribute(kind, value)]), indicator_type=selected)["data"]["created"] == 1


@pytest.mark.parametrize(
    "target,selected,kind,value",
    [
        ({"id": 43, "entry_type": "IP"}, "ipv4", "ip-dst", "192.0.2.1"),
        ({"id": True, "entry_type": "IP"}, "ipv4", "ip-dst", "192.0.2.1"),
        ({"id": "42", "entry_type": "IP"}, "ipv4", "ip-dst", "192.0.2.1"),
        ({"id": 42, "entry_type": "ALN"}, "ipv4", "ip-dst", "192.0.2.1"),
        ({"id": 42, "entry_type": []}, "ipv4", "ip-dst", "192.0.2.1"),
        ({"id": 42, "entry_type": "ALNIC"}, "url", "url", "https://example.org/Case"),
        ({"id": 42, "entry_type": "IP"}, "ipv6", "ip-src", "2001:db8::1"),
    ],
)
def test_wrong_identity_or_type_prevents_all_writes(client, target, selected, kind, value):
    client.request.side_effect = None
    client.request.return_value = response(target)
    result = run(event([attribute(kind, value)]), indicator_type=selected)
    assert "error" in result and result["data"]["success"] is False
    assert client.request.call_count == 1
    client.close.assert_called_once()


def test_dry_run_needs_no_credentials_and_matches_export_values(client, monkeypatch):
    monkeypatch.delenv("QRADAR_URL")
    monkeypatch.delenv("QRADAR_API_TOKEN")
    data = event([attribute(), attribute(uuid="other-source")])
    result = run(data, dry_run="true", domain_id="0")
    assert result["data"]["planned"] == 1
    item = result["data"]["items"][0]
    assert item["payload"]["domain_id"] == 0
    assert item["payload"]["value"] == export_values(data)[0][0]
    assert len(item["sources"]) == 2
    client.constructor.assert_not_called()


def test_shared_domain_is_explicit_and_serialized_as_null(client):
    result = run(domain_id="SHARED")
    assert result["data"]["created"] == 1
    assert client.request.call_args.kwargs["json"]["domain_id"] is None


def test_shared_acknowledgement_requires_an_explicit_null_domain_field(client):
    record = {"id": 901, "collection_id": 42, "source": "misp-modules", "value": "192.0.2.1"}
    client.request.side_effect = [response({"id": 42, "entry_type": "IP"}), response(record, 201)]
    assert run(domain_id="SHARED")["data"]["failed"] == 1


@pytest.mark.parametrize(
    "params",
    [
        {"reference_set_id": None},
        {"reference_set_id": 0},
        {"reference_set_id": "42/evil"},
        {"reference_set_id": True},
        {"reference_set_id": 1.5},
        {"reference_set_id": "9" * 20},
        {"domain_id": None},
        {"domain_id": -1},
        {"domain_id": False},
        {"domain_id": "7,8"},
        {"indicator_type": "all"},
        {"source": "bad\nlabel"},
        {"source": False},
        {"dry_run": "maybe"},
    ],
)
def test_invalid_action_parameters_fail_before_network(client, params):
    assert "error" in run(**params)
    client.constructor.assert_not_called()


@pytest.mark.parametrize("field", ["filteredItems", "matchingData"])
def test_action_rejects_unapplied_workflow_filters(client, field):
    result = publish.handler(
        json.dumps({"params": {"reference_set_id": 42, "domain_id": 7}, "data": event([attribute()]), field: []})
    )
    assert "error" in result
    client.constructor.assert_not_called()


@pytest.mark.parametrize(
    "origin",
    [
        "http://qradar.example",
        "https://user:password@qradar.example",
        "https://@qradar.example",
        "https://:password@qradar.example",
        "https://qradar.example/api",
        "https://qradar.example/?q=x",
        "https://qradar.example/#x",
        "https://qradar.example:bad",
        "https://qradar.example\n",
        "",
    ],
)
def test_invalid_console_origins_cannot_receive_tokens(client, monkeypatch, origin):
    monkeypatch.setenv("QRADAR_URL", origin)
    result = run()
    assert "error" in result and "password" not in json.dumps(result)
    client.constructor.assert_not_called()


@pytest.mark.parametrize("token", ["", "secret\r\nHeader: bad", "secret token", "tökén"])
def test_invalid_token_is_not_exposed(client, monkeypatch, token):
    monkeypatch.setenv("QRADAR_API_TOKEN", token)
    assert "error" in run()
    client.constructor.assert_not_called()


def test_server_ca_bundle_is_used_without_disabling_verification(client, monkeypatch):
    monkeypatch.setenv("QRADAR_CA_BUNDLE", "/etc/certs/qradar-ca.pem")
    assert run()["data"]["created"] == 1
    assert all(call.kwargs["verify"] == "/etc/certs/qradar-ca.pem" for call in client.request.call_args_list)


def test_unreadable_ca_bundle_fails_preflight_without_exposing_exception_details(client):
    client.request.side_effect = OSError("test-token")
    result = run()
    assert "error" in result and "test-token" not in json.dumps(result)
    assert client.request.call_count == 1
    client.close.assert_called_once()


def test_action_limit_is_checked_before_any_network(client):
    data = event([attribute(value=f"192.0.2.{index}") for index in range(101)])
    assert "error" in run(data)
    client.constructor.assert_not_called()
    assert export_values(data)[1]["summary"]["count"] == 101


@pytest.mark.parametrize("status", [202, 204, 301, 302, 400, 401, 403, 404, 422, 429, 500])
def test_bad_lookup_http_status_does_not_write_or_expose_response(client, status):
    client.request.side_effect = None
    client.request.return_value = response({"message": "test-token"}, status)
    result = run()
    assert "error" in result and "test-token" not in json.dumps(result)
    assert client.request.call_count == 1


@pytest.mark.parametrize(
    "body",
    [
        [],
        None,
        {},
        {"id": 42, "entry_type": "IP", "errors": [{}]},
        {"http_response": {"code": 500}},
        {"id": 42, "entry_type": "IP", "warnings": [{}]},
    ],
)
def test_malformed_lookup_and_api_errors_prevent_writes(client, body):
    client.request.side_effect = None
    client.request.return_value = response(body)
    assert "error" in run()
    assert client.request.call_count == 1


@pytest.mark.parametrize(
    "change",
    [
        {"id": None},
        {"id": True},
        {"collection_id": 43},
        {"collection_id": True},
        {"domain_id": 8},
        {"domain_id": True},
        {"value": "192.0.2.2"},
        {"source": "foreign"},
        {"delete_entry": True},
    ],
)
def test_write_acknowledgement_must_confirm_identity_domain_value_and_source(client, change):
    record = {"id": 901, "collection_id": 42, "domain_id": 7, "value": "192.0.2.1", "source": "misp-modules", **change}
    client.request.side_effect = [response({"id": 42, "entry_type": "IP"}), response(record, 201)]
    result = run()
    assert result["data"]["failed"] == 1 and result["data"]["created"] == 0
    assert "unknown" in result["data"]["items"][0]["error"]
    assert client.request.call_count == 2


@pytest.mark.parametrize(
    "failure",
    [requests.Timeout("test-token"), requests.ConnectionError("test-token"), response({"message": "test-token"}, 429)],
)
def test_partial_publication_preserves_success_and_reports_uncertain_outcomes_without_retry(client, failure):
    good = {"id": 901, "collection_id": 42, "domain_id": 7, "value": "192.0.2.1", "source": "misp-modules"}
    client.request.side_effect = [response({"id": 42, "entry_type": "IP"}), response(good, 201), failure]
    result = run(event([attribute(), attribute(value="192.0.2.2")]))
    assert result["data"]["created"] == 1 and result["data"]["failed"] == 1
    assert result["data"]["success"] is False and "partial" in result["error"]
    assert "test-token" not in json.dumps(result) and client.request.call_count == 3
    client.close.assert_called_once()


def test_invalid_json_response_is_sanitized(client):
    bad = response({})
    bad.json.side_effect = ValueError("test-token")
    client.request.side_effect = [response({"id": 42, "entry_type": "IP"}), bad]
    result = run()
    assert result["data"]["failed"] == 1 and "test-token" not in json.dumps(result)


def test_processing_budget_is_checked_after_target_lookup(client, monkeypatch):
    clock = iter([0, publish.DEADLINE_SECONDS + 1])
    monkeypatch.setattr(publish.time, "monotonic", lambda: next(clock))
    result = run()
    assert result["data"]["failed"] == 1 and client.request.call_count == 1


def test_requests_serializes_actual_wire_contract(monkeypatch):
    calls = []

    def send(self, request, **kwargs):
        calls.append((request, kwargs))
        if request.method == "GET":
            assert request.path_url == "/api/reference_data_collections/sets/42"
            body, status = {"id": 42, "entry_type": "IP"}, 200
        else:
            assert request.path_url == "/api/reference_data_collections/set_entries"
            payload = json.loads(request.body)
            assert payload == {"collection_id": 42, "domain_id": 0, "source": "misp-modules", "value": "192.0.2.1"}
            assert request.headers["Content-Type"] == "application/json"
            body, status = {**payload, "id": 901}, 201
        result = requests.Response()
        result.status_code, result._content = status, json.dumps(body).encode()
        result.request, result.url = request, request.url
        return result

    monkeypatch.setenv("QRADAR_URL", "https://qradar.example/")
    monkeypatch.setenv("QRADAR_API_TOKEN", "test-token")
    monkeypatch.delenv("QRADAR_CA_BUNDLE", raising=False)
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    assert run(domain_id=0)["data"]["created"] == 1
    assert [request.method for request, _ in calls] == ["GET", "POST"]
    assert all(request.headers["SEC"] == "test-token" and request.headers["Version"] == "20.0" for request, _ in calls)


class TestQRadarHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {
                "qradar_reference_set_export": export,
                "type:qradar_reference_set_export": "export_mod",
                "qradar_reference_set_publish": publish,
                "type:qradar_reference_set_publish": "action_mod",
            }
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_export_and_action_have_distinct_names_and_contracts(self):
        descriptors = {descriptor["name"]: descriptor for descriptor in json.loads(self.fetch("/modules").body)}
        assert set(descriptors) == {"qradar_reference_set_export", "qradar_reference_set_publish"}
        assert descriptors["qradar_reference_set_export"]["type"] == "export_mod"
        assert descriptors["qradar_reference_set_publish"]["meta"]["config"]["blocking"] is True
        for name in descriptors:
            result = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps(
                    {
                        "module": name,
                        "data": [event([attribute()])],
                        "params": {"reference_set_id": 42, "domain_id": 7, "dry_run": True},
                    }
                ),
            )
            assert result.code == 200
            body = json.loads(result.body)
            assert "error" not in body
            if name.endswith("_export"):
                assert base64.b64decode(body["data"]) == b"192.0.2.1\n"
            else:
                assert body["data"]["planned"] == 1
