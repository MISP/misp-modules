import base64
import copy
import csv
import io
import json
from pathlib import Path

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import splunk_export


def attribute(kind="domain", value="example.org", **metadata):
    return {"type": kind, "value": value, "to_ids": True, "uuid": "attribute-1", **metadata}


def event(attributes=None, objects=None, **metadata):
    return {
        "uuid": "event-1",
        "id": "42",
        "info": "Example event",
        "Attribute": attributes or [],
        "Object": objects or [],
        **metadata,
    }


def export(data, config=None):
    request = {"data": data, "config": config}
    result = splunk_export.handler(json.dumps(request))
    assert "error" not in result, result
    return list(csv.DictReader(io.StringIO(base64.b64decode(result["data"]).decode("utf-8")))), result


def test_standard_legacy_and_bare_events_preserve_object_context_without_mutation():
    obj = {
        "uuid": "object-1",
        "name": "domain-ip",
        "Tag": [{"name": "object-tag"}],
        "Attribute": [attribute("ip-dst", "2001:db8::1", object_relation="ip")],
    }
    standard = event([attribute()], [obj], Tag=[{"name": "tlp:amber"}])
    legacy = {
        "Event": {key: value for key, value in standard.items() if key not in ("Attribute", "Object", "Tag")},
        "Attribute": standard["Attribute"],
        "Object": standard["Object"],
        "EventTag": [{"Tag": {"name": "tlp:amber"}}],
    }
    original = copy.deepcopy([standard, legacy])
    expected, _ = export([standard])
    assert export([{"Event": standard}])[0] == expected
    assert export([legacy])[0] == expected
    assert [standard, legacy] == original
    assert [(row["indicator"], row["object_uuid"]) for row in expected] == [
        ("example.org", ""),
        ("2001:db8::1", "object-1"),
    ]
    assert expected[1]["object_name"] == "domain-ip"
    assert expected[1]["object_relation"] == "ip"
    assert json.loads(expected[1]["tags"]) == ["object-tag", "tlp:amber"]


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("domain|ip", "example.org|192.0.2.1", [("example.org", "domain", ""), ("192.0.2.1", "ip", "")]),
        ("ip-src|port", "2001:db8::1|443", [("2001:db8::1", "ip", "443")]),
        ("ip-dst|port", "192.0.2.1|0", [("192.0.2.1", "ip", "0")]),
        ("hostname|port", "host.example.org|65535", [("host.example.org", "hostname", "65535")]),
        ("filename|md5", "a|b.exe|" + "a" * 32, [("a|b.exe", "filename", ""), ("a" * 32, "md5", "")]),
        ("filename|sha1", "a.exe|" + "a" * 40, [("a.exe", "filename", ""), ("a" * 40, "sha1", "")]),
        ("filename|sha256", "a.exe|" + "a" * 64, [("a.exe", "filename", ""), ("a" * 64, "sha256", "")]),
        ("filename|sha512", "a.exe|" + "a" * 128, [("a.exe", "filename", ""), ("a" * 128, "sha512", "")]),
        ("malware-sample", "a.exe|" + "a" * 32, [("a.exe", "filename", ""), ("a" * 32, "md5", "")]),
    ],
)
def test_composites_preserve_original_value_and_port(kind, value, expected):
    rows, _ = export([event([attribute(kind, value)])])
    assert [(row["indicator"], row["indicator_type"], row["port"]) for row in rows] == expected
    assert all(row["original_value"] == value and row["misp_type"] == kind for row in rows)
    assert all(row["attribute_uuid"] == "attribute-1" for row in rows)


@pytest.mark.parametrize(
    "kind,value,indicator_type,cim_fields",
    [
        ("ip-src", "192.0.2.1", "ip", "src_ip"),
        ("ip-dst", "2001:db8::1", "ip", "dest_ip"),
        ("domain", "example.org", "domain", "query"),
        ("hostname", "host.example.org", "hostname", "dest"),
        ("url", 'https://example.org/?q="quoted",x=1', "url", "url"),
        ("email-src", "sender@example.org", "email", "src_user"),
        ("email-dst", "recipient@example.org", "email", "recipient"),
        ("filename", "O'Brien.exe", "filename", "file_name"),
        ("md5", "a" * 32, "md5", "file_hash"),
        ("sha1", "a" * 40, "sha1", "file_hash"),
        ("sha256", "a" * 64, "sha256", "file_hash"),
        ("sha512", "a" * 128, "sha512", "file_hash"),
    ],
)
def test_simple_indicator_types(kind, value, indicator_type, cim_fields):
    rows, _ = export([event([attribute(kind, value)])])
    assert [(row["indicator"], row["indicator_type"], row["cim_fields"]) for row in rows] == [
        (value, indicator_type, cim_fields),
    ]


def test_csv_round_trip_preserves_unicode_quotes_newlines_and_scoped_tags():
    comment = 'Evidence, "quoted"\nsecond line: café'
    source = attribute(
        "url",
        'https://example.org/?q="a,b"',
        comment=comment,
        first_seen="2026-10-01T12:00:00+00:00",
        last_seen="2026-10-02T12:00:00+00:00",
        AttributeTag=[{"Tag": {"name": 'campaign:"α,β"'}}],
    )
    rows, _ = export([event([source], Tag=[{"name": "tlp:amber"}, {"name": "tlp:amber"}])])
    assert len(rows) == 1
    assert rows[0]["comment"] == comment
    assert rows[0]["indicator"] == source["value"]
    assert rows[0]["first_seen"] == source["first_seen"]
    assert rows[0]["last_seen"] == source["last_seen"]
    assert json.loads(rows[0]["tags"]) == ['campaign:"α,β"', "tlp:amber"]


def test_all_events_are_exported_and_deduplication_keeps_distinct_sources():
    source = attribute()
    first = event([source, source, attribute(uuid="attribute-2")])
    second = event([source], uuid="event-2", id="43")
    rows, _ = export([first, second])
    assert [(row["event_uuid"], row["attribute_uuid"]) for row in rows] == [
        ("event-1", "attribute-1"),
        ("event-1", "attribute-2"),
        ("event-2", "attribute-1"),
    ]


@pytest.mark.parametrize(
    "template,relation,value",
    [
        ("domain-ip", "domain", "example.org"),
        ("file", "sha256", "a" * 64),
    ],
)
def test_existing_pymisp_object_templates_need_no_extensions(template, relation, value):
    obj = MISPObject(template, strict=True)
    obj.add_attribute(relation, value=value, to_ids=True)
    obj._validate()
    rows, _ = export([event(objects=[json.loads(obj.to_json())])])
    assert rows[0]["indicator"] == value
    assert rows[0]["object_uuid"] == obj.uuid
    assert rows[0]["object_name"] == template


def test_repository_legacy_fixture():
    fixture = json.loads((Path(__file__).parent / "test_files" / "misp_event.json").read_text())
    assert export([fixture])[0] == []
    rows, result = export([fixture], {"include_non_ids": True})
    assert [row["indicator"] for row in rows] == ["google.com", "127.0.0.1"]
    assert all(row["event_uuid"] == fixture["Event"]["uuid"] for row in rows)
    assert json.loads(rows[0]["tags"]) == ["tlp:white"]
    assert result["warnings"] == ["Skipped 2 unsupported attribute(s)."]


@pytest.mark.parametrize("setting", [False, 0, "false", "False", "0", "", None])
def test_default_filter_does_not_treat_false_strings_as_true(setting):
    data = [event([attribute(), attribute(to_ids="0"), attribute(to_ids=False)])]
    rows, _ = export(data, {"include_non_ids": setting})
    assert len(rows) == 1
    assert rows[0]["to_ids"] == "true"


@pytest.mark.parametrize("setting", [True, 1, "true", "True", "1"])
def test_include_non_ids_never_includes_deleted_attributes_objects_or_events(setting):
    data = [
        event(
            [attribute(to_ids=False), attribute(value="deleted.example", deleted="1")],
            [{"deleted": True, "Attribute": [attribute(value="object.example")]}],
        ),
        event([attribute(value="event.example")], deleted=True),
    ]
    rows, _ = export(data, {"include_non_ids": setting})
    assert [row["indicator"] for row in rows] == ["example.org"]
    assert rows[0]["to_ids"] == "false"


@pytest.mark.parametrize(
    "kind,value",
    [
        ("domain|ip", "example.org"),
        ("domain|ip", "example.org|"),
        ("domain|ip", "a|b|c"),
        ("ip-dst|port", "192.0.2.1|65536"),
        ("ip-src|port", "192.0.2.1|-1"),
        ("hostname|port", "host|not-a-port"),
        ("domain", " "),
        ("domain", None),
    ],
)
def test_malformed_attributes_are_reported_without_losing_valid_indicators(kind, value):
    rows, result = export([event([attribute(kind, value), attribute()])])
    assert [row["indicator"] for row in rows] == ["example.org"]
    assert result["warnings"] == ["Skipped 1 malformed attribute(s)."]


def test_empty_and_unsupported_input_produce_a_valid_header_only_csv():
    assert export([])[0] == []
    rows, result = export([event([attribute("text", "Not an IOC")])])
    assert rows == []
    assert result["warnings"] == ["Skipped 1 unsupported attribute(s)."]
    header = next(csv.reader(io.StringIO(base64.b64decode(result["data"]).decode())))
    assert header == list(splunk_export.CSV_FIELDS)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"data": {}},
        {"data": ["event"]},
        {"data": [{"Event": "event"}]},
        {"data": [{"Attribute": "attributes"}]},
        {"data": [{"Object": ["object"]}]},
        {"data": [], "config": {"include_non_ids": "maybe"}},
        {"data": [], "config": [1]},
        {"data": [], "config": []},
    ],
)
def test_invalid_requests_return_errors(payload):
    assert "error" in splunk_export.handler(json.dumps(payload))


def test_handler_contract_and_discovery_metadata():
    assert splunk_export.handler() is False
    assert "error" in splunk_export.handler("not json")
    assert splunk_export.introspection()["outputFileExtension"] == "csv"
    assert splunk_export.version()["module-type"] == ["export"]
    assert "include_non_ids" in splunk_export.version()["config"]


class TestSplunkExportHTTP(AsyncHTTPTestCase):
    """Exercise discovery and the real /query handler without loading unrelated modules."""

    def get_app(self):
        self.previous_handlers = service.MODULES_HANDLERS.copy()
        self.previous_cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"splunk_export": splunk_export, "type:splunk_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous_handlers)
        service.ListModules.CACHE = self.previous_cache
        super().tearDown()

    def test_discovery_and_query(self):
        modules = json.loads(self.fetch("/modules").body)
        assert modules[0]["name"] == "splunk_export"
        response = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "splunk_export", "data": [{"Event": event([attribute()])}]}),
        )
        assert response.code == 200
        result = json.loads(response.body)
        rows = list(csv.DictReader(io.StringIO(base64.b64decode(result["data"]).decode())))
        assert rows[0]["indicator"] == "example.org"
