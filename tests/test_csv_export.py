import base64
import copy
import csv
import io
import json
from pathlib import Path

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import csv_export


def export(data):
    response = csv_export.handler(json.dumps({"data": data}))
    assert "error" not in response, response
    text = base64.b64decode(response["data"]).decode("utf-8")
    return list(csv.DictReader(io.StringIO(text, newline="")))


def test_all_types_and_events_with_objects_keep_context_and_do_not_mutate():
    event = {
        "id": "12",
        "uuid": "event-1",
        "info": "Investigation",
        "Tag": [{"name": "tlp:amber"}],
        "Attribute": [
            {"type": "text", "value": "context", "to_ids": False, "uuid": "attribute-1"},
            {"type": "domain|ip", "value": "example.org|192.0.2.1", "to_ids": True},
        ],
        "Object": [
            {
                "uuid": "object-1",
                "name": "file",
                "Tag": [{"name": "object-tag"}],
                "Attribute": [
                    {
                        "type": "filename",
                        "value": "sample.exe",
                        "object_relation": "filename",
                        "Tag": [{"name": "attribute-tag"}],
                        "first_seen": "2026-01-01",
                    }
                ],
            }
        ],
    }
    other = {"Attribute": [{"type": "future-type", "value": "anything"}]}
    original = copy.deepcopy(event)
    rows = export([{"Event": event}, other])
    assert event == original
    assert [row["value"] for row in rows] == ["context", "example.org|192.0.2.1", "sample.exe", "anything"]
    assert rows[0]["to_ids"] == "false"
    assert rows[1]["to_ids"] == "true"
    assert rows[2]["event_uuid"] == "event-1"
    assert rows[2]["event_id"] == "12"
    assert rows[2]["object_name"] == "file"
    assert rows[2]["object_uuid"] == "object-1"
    assert rows[2]["object_relation"] == "filename"
    assert rows[2]["first_seen"] == "2026-01-01"
    for key, tags in [
        ("event_tags", ["tlp:amber"]),
        ("object_tags", ["object-tag"]),
        ("attribute_tags", ["attribute-tag"]),
    ]:
        assert json.loads(rows[2][key]) == tags


def test_standard_bare_and_legacy_envelopes():
    event = {"uuid": "event-1", "Attribute": [{"type": "text", "value": "hello"}], "Tag": [{"name": "tag"}]}
    legacy = {"Event": {"uuid": "event-1"}, "Attribute": event["Attribute"], "EventTag": [{"Tag": {"name": "tag"}}]}
    assert export([event]) == export([{"Event": event}]) == export([legacy])


def test_repository_legacy_fixture():
    event = json.loads((Path(__file__).parent / "test_files/misp_event.json").read_text())
    rows = export([event])
    assert len(rows) == len(event["Attribute"])
    assert "google.com|127.0.0.1" in [row["value"] for row in rows]
    assert all(row["event_id"] == event["Event"]["id"] for row in rows)


def test_unicode_quoting_missing_fields_and_scalar_values():
    values = ['café, "quoted"\r\nnext line', 443, 0, None]
    rows = export([{"Attribute": [{"type": "text", "value": value} for value in values]}])
    assert [row["value"] for row in rows] == [values[0], "443", "0", ""]
    assert rows[0]["comment"] == ""


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-1", "@SUM(A1)", "  =1", "\t=1", "\r=1", "\n=1", "\x00=1"])
def test_formula_protection_applies_to_all_text_fields(value):
    row = export(
        [
            {
                "info": value,
                "Object": [
                    {
                        "name": value,
                        "Attribute": [
                            {"type": "text", "value": value, "comment": value},
                        ],
                    }
                ],
            }
        ]
    )[0]
    for key in ("event_info", "object_name", "value", "comment"):
        assert row[key] == "'" + value


@pytest.mark.parametrize("flag", [True, 1, "1", "true"])
def test_deleted_events_objects_and_attributes_are_excluded(flag):
    attribute = {"type": "text", "value": "keep"}
    assert export([{"deleted": flag, "Attribute": [attribute]}]) == []
    assert export([{"Object": [{"deleted": flag, "Attribute": [attribute]}]}]) == []
    assert export([{"Attribute": [dict(attribute, deleted=flag), attribute]}])[0]["value"] == "keep"


def test_empty_input_still_has_fixed_header():
    response = csv_export.handler('{"data": []}')
    reader = csv.reader(io.StringIO(base64.b64decode(response["data"]).decode()))
    assert next(reader) == list(csv_export.CSV_FIELDS)
    assert list(reader) == []


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"data": {}},
        {"data": [1]},
        {"data": [{"Event": None}]},
        {"data": [{"Attribute": {}}]},
        {"data": [{"Object": [None]}]},
        {"data": [{"Tag": "tag"}]},
    ],
)
def test_invalid_requests_return_errors(payload):
    assert "error" in csv_export.handler(json.dumps(payload))


def test_invalid_json_and_metadata():
    assert csv_export.handler() is False
    assert "error" in csv_export.handler("not json")
    assert csv_export.version()["module-type"] == ["export"]
    assert csv_export.introspection()["outputFileExtension"] == "csv"


def test_website_bundled_exporter_stays_in_sync():
    # The website must work with older locked misp-modules releases. Keep its
    # bundled copy identical so CSV behavior and safety fixes cannot drift.
    root = Path(__file__).resolve().parents[1]
    bundled = (root / "website/app/_csv_export.py").read_text()
    assert bundled.split("\n", 1)[1] == Path(csv_export.__file__).read_text()


class TestCSVExportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous_handlers = service.MODULES_HANDLERS.copy()
        self.previous_cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"csv_export": csv_export, "type:csv_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous_handlers)
        service.ListModules.CACHE = self.previous_cache
        super().tearDown()

    def test_discovery_and_query(self):
        modules = json.loads(self.fetch("/modules").body)
        assert modules[0]["name"] == "csv_export"
        assert modules[0]["mispattributes"]["responseType"] == "text/csv"
        response = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "csv_export", "data": [{"Attribute": [{"type": "text", "value": "hello"}]}]}),
        )
        assert response.code == 200
        result = json.loads(response.body)
        rows = list(csv.DictReader(io.StringIO(base64.b64decode(result["data"]).decode())))
        assert rows[0]["value"] == "hello"
