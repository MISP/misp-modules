import base64
import copy
import csv
import hashlib
import json
import socket
from io import StringIO
from pathlib import Path

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.lib import timesketch_exchange as exchange
from misp_modules.modules.export_mod import timesketch_export as exporter
from misp_modules.modules.import_mod import timesketch_import as importer

FIXTURES = Path(__file__).parent / "fixtures/timesketch"
DATE = "2026-10-10T12:00:00.123456Z"
STAMP = 1791633600123456


def request(raw, config=None, **kwargs):
    return json.dumps({"data": base64.b64encode(raw).decode(), "config": config, **kwargs})


def imported(raw=None, filename="timesketch-api.json", **config):
    raw = (FIXTURES / filename).read_bytes() if raw is None else raw
    result = importer.handler(request(raw, config, filename=filename))
    assert "error" not in result, result
    return result


def objects(result, name="timesketch-timeline"):
    return [o for o in result["results"]["Object"] if o["name"] == name]


def fields(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def row(**kwargs):
    return {
        "datetime": DATE,
        "timestamp": STAMP,
        "timestamp_desc": "File Modification Time",
        "message": "Example",
        **kwargs,
    }


def timeline(name="timesketch-timeline", **kwargs):
    values = {"datetime": DATE, "message": "An observation", "timestamp_desc": "File Modification Time", **kwargs}
    return {
        "name": name,
        "uuid": "object-1",
        "Attribute": [
            {"type": "datetime" if k == "datetime" else "text", "value": v, "object_relation": k, "uuid": f"attr-{k}"}
            for k, v in values.items()
        ],
    }


def event(objects_=None, attributes=None, **kwargs):
    return {"uuid": "event-uuid", "id": "42", "Object": objects_ or [], "Attribute": attributes or [], **kwargs}


def exported(data, config=None):
    result = exporter.handler(json.dumps({"data": data, "config": config}))
    assert "error" not in result, result
    rows = [json.loads(line) for line in base64.b64decode(result["data"]).decode().split("\n") if line]
    return result, rows


def annotation_csv(value):
    stream = StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=[*row(), "tag"])
    writer.writeheader()
    writer.writerow(row(tag="['valid']"))
    writer.writerow(row(tag=value))
    return stream.getvalue().encode()


def test_explore_metadata_is_preserved_without_redundant_configuration():
    response = json.loads((FIXTURES / "timesketch-api.json").read_text())
    response["meta"].update(
        timeline_id=12, source_url="https://timesketch.example/sketch/7", unrelated="excluded context"
    )
    result = imported(raw=json.dumps(response).encode(), selection="annotated")
    value = fields(objects(result)[0])
    assert value["sketch-id"] == "7" and value["timeline-id"] == "12"
    assert value["source-url"] == "https://timesketch.example/sketch/7"
    assert "attachment" not in fields(objects(result, "file")[0])
    assert "excluded context" not in json.dumps(result)
    assert json.loads(value["raw-event"]) == response["objects"][0]


def test_entry_then_response_metadata_then_config_provenance_precedence():
    response = json.loads((FIXTURES / "timesketch-api.json").read_text())
    response["meta"]["timeline_id"] = "response-timeline"
    response["objects"][0]["_source"]["sketch_id"] = "entry-sketch"
    response["objects"].append({"_source": row()})
    result = imported(
        raw=json.dumps(response).encode(),
        sketch_id="config-sketch",
        timeline_id="config-timeline",
        source_url="https://misp.example/reference",
    )
    values = [fields(obj) for obj in objects(result)]
    assert values[0]["sketch-id"] == "entry-sketch"
    assert values[1]["sketch-id"] == values[2]["sketch-id"] == "7"
    assert values[0]["timeline-id"] == "12" and values[2]["timeline-id"] == "response-timeline"
    assert all(value["source-url"] == "https://misp.example/reference" for value in values)


@pytest.mark.parametrize("meta", [None, [], "invalid", {"sketch_id": []}, {"timeline_id": True}, {"source_url": {}}])
def test_invalid_explore_metadata_returns_an_atomic_error(meta):
    result = importer.handler(request(json.dumps({"meta": meta, "objects": [row()]}).encode()))
    assert "error" in result and "results" not in result


@pytest.mark.parametrize(
    "value", ["{1: 2}", "{True: 'label'}", "{None: 'label'}", "{(1, 2): 'label'}", "{'nested': [{1: 'label'}]}"]
)
def test_csv_annotation_non_string_keys_return_an_atomic_error(value):
    result = importer.handler(request(annotation_csv(value)))
    assert "dictionary keys must be strings" in result["error"]
    assert "results" not in result


def test_parsed_annotation_depth_errors_cannot_fall_back_to_unvalidated_text():
    annotation = "{'nested': " + "[" * 33 + "'label'" + "]" * 33 + "}"
    result = importer.handler(request(annotation_csv(annotation)))
    assert "nesting exceeds" in result["error"] and "results" not in result


@pytest.mark.parametrize(
    "filename,unit",
    [
        ("timesketch-api.json", None),
        ("timesketch-cli.csv", None),
        ("timesketch-cli.json", "ms"),
        ("timesketch-cli.jsonl", "ms"),
    ],
)
def test_upstream_cli_and_api_exports_preserve_precision_and_context(filename, unit):
    raw = (FIXTURES / filename).read_bytes()
    result = imported(filename=filename, datetime_unit=unit, sketch_id="7", timeline_id="12")
    entries = objects(result)
    assert len(entries) == 2
    first = fields(entries[0])
    assert first["datetime"] == "2026-10-10T12:00:00.123456+00:00"
    assert first["timestamp"] == str(STAMP)
    assert first["event-id"] == "event-1" and first["source-index"] == "source-index"
    assert first["sketch-id"] == "7" and first["timeline-id"] == "12"
    assert json.loads(first["source-labels"]) == ["__ts_star"]
    assert json.loads(first["source-comments"])[0]["user"] == "analyst"
    assert first["source-sha256"] == hashlib.sha256(raw).hexdigest()
    if filename != "timesketch-api.json":
        assert first["timeline-name"] == "Evidence timeline"
    source = objects(result, "file")[0]
    assert base64.b64decode(next(a["data"] for a in source["Attribute"] if a["object_relation"] == "attachment")) == raw
    assert {r["referenced_uuid"] for r in source["ObjectReference"] if r["relationship_type"] == "derived-from"} == {
        o["uuid"] for o in entries
    }
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])
    assert not result["warnings"]


def test_plaso_preserves_dfvfs_parent_evidence_and_tag_context_without_verdict():
    result = imported(filename="plaso.jsonl", selection="annotated")
    values = fields(objects(result)[0])
    assert values["datetime"] == "2012-06-27T18:17:01+00:00"
    assert json.loads(values["pathspec"])["parent"]["location"] == "/cases/image.dd"
    assert json.loads(values["source-tags"])["labels"] == ["Malware", "Printed"]
    assert values["parser"] == "test" and values["data-type"] == "test:event"
    assert "verdict" not in values and "Tag" not in objects(result)[0]
    assert json.loads(values["raw-event"])["hostname"] == "ubuntu"


@pytest.mark.parametrize("selection,expected", [("selected", "event-2"), ("annotated", "event-1")])
def test_selection_excludes_other_rows_and_omits_original_attachment(selection, expected):
    result = imported(selection=selection)
    assert result["summary"]["excluded"] == result["summary"]["imported"] == 1
    assert fields(objects(result)[0])["event-id"] == expected
    assert "attachment" not in fields(objects(result, "file")[0])
    excluded = "Selected example" if selection == "annotated" else "Example file changed"
    assert excluded not in json.dumps(result)
    assert result["warnings"]


def test_plaso_empty_eventtag_metadata_is_not_an_annotation():
    value = row(tag={"__type__": "AttributeContainer", "labels": []})
    assert "error" in importer.handler(request(json.dumps(value).encode(), {"selection": "annotated"}))


@pytest.mark.parametrize(
    "date,timestamp,unit,expected",
    [
        ("1970-01-01T00:00:00Z", 0, None, "1970-01-01T00:00:00+00:00"),
        ("1969-12-31T23:59:59.999999Z", -1, None, "1969-12-31T23:59:59.999999+00:00"),
        ("2026-10-10T14:00:00.123456+02:00", STAMP, None, "2026-10-10T12:00:00.123456+00:00"),
        ("2026-10-10T12:00:00.123456+0000", STAMP, None, "2026-10-10T12:00:00.123456+00:00"),
        ("2026-10-10T17:30:00.123456+0530", STAMP, None, "2026-10-10T12:00:00.123456+00:00"),
        ("2026-10-10T08:30:00.123456-0330", STAMP, None, "2026-10-10T12:00:00.123456+00:00"),
        (1791633600123, STAMP, "ms", "2026-10-10T12:00:00.123456+00:00"),
        (str(STAMP * 1000), STAMP, "ns", "2026-10-10T12:00:00.123456+00:00"),
    ],
)
def test_known_timestamps_are_exact(date, timestamp, unit, expected):
    result = imported(raw=json.dumps(row(datetime=date, timestamp=timestamp)).encode(), datetime_unit=unit)
    assert fields(objects(result)[0])["datetime"] == expected


@pytest.mark.parametrize(
    "date,timestamp,unit",
    [
        (1791633600123, STAMP, None),
        (DATE, STAMP + 1, None),
        ("2026-10-10T12:00:00", STAMP, None),
        ("2026-10-10T12:00:00-00:00", STAMP, None),
        ("2026-10-10T12:00:00-0000", STAMP, None),
        ("2026-10-10T12:00:00+2400", STAMP, None),
        ("2026-10-10T12:00:00+0060", STAMP, None),
        ("2026-10-10T12:00:00+00:60", STAMP, None),
        ("2026-10-10T12:00:00+000", STAMP, None),
        ("2026-10-10T12:00:00.1234567+0000", STAMP, None),
        ("2026-10-10T12:00:00.1234567Z", STAMP, None),
        (str(STAMP * 1000 + 1), STAMP, "ns"),
        (1.5, STAMP, "s"),
        (True, STAMP, "s"),
        (DATE, 1e30, None),
    ],
)
def test_ambiguous_or_conflicting_times_are_retained_without_normalization(date, timestamp, unit):
    result = imported(raw=json.dumps(row(datetime=date, timestamp=timestamp)).encode(), datetime_unit=unit)
    value = fields(objects(result)[0])
    assert "datetime" not in value and "datetime-raw" in value
    assert json.loads(value["raw-event"])["datetime"] == date
    assert result["warnings"]
    assert "error" in exporter.handler(json.dumps({"data": result["results"]}))


def test_roundtrip_keeps_source_references_and_annotations_as_namespaced_snapshots():
    original = imported(sketch_id="7", source_url="https://timesketch.example/sketch/7")
    result, rows = exported(
        event(original["results"]["Object"], Tag=[{"name": "tlp:amber"}], distribution="0"),
        {"misp_url": "https://misp.example"},
    )
    first = rows[0]
    assert first["datetime"] == DATE and first["timestamp"] == STAMP
    assert first["misp_source_event_id"] == "event-1" and first["misp_source_timeline_id"] == "12"
    assert first["misp_source_parser"] == "filestat"
    assert first["misp_source_url"] == "https://timesketch.example/sketch/7"
    assert first["misp_source_export_sha256"] == original["summary"]["source_sha256"]
    assert (
        first["misp_tags"] == ["tlp:amber"] and first["misp_event_url"] == "https://misp.example/events/view/event-uuid"
    )
    assert first["misp_distribution"]["event"] == {"distribution": "0"}
    assert not {
        "_id",
        "_index",
        "__ts_timeline_id",
        "timesketch_label",
        "tag",
        "label",
        "comment",
        "raw-event",
        "data",
    }.intersection(first)
    again = imported(raw=base64.b64decode(result["data"]))
    values = fields(objects(again)[0])
    for key in (
        "event-id",
        "timeline-id",
        "source-index",
        "parser",
        "data-type",
        "source-comments",
        "source-labels",
        "source-tags",
        "datetime",
    ):
        assert values[key] == fields(objects(original)[0])[key]


def test_existing_both_timesketch_templates_and_wrapped_event_layouts():
    modern, old = timeline(), timeline(name="timesketch_message")
    old["Attribute"] = [a for a in old["Attribute"] if a["object_relation"] != "timestamp_desc"]
    for data in [
        event([modern, old]),
        {"Event": event([modern, old])},
        {"Event": {"uuid": "event-uuid"}, "Object": [modern, old]},
    ]:
        _, rows = exported(data)
        assert len(rows) == 2 and rows[1]["timestamp_desc"] == "Timesketch message"


@pytest.mark.parametrize(
    "name,relation", [(name, relation) for name, relations in exchange.OBJECT_TIMES.items() for relation in relations]
)
def test_supported_forensic_object_timestamps_use_observation_relations(name, relation):
    obj = {
        "name": name,
        "uuid": "object-1",
        "Attribute": [{"object_relation": relation, "value": DATE, "uuid": "attribute-1", "type": "datetime"}],
    }
    _, rows = exported(event([obj]))
    assert rows[0]["timestamp_desc"] == rows[0]["misp_object_relation"] == relation
    assert rows[0]["misp_attribute_uuid"] == "attribute-1"


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-10T12:00:00.123456+0000",
        "2026-10-10T17:30:00.123456+0530",
        "2026-10-10T08:30:00.123456-0330",
    ],
)
def test_saved_misp_compact_offsets_export_exact_observation_times(value):
    obj = {
        "name": "windows-event-log-record",
        "uuid": "record-uuid",
        "Attribute": [{"object_relation": "event-time", "type": "datetime", "value": value}],
    }
    original = copy.deepcopy(obj)
    result, rows = exported({"Event": event([obj])})
    assert len(rows) == 1 and rows[0]["datetime"] == DATE
    assert rows[0]["timestamp"] == STAMP
    assert rows[0]["misp_object_uuid"] == "record-uuid"
    assert rows[0]["timestamp_desc"] == "event-time"
    assert result["summary"]["skipped"] == {}
    assert obj == original


@pytest.mark.parametrize("offset", ["-0000", "-00:00", "+2400", "+0060", "+00:60", "+000", ""])
def test_export_does_not_guess_unknown_missing_or_invalid_offsets(offset):
    result = exporter.handler(json.dumps({"data": event([timeline(datetime="2026-10-10T12:00:00" + offset)])}))
    assert result["error"] == "No supported timestamped observations selected."
    assert sum(result["summary"]["skipped"].values()) == 1


def test_first_last_seen_are_observations_even_without_to_ids_and_event_metadata_is_ignored():
    attr = {
        "type": "domain",
        "value": "example.org",
        "uuid": "attr-1",
        "to_ids": False,
        "first_seen": DATE,
        "last_seen": "1791633601",
    }
    _, rows = exported(
        event(attributes=[attr], date="2026-10-10", timestamp="1791633600", publish_timestamp="1791633600")
    )
    assert len(rows) == 2 and {r["timestamp_desc"] for r in rows} == {"first_seen", "last_seen"}
    assert rows[1]["timestamp"] == 1791633601000000
    assert "error" in exporter.handler(
        json.dumps({"data": event(attributes=[{"type": "datetime", "value": DATE}], timestamp="1791633600")})
    )


@pytest.mark.parametrize(
    "value,deleted", [(False, False), ("false", False), ("0", False), (True, True), ("true", True), ("1", True)]
)
@pytest.mark.parametrize("scope", ["event", "envelope", "object", "attribute"])
def test_deleted_flags_are_parsed_at_every_scope(value, deleted, scope):
    obj = timeline()
    data = {"Event": event([obj])}
    target = {"event": data["Event"], "envelope": data, "object": obj, "attribute": obj["Attribute"][0]}[scope]
    target["deleted"] = value
    result = exporter.handler(json.dumps({"data": data}))
    assert ("error" in result) is deleted


def test_ambiguous_repeated_time_relation_is_skipped_and_reported():
    obj = timeline()
    obj["Attribute"].append({"object_relation": "datetime", "value": "2026-10-11T00:00:00Z"})
    result = exporter.handler(json.dumps({"data": event([obj])}))
    assert "error" in result and any("Ambiguous" in reason for reason in result["summary"]["skipped"])


def test_forensic_source_references_survive_without_attachments_or_unmapped_raw_content():
    obj = {
        "name": "windows-event-log-record",
        "uuid": "event-record-uuid",
        "Attribute": [
            {"object_relation": k, "value": v}
            for k, v in {
                "event-time": DATE,
                "source-evtx": "host/Security.evtx",
                "record-id": "23",
                "event-id": "4624",
                "raw-event": "private-unmapped-details",
                "attachment": "source.evtx",
            }.items()
        ],
        "ObjectReference": [
            {"referenced_uuid": "source-uuid", "relationship_type": "derived-from", "data": "binary-secret"}
        ],
    }
    obj["Attribute"][-1]["data"] = "binary-secret"
    _, rows = exported(event([obj]))
    assert rows[0]["misp_context"]["source-evtx"] == ["host/Security.evtx"]
    assert rows[0]["misp_context"]["record-id"] == ["23"]
    assert rows[0]["misp_object_references"] == [
        {"referenced_uuid": "source-uuid", "relationship_type": "derived-from"}
    ]
    assert "binary-secret" not in json.dumps(rows) and "private-unmapped-details" not in json.dumps(rows)


@pytest.mark.parametrize(
    "raw,config",
    [
        (b'{"message":"x","message":"y","timestamp":0}', {}),
        (b'{"message":"x","timestamp":NaN}', {}),
        (b"[]", {}),
        (b"message,timestamp,timestamp\nx,0,0\n", {}),
        (b"message,timestamp\nx,0,extra\n", {}),
        (b'{"message":"x","timestamp":0}\n{"message":"y","timestamp":1}', {"format": "json"}),
        (b'{"message":"x","timestamp":0}', {"format": False}),
        (b'{"message":"x","timestamp":0}', {"selection": []}),
        (b'{"message":"x","timestamp":0}', {"datetime_unit": False}),
        (json.dumps(row(selected="yes")).encode(), {}),
        (json.dumps(row(_id="one", misp_source_event_id="two")).encode(), {}),
    ],
)
def test_malformed_imports_fail_atomically(raw, config):
    result = importer.handler(request(raw, config))
    assert "error" in result and "results" not in result


def test_bounds_non_utf8_and_invalid_requests(monkeypatch):
    raw = json.dumps([row()] * 1001).encode()
    assert "error" in importer.handler(request(raw))
    for query in ["[]", "null", "{}", json.dumps({"data": "%%%"}), request(b"\xff")]:
        assert "error" in importer.handler(query)
    monkeypatch.setattr(exchange, "MAX_ROW", 50)
    assert "error" in importer.handler(request(json.dumps(row()).encode()))
    monkeypatch.setattr(exchange, "MAX_EXPORT", 1)
    assert "error" in exporter.handler(json.dumps({"data": event([timeline(), timeline()])}))


@pytest.mark.parametrize(
    "url", [False, [], 1, "ftp://example.org", "https://user:password@example.org", "https://example.org?token=1"]
)
def test_export_rejects_invalid_configuration(url):
    assert "error" in exporter.handler(json.dumps({"data": event([timeline()]), "config": {"misp_url": url}}))


def test_no_network_templates_validate_and_identity_is_repeatable(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Module must not access the network")

    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(socket.socket, "connect", fail)
    first, second = imported(source_url="https://unreachable.example"), imported(
        source_url="https://unreachable.example"
    )
    assert first == second
    for obj in objects(first):
        parsed = MISPObject("timesketch-timeline", strict=True, misp_objects_template_custom=exchange.template())
        parsed.from_dict(**copy.deepcopy(obj))
        assert parsed.to_json(strict=True)
    assert exported(event(first["results"]["Object"])) == exported(event(first["results"]["Object"]))


class TestTimesketchHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {
                "timesketch_import": importer,
                "type:timesketch_import": "import_mod",
                "timesketch_export": exporter,
                "type:timesketch_export": "export_mod",
            }
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_both_handlers(self):
        modules = {m["name"]: m for m in json.loads(self.fetch("/modules").body)}
        assert modules["timesketch_import"]["mispattributes"]["format"] == "misp_standard"
        assert modules["timesketch_export"]["mispattributes"]["outputFileExtension"] == "jsonl"
        assert importer.handler() is exporter.handler() is False
        response = self.fetch(
            "/query",
            method="POST",
            body=request((FIXTURES / "timesketch-api.json").read_bytes(), module="timesketch_import"),
        )
        assert response.code == 200
        imported_data = json.loads(response.body)["results"]
        assert all(
            fields(obj)["sketch-id"] == "7" for obj in imported_data["Object"] if obj["name"] == "timesketch-timeline"
        )
        response = self.fetch(
            "/query", method="POST", body=json.dumps({"module": "timesketch_export", "data": imported_data})
        )
        assert response.code == 200 and json.loads(response.body)["summary"]["observations"] == 2

    def test_invalid_csv_annotations_return_module_errors_instead_of_http_500(self):
        for value in ("{1: 2}", "{'nested': [{False: 'label'}]}"):
            response = self.fetch(
                "/query", method="POST", body=request(annotation_csv(value), module="timesketch_import")
            )
            assert response.code == 200
            result = json.loads(response.body)
            assert "dictionary keys must be strings" in result["error"]
            assert "results" not in result
