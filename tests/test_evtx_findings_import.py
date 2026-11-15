"""Native export fixtures, rule/event semantics, provenance and bounded parsing."""

import base64
import copy
import csv
import hashlib
import json
import socket
from io import StringIO
from pathlib import Path

import pytest
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.import_mod import evtx_findings_import as module

FIXTURES = Path(__file__).parent / "fixtures/evtx_findings"


def request(raw, config=None, **kwargs):
    return json.dumps({"data": base64.b64encode(raw).decode(), "config": config, **kwargs})


def imported(filename="hayabusa.jsonl", raw=None, **config):
    raw = (FIXTURES / filename).read_bytes() if raw is None else raw
    result = module.handler(request(raw, config, filename=filename))
    assert "error" not in result, result
    return result


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def fields(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def refs(obj, relationship):
    return [r["referenced_uuid"] for r in obj.get("ObjectReference", []) if r["relationship_type"] == relationship]


def hayabusa():
    return json.loads((FIXTURES / "hayabusa.jsonl").read_text().splitlines()[0])


def chainsaw():
    return json.loads((FIXTURES / "chainsaw.json").read_text())[0]


@pytest.mark.parametrize(
    "filename,tool",
    [
        ("hayabusa.json", "hayabusa"),
        ("hayabusa.jsonl", "hayabusa"),
        ("hayabusa.csv", "hayabusa"),
        ("chainsaw.json", "chainsaw"),
        ("chainsaw.jsonl", "chainsaw"),
        ("chainsaw-sigma.json", "chainsaw"),
    ],
)
def test_native_exports_preserve_rule_event_context_and_source_bytes(filename, tool):
    raw = (FIXTURES / filename).read_bytes()
    result = imported(filename)
    detections = objects(result, "windows-event-log-detection")
    events = objects(result, "windows-event-log-record")
    source = objects(result, "file")[0]
    assert result["summary"]["detections"] == result["summary"]["event_contexts"] == 2
    assert fields(source)["sha256"] == hashlib.sha256(raw).hexdigest()
    attachment = next(a for a in source["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == raw
    assert [fields(e)["record-id"] for e in events] == ["31794", "31799"]
    for detection, event in zip(detections, events):
        values, context = fields(detection), fields(event)
        assert values["tool"] == tool
        assert values["severity"] == ("informational" if tool == "hayabusa" else "info")
        assert values["review-status"] == "unreviewed"
        assert context["computer"] == "DESKTOP-JK4Q86I"
        assert context["event-id"] == "4624"
        assert context["channel"] == "Security"
        assert context["provider"] == "Microsoft-Windows-Security-Auditing"
        assert context["source-evtx"].endswith("security_sample.evtx")
        assert refs(detection, "describes") == [event["uuid"]]
        assert refs(event, "derived-from") == [detection["uuid"]]
        assert not refs(detection, "derived-from")
        if tool == "hayabusa" or filename == "chainsaw-sigma.json":
            assert values["rule-id"] == "6b71bdb7-0874-4b5e-b51e-e8fa032c7871"
        else:
            assert "rule-id" not in values  # Native Chainsaw rules have no Sigma ID.
            assert context["event-level"] == "0"  # Distinct from rule severity.
        assert values["source-sha256"] == fields(source)["sha256"]
    assert set(refs(source, "derived-from")) == {o["uuid"] for o in detections + events}
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])
    assert objects(result, "threat-hunt-finding") == []


def test_chainsaw_aggregate_preserves_per_host_record_scope():
    result = imported("chainsaw-aggregate.json")
    detections = objects(result, "windows-event-log-detection")
    events = objects(result, "windows-event-log-record")
    assert len(detections) == 1 and len(events) == 2
    assert fields(detections[0])["detection-kind"] == "aggregate"
    assert fields(detections[0])["severity"] == "high"
    assert [fields(e)["computer"] for e in events] == ["host-a", "host-b"]
    assert [fields(e)["channel"] for e in events] == ["Security", "System"]
    assert [fields(e)["source-evtx"] for e in events] == ["host-a/Security.evtx", "host-b/System.evtx"]
    assert [fields(e)["record-id"] for e in events] == ["7", "7"]
    assert events[0]["uuid"] != events[1]["uuid"]
    assert set(refs(detections[0], "describes")) == {event["uuid"] for event in events}
    for event in events:
        assert refs(event, "derived-from") == [detections[0]["uuid"]]


@pytest.mark.parametrize("kind", ["cached", "individual"])
def test_cached_and_missing_event_system_are_retained(kind):
    row = chainsaw()
    row["kind"] = kind
    row["document"]["data"] = None
    result = imported(raw=json.dumps(row).encode())
    context = fields(objects(result, "windows-event-log-record")[0])
    assert context["source-evtx"] == "security_sample.evtx"
    assert "record-id" not in context
    assert json.loads(context["raw-event"])["data"] is None
    assert result["warnings"]


def test_non_evtx_chainsaw_document_is_not_misrepresented_as_event():
    row = chainsaw()
    row["document"]["kind"] = "hve"
    result = imported(raw=json.dumps(row).encode())
    assert len(objects(result, "windows-event-log-detection")) == 1
    assert objects(result, "windows-event-log-record") == []
    assert any("Non-EVTX" in warning for warning in result["warnings"])


def test_rule_status_and_input_verdict_do_not_confirm_malicious_activity():
    row = hayabusa()
    row["Status"] = "stable"
    row["review-status"] = "confirmed-malicious"
    row["verdict"] = "malicious"
    result = imported(raw=json.dumps(row).encode())
    finding = fields(objects(result, "windows-event-log-detection")[0])
    assert finding["review-status"] == "unreviewed"
    assert finding["rule-status"] == "stable"
    assert json.loads(finding["raw-result"])["verdict"] == "malicious"
    assert "outcome" not in finding and "verdict" not in finding


def test_minimal_profile_missing_context_and_explicit_evtx_default():
    row = {"RuleTitle": "Test", "Level": "med ", "Computer": "example", "EventID": 1, "RecordID": 2}
    result = imported(raw=json.dumps(row).encode(), source_evtx="evidence/Security.evtx", tool_version="4.4.0")
    finding = fields(objects(result, "windows-event-log-detection")[0])
    event = fields(objects(result, "windows-event-log-record")[0])
    assert finding["severity"] == "med"  # PyMISP strips surrounding scalar whitespace.
    assert json.loads(finding["raw-result"])["Level"] == "med "
    assert finding["tool-version"] == "4.4.0"
    assert "rule-id" not in finding
    assert event["source-evtx"] == "evidence/Security.evtx"
    assert "provider" not in event
    assert any("rule ID" in warning for warning in result["warnings"])
    row["EvtxFile"] = "reported.evtx"
    result = imported(raw=json.dumps(row).encode(), source_evtx="fallback.evtx")
    assert fields(objects(result, "windows-event-log-record")[0])["source-evtx"] == "reported.evtx"


def test_timesketch_profile_and_multiline_csv():
    row = hayabusa()
    row["datetime"] = row.pop("Timestamp")
    row["message"] = row.pop("RuleTitle")
    row["timestamp_desc"] = "hayabusa"
    row["Details"] = 'Quoted "command", field\nsecond line'
    stream = StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=row)
    writer.writeheader()
    writer.writerow(row)
    result = imported(raw=stream.getvalue().encode(), format="csv")
    detection = fields(objects(result, "windows-event-log-detection")[0])
    assert detection["rule-title"] == row["message"]
    assert json.loads(detection["raw-result"])["Details"] == row["Details"]


@pytest.mark.parametrize("value", ["2026-11-15 10:00:00.123 +01:00", "2026-11-15T09:00:00.123Z"])
def test_known_timezone_formats_are_normalized(value):
    row = hayabusa()
    row["Timestamp"] = value
    result = imported(raw=json.dumps(row).encode())
    detection = fields(objects(result, "windows-event-log-detection")[0])
    event = fields(objects(result, "windows-event-log-record")[0])
    assert detection["detection-time"] == event["event-time"] == "2026-11-15T09:00:00.123000+00:00"
    assert detection["timestamp-raw"] == event["timestamp-raw"] == value


@pytest.mark.parametrize(
    "value",
    [
        "2026-11-15T09:00:00.123456789Z",
        "2026-11-15 09:00:00",
        "2026-11-15T09:00:00-00:00",
        "2026-11-15T09:00:00+00:99",
        "2026-02-30T09:00:00Z",
        1794733200,
    ],
)
def test_high_precision_or_ambiguous_times_remain_raw(value):
    row = hayabusa()
    row["Timestamp"] = value
    result = imported(raw=json.dumps(row).encode())
    detection = fields(objects(result, "windows-event-log-detection")[0])
    event = fields(objects(result, "windows-event-log-record")[0])
    assert "detection-time" not in detection and "event-time" not in event
    assert detection["timestamp-raw"] == str(value)
    assert result["warnings"]


def test_event_identifier_bounds_zeroes_and_precision():
    row = hayabusa()
    row["EventID"], row["RecordID"] = 0, 2**64 - 1
    result = imported(raw=json.dumps(row).encode())
    event = fields(objects(result, "windows-event-log-record")[0])
    assert event["event-id"] == "0" and event["record-id"] == str(2**64 - 1)
    row["EventID"], row["RecordID"] = 65536, True
    result = imported(raw=json.dumps(row).encode())
    event = fields(objects(result, "windows-event-log-record")[0])
    assert "event-id" not in event and "record-id" not in event
    assert result["warnings"]


def test_ids_and_references_are_repeatable_but_occurrences_stay_distinct():
    assert imported() == imported()
    row = hayabusa()
    result = imported(raw=json.dumps([row, row]).encode())
    detections = objects(result, "windows-event-log-detection")
    events = objects(result, "windows-event-log-record")
    assert detections[0]["uuid"] != detections[1]["uuid"]
    assert events[0]["uuid"] != events[1]["uuid"]


def test_explicit_json_rejects_streams_and_jsonl_rejects_pretty_objects():
    raw = (FIXTURES / "hayabusa.json").read_bytes()
    for format_ in ("json", "jsonl"):
        result = module.handler(request(raw, {"format": format_}))
        assert "error" in result and "results" not in result
    assert imported(raw=raw, format="hayabusa-json")["summary"]["detections"] == 2
    assert imported(raw=json.dumps([hayabusa()]).encode(), format="json")["summary"]["detections"] == 1


@pytest.mark.parametrize("format_", ["auto", "jsonl"])
def test_unicode_line_separators_inside_json_strings_are_not_record_delimiters(format_):
    row = hayabusa()
    row["Details"] = "line one\u2028line two\u0085line three"
    raw = ((json.dumps(row, ensure_ascii=False) + "\n") * 2).encode()
    result = imported(raw=raw, format=format_)
    assert result["summary"]["detections"] == 2
    assert result["summary"]["format"] == "jsonl"
    finding = fields(objects(result, "windows-event-log-detection")[0])
    assert json.loads(finding["raw-result"])["Details"] == row["Details"]


def test_explicit_tool_and_native_stream_contracts():
    for filename, config in [
        ("hayabusa.jsonl", {"tool": "chainsaw"}),
        ("chainsaw.json", {"tool": "hayabusa"}),
        ("chainsaw.json", {"format": "hayabusa-json"}),
        ("hayabusa.csv", {"format": "hayabusa-json"}),
    ]:
        assert "error" in module.handler(request((FIXTURES / filename).read_bytes(), config))


def test_pymisp_templates_validate_and_http_independent_no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Importer must not use the network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    result = imported("chainsaw-aggregate.json")
    event = MISPEvent()
    event.from_dict(info="EVTX findings", **copy.deepcopy(result["results"]))
    for obj in event.objects:
        if obj.name.startswith("windows-event-log-"):
            obj._definition = module._template(obj.name)
        assert obj._validate()
    assert json.loads(event.to_json())["Object"]


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b"{}",
        b"null",
        b"[1]",
        b'{"RuleTitle":"x","RuleTitle":"y","Level":"low"}',
        b'{"RuleTitle":"x","Level":NaN}',
        b'{"RuleTitle":"x","Level":"low"}\ngarbage',
        b'{"RuleTitle":"x","Level":"low","x":Infinity}',
        b'RuleTitle,Level\n"unclosed,low',
        b"RuleTitle,RuleTitle\nx,y",
        b"RuleTitle,Level\nx,low,extra",
        b"RuleTitle,Level\nx",
        b"\xff",
        rb'{"RuleTitle":"\ud800","Level":"low"}',
    ],
)
def test_bad_exports_reject_without_partial_results(raw):
    result = module.handler(request(raw))
    assert "error" in result and "results" not in result


@pytest.mark.parametrize(
    "config",
    [
        [],
        False,
        {"tool": "other"},
        {"tool": []},
        {"format": "xml"},
        {"format": []},
        {"source_evtx": 1},
        {"tool_version": "x\n"},
    ],
)
def test_invalid_configuration(config):
    assert "error" in module.handler(request(json.dumps(hayabusa()).encode(), config))


@pytest.mark.parametrize("envelope", ["{", "[]", "null", "{}", '{"data":123}', '{"data":"%%%"}'])
def test_invalid_envelope(envelope):
    assert "error" in module.handler(envelope)


@pytest.mark.parametrize("change", [{"documents": None}, {"documents": []}, {"documents": [None]}])
def test_invalid_aggregate_rejects_atomically(change):
    row = json.loads((FIXTURES / "chainsaw-aggregate.json").read_text())[0]
    row.update(change)
    result = module.handler(request(json.dumps([hayabusa(), row]).encode()))
    assert "error" in result and "results" not in result


def test_resource_limits(monkeypatch):
    monkeypatch.setattr(module, "MAX_RESULTS", 1)
    for name in ("hayabusa.json", "hayabusa.jsonl", "hayabusa.csv", "chainsaw.json"):
        assert "error" in module.handler(request((FIXTURES / name).read_bytes()))
    monkeypatch.setattr(module, "MAX_EVENTS", 1)
    assert "error" in module.handler(request((FIXTURES / "chainsaw-aggregate.json").read_bytes()))
    monkeypatch.setattr(module, "MAX_RESULT", 10)
    assert "error" in module.handler(request(json.dumps(hayabusa()).encode()))
    monkeypatch.setattr(module, "MAX_INPUT", 10)
    assert "error" in module.handler(request(json.dumps(hayabusa()).encode()))


def test_nesting_and_unicode_key_limits():
    row = hayabusa()
    nested = 1
    for _ in range(33):
        nested = [nested]
    row["nested"] = nested
    assert "error" in module.handler(request(json.dumps(row).encode()))
    assert "error" in module.handler(request(rb'{"RuleTitle":"x","Level":"low","\ud800":1}'))


def test_bom_filename_and_unknown_extensions_preserved():
    row = hayabusa()
    row["Custom"] = {"list": [1, True, "text"]}
    raw = b"\xef\xbb\xbf" + json.dumps(row).encode()
    result = imported(filename="C:\\uploads\\findings.json", raw=raw)
    assert fields(objects(result, "file")[0])["filename"] == "findings.json"
    assert (
        json.loads(fields(objects(result, "windows-event-log-detection")[0])["raw-result"])["Custom"] == row["Custom"]
    )


class TestEVTXFindingsHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"evtx_findings_import": module, "type:evtx_findings_import": "import_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_import_and_errors(self):
        modules = json.loads(self.fetch("/modules").body)
        assert modules[0]["name"] == "evtx_findings_import"
        assert modules[0]["mispattributes"]["format"] == "misp_standard"
        assert module.handler() is False
        response = self.fetch(
            "/query",
            method="POST",
            body=request((FIXTURES / "hayabusa.csv").read_bytes(), {}, module="evtx_findings_import"),
        )
        assert response.code == 200 and len(objects(json.loads(response.body), "windows-event-log-detection")) == 2
        response = self.fetch(
            "/query", method="POST", body=json.dumps({"module": "evtx_findings_import", "data": "%%%"})
        )
        assert response.code == 200 and "error" in json.loads(response.body)
