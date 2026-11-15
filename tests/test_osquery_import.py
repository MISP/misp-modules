import base64
import copy
import hashlib
import json
import socket
from pathlib import Path

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import osqueryexport
from misp_modules.modules.import_mod import osquery_import as module

FIXTURES = Path(__file__).parent / "fixtures/osquery"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())
SOURCES = json.loads((FIXTURES / "sources.json").read_text())
NATIVE = sorted(p.name for p in FIXTURES.glob("*.jsonl"))


def request(raw, config=None, **kwargs):
    return json.dumps({"data": base64.b64encode(raw).decode(), "config": config, **kwargs})


def imported(filename="event.jsonl", raw=None, config=None):
    raw = (FIXTURES / filename).read_bytes() if raw is None else raw
    config = {"pack_name": MANIFEST["pack_name"], "sources": SOURCES} if config is None else config
    result = module.handler(request(raw, config, filename=filename))
    assert "error" not in result, result
    return result


def objects(result, name="osquery-result"):
    return [o for o in result["results"]["Object"] if o["name"] == name]


def fields(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def event(**kwargs):
    return {
        "name": "example",
        "hostIdentifier": "host-uuid-not-a-hostname",
        "unixTime": 0,
        "calendarTime": "Thu Jan  1 00:00:00 1970 UTC",
        "action": "added",
        "columns": {"value": "example"},
        **kwargs,
    }


@pytest.mark.parametrize("filename", NATIVE)
def test_actual_osquery_daemon_logs_preserve_provenance_actions_and_bytes(filename):
    raw = (FIXTURES / filename).read_bytes()
    native = [json.loads(line) for line in raw.decode().splitlines() if line]
    result = imported(filename)
    assert result["summary"]["records"] == len(native)
    assert len(objects(result)) == result["summary"]["rows"] + result["summary"]["empty_results"]
    source = objects(result, "file")[0]
    assert fields(source)["sha256"] == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(next(a["data"] for a in source["Attribute"] if a["object_relation"] == "attachment")) == raw
    assert {r["referenced_uuid"] for r in source["ObjectReference"]} == {o["uuid"] for o in objects(result)}
    assert all(r["relationship_type"] == "derived-from" for r in source["ObjectReference"])
    for obj in objects(result):
        values = fields(obj)
        assert values["host-identifier"] == "fixture-host" and values["pack-name"] == MANIFEST["pack_name"]
        assert values["review-status"] == "unreviewed"
        assert values["scheduled-name"].startswith("pack_" + MANIFEST["pack_name"] + "_")
        assert values["execution-time"].endswith("+00:00") and "calendar-time" in values
        assert values["epoch"] == "314159265" and "counter" in values and "numerics" in values
        assert values["source-sha256"] == fields(source)["sha256"]
        if values["query-name"] == MANIFEST["query_name"]:
            assert json.loads(values["source-indicators"]) == SOURCES[MANIFEST["query_name"]]
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])
    assert not result["warnings"]


def test_export_to_native_results_return_path_preserves_original_indicator_references():
    exported = osqueryexport.handler(json.dumps({"data": [MANIFEST["event"]], "config": {"interval": 1}}))
    assert "error" not in exported
    assert exported["sources"] == SOURCES
    pack = json.loads(base64.b64decode(exported["data"]))
    assert MANIFEST["query_name"] in pack["queries"]
    native = [json.loads(line) for line in (FIXTURES / "event.jsonl").read_text().splitlines()]
    wrapper = {"results": native, "sources": exported["sources"]}
    result = imported(raw=json.dumps(wrapper).encode(), config={})
    for obj in objects(result):
        values = fields(obj)
        assert values["query-name"] == MANIFEST["query_name"]
        assert values["pack-name"] == MANIFEST["pack_name"]
        assert json.loads(values["source-indicators"])[0]["attribute"] == MANIFEST["event"]["Attribute"][0]["uuid"]
    assert not result["warnings"]


def test_empty_snapshots_and_batches_are_execution_context_not_matched_rows():
    result = imported("event-snapshots.jsonl")
    empty = [fields(o) for o in objects(result) if fields(o)["record-type"] == "empty-result"]
    assert empty and result["summary"]["empty_results"] == len(empty)
    assert all(
        v["row-action"] == "snapshot" and v["row-count"] == "0" and "row" not in v and "row-index" not in v
        for v in empty
    )
    batch = event()
    batch.pop("columns")
    batch.pop("action")
    batch["diffResults"] = {"added": [], "removed": []}
    result = imported(raw=json.dumps(batch).encode(), config={})
    values = fields(objects(result)[0])
    assert values["record-type"] == "empty-result" and "row-action" not in values and "row" not in values
    assert result["summary"]["rows"] == 0


def test_added_removed_actions_do_not_modify_or_confirm_source_indicators():
    for filename in ("event.jsonl", "batch.jsonl"):
        result = imported(filename)
        assert {fields(o)["row-action"] for o in objects(result)} == {"added", "removed"}
        assert all(fields(o)["result-kind"] == "differential" for o in objects(result))
        assert all(not o.get("deleted") for o in result["results"]["Object"])
        assert not objects(result, "threat-hunt-finding") and "Attribute" not in result["results"]
        assert all(fields(o)["review-status"] == "unreviewed" for o in objects(result))


def test_ad_hoc_snapshot_requires_context_and_keeps_column_types_without_identity_guessing():
    raw = (FIXTURES / "adhoc.json").read_bytes()
    config = {
        "input_type": "snapshot",
        "host_identifier": "uuid:host",
        "query_name": "adhoc",
        "executed_at": "2026-11-15T12:00:00.123456Z",
    }
    result = imported(raw=raw, config=config)
    value = fields(objects(result)[0])
    assert value["row-action"] == "snapshot" and value["host-identifier"] == "uuid:host"
    assert value["execution-time"] == "2026-11-15T12:00:00.123456+00:00"
    assert json.loads(value["row"]) == json.loads(raw)[0]
    assert json.loads(value["row"])["value"] == "42"  # Native osqueryi --json preserves string columns.
    assert "pack-name" not in value
    for incomplete in [{"input_type": "snapshot"}, {"input_type": "snapshot", "host_identifier": "host"}]:
        assert "error" in module.handler(request(raw, incomplete))
    assert "error" in module.handler(request(raw, {}))
    empty = imported(raw=b"[]", config=config)
    assert empty["summary"]["rows"] == 0 and fields(objects(empty)[0])["record-type"] == "empty-result"


def test_native_logger_numeric_columns_keep_numeric_types():
    result = imported("event-snapshots.jsonl")
    values = [fields(o) for o in objects(result) if fields(o)["record-type"] == "row"]
    assert values and all(json.loads(value["row"])["value"] == 42 for value in values)


def test_deduplicated_hunting_query_keeps_multiple_event_and_object_origins():
    first = copy.deepcopy(MANIFEST["event"])
    second = {
        "uuid": "another-event",
        "Object": [
            {
                "uuid": "source-object",
                "name": "file",
                "Attribute": [{**copy.deepcopy(first["Attribute"][0]), "uuid": "another-attribute"}],
            }
        ],
    }
    exported = osqueryexport.handler(json.dumps({"data": [first, second], "config": {"interval": 1}}))
    refs = exported["sources"][MANIFEST["query_name"]]
    assert len(refs) == 2 and refs[1]["object"] == "source-object"
    result = imported(config={"sources": exported["sources"]})
    assert all(json.loads(fields(obj)["source-indicators"]) == refs for obj in objects(result))


def test_identical_rows_on_different_hosts_and_runs_are_not_merged():
    records = [
        event(hostIdentifier="host-a", epoch=0, counter=0),
        event(hostIdentifier="host-b", epoch=0, counter=0),
        event(hostIdentifier="host-a", epoch=0, counter=1),
    ]
    result = imported(raw=json.dumps(records).encode(), config={})
    assert len({o["uuid"] for o in objects(result)}) == 3
    assert [fields(o)["host-identifier"] for o in objects(result)] == ["host-a", "host-b", "host-a"]
    assert [fields(o)["counter"] for o in objects(result)] == ["0", "0", "1"]


def test_row_columns_and_unknown_native_metadata_are_not_promoted_to_provenance_or_tags():
    value = event(
        columns={"hostIdentifier": "spoof", "misp_attribute_uuid": "fake", "verdict": "malicious"},
        decorations={"host": "a", "labels": ["malicious"]},
        results="native decoration named results",
    )
    result = imported(raw=json.dumps(value).encode(), config={})
    attrs = fields(objects(result)[0])
    assert attrs["host-identifier"] == value["hostIdentifier"]
    assert "source-indicators" not in attrs and attrs["review-status"] == "unreviewed"
    assert json.loads(attrs["record-context"])["results"] == "native decoration named results"
    assert json.loads(attrs["decorations"]) == value["decorations"]
    assert "Tag" not in objects(result)[0]


def test_pack_identity_is_not_guessed_by_splitting_arbitrary_underscores():
    value = event(name="pack_team_pack_query_with_underscores")
    result = imported(raw=json.dumps(value).encode(), config={})
    attrs = fields(objects(result)[0])
    assert attrs["query-name"] == value["name"] and "pack-name" not in attrs
    result = imported(raw=json.dumps(value).encode(), config={"pack_name": "team_pack"})
    assert fields(objects(result)[0])["query-name"] == "query_with_underscores"
    value = event(name="pack_" + MANIFEST["pack_name"] + "_" + MANIFEST["query_name"])
    assert "error" in module.handler(request(json.dumps(value).encode(), {"pack_name": "wrong"}))


def test_exact_scheduled_source_key_precedes_bare_query_mapping_and_object_scope_is_kept():
    name = "pack_" + MANIFEST["pack_name"] + "_" + MANIFEST["query_name"]
    ref = {"event": "event", "object": "object", "attribute": "attribute", "misp_type": "ip-dst"}
    mapping = {**SOURCES, name: [ref]}
    result = imported(raw=json.dumps(event(name=name)).encode(), config={"sources": json.dumps(mapping)})
    assert json.loads(fields(objects(result)[0])["source-indicators"]) == [ref]
    assert not result["warnings"]
    result = imported(raw=json.dumps(event(name=name)).encode(), config={})
    assert "source-indicators" not in fields(objects(result)[0]) and result["warnings"]


@pytest.mark.parametrize(
    "value,expected",
    [(0, "1970-01-01T00:00:00+00:00"), (-1, "1969-12-31T23:59:59+00:00"), ("1794744000", "2026-11-15T12:00:00+00:00")],
)
def test_native_unix_seconds_are_explicit_units_including_zero(value, expected):
    result = imported(raw=json.dumps(event(unixTime=value)).encode(), config={})
    assert fields(objects(result)[0])["execution-time"] == expected


@pytest.mark.parametrize("value", [True, 1.5, "1794744000.5", 10**30, {"time": 0}])
def test_invalid_unix_time_is_raw_without_unit_guessing_or_fallback(value):
    result = imported(raw=json.dumps(event(unixTime=value)).encode(), config={"executed_at": "2026-11-15T12:00:00Z"})
    attrs = fields(objects(result)[0])
    assert "execution-time" not in attrs and "unix-time" in attrs and result["warnings"]
    assert json.loads(attrs["record-context"])["unixTime"] == value


@pytest.mark.parametrize("value", ["2026-11-15T12:00:00", "2026-11-15T12:00:00-00:00", "2026-11-15T12:00:00.1234567Z"])
def test_ambiguous_collector_time_is_not_normalized(value):
    data = event()
    data.pop("unixTime")
    result = imported(raw=json.dumps(data).encode(), config={"executed_at": value})
    attrs = fields(objects(result)[0])
    assert "execution-time" not in attrs and attrs["execution-time-raw"] == value and result["warnings"]


@pytest.mark.parametrize(
    "change",
    [
        {"action": "delete"},
        {"columns": []},
        {"snapshot": []},
        {"diffResults": {"added": [], "removed": []}},
        {"hostIdentifier": []},
        {"numerics": "false"},
    ],
)
def test_invalid_event_schema_is_atomic(change):
    result = module.handler(request(json.dumps(event(**change)).encode(), {}))
    assert "error" in result and "results" not in result


@pytest.mark.parametrize(
    "payload",
    [
        {"snapshot": [None]},
        {"snapshot": {}},
        {"diffResults": {"added": None, "removed": []}},
        {"diffResults": {"added": [], "removed": [], "unknown": []}},
        {"diffResults": {"added": [None], "removed": []}},
    ],
)
def test_invalid_batch_and_snapshot_rows_are_not_empty_findings(payload):
    data = {"name": "query", "hostIdentifier": "host", "unixTime": 0, **payload}
    result = module.handler(request(json.dumps(data).encode(), {}))
    assert "error" in result and "results" not in result


@pytest.mark.parametrize(
    "sources",
    [
        [],
        {"query": {}},
        {"query": [None]},
        {"query": [{"event": "e"}]},
        {"query": [{"event": "e", "attribute": False, "misp_type": "text"}]},
    ],
)
def test_invalid_source_references_are_rejected(sources):
    result = module.handler(request(json.dumps(event()).encode(), {"sources": sources}))
    assert "error" in result and "results" not in result


def test_duplicate_keys_explicit_formats_and_conflicting_sidecars_are_rejected():
    for raw in [b'{"name":"a","name":"b"}', b'{"value":NaN}', b"[]"]:
        assert "error" in module.handler(request(raw, {}))
    assert "error" in module.handler(request((FIXTURES / "event.jsonl").read_bytes(), {"format": "json"}))
    ref = SOURCES[MANIFEST["query_name"]][0]
    wrapper = {"results": [event()], "sources": SOURCES, "metadata": {"host_identifier": "host"}}
    for config in [
        {"sources": {MANIFEST["query_name"]: [{**ref, "attribute": "other"}]}},
        {"host_identifier": "other"},
    ]:
        assert "error" in module.handler(request(json.dumps(wrapper).encode(), config))


def test_resource_limits_are_atomic(monkeypatch):
    assert "error" in module.handler(request(json.dumps([event()] * 1001).encode(), {}))
    data = {"name": "q", "hostIdentifier": "host", "snapshot": [{}] * 1001}
    assert "error" in module.handler(request(json.dumps(data).encode(), {}))
    data = [event(snapshot=[{}])]
    data[0].pop("columns")
    data[0]["action"] = "snapshot"
    monkeypatch.setattr(module, "MAX_ROWS", 1)
    assert "error" in module.handler(request(json.dumps(data * 2).encode(), {}))
    monkeypatch.setattr(module, "MAX_ROW", 20)
    assert "error" in module.handler(request(json.dumps(event()).encode(), {}))
    monkeypatch.setattr(module, "MAX_INPUT", 1)
    assert "error" in module.handler(request(b"{}", {}))


@pytest.mark.parametrize("config", [[], {"format": False}, {"input_type": []}, {"query_name": False}])
def test_invalid_configuration_is_rejected(config):
    assert "error" in module.handler(request(json.dumps(event()).encode(), config))


def test_jsonl_unicode_separators_and_no_network_dependency(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Importer must not access the network")

    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(socket.socket, "connect", fail)
    records = [event(columns={"text": "first\u2028second\u0085third"}), event(action="removed")]
    raw = ("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n").encode()
    first = imported(raw=raw, config={})
    assert first == imported(raw=raw, config={})
    assert json.loads(fields(objects(first)[0])["row"])["text"] == records[0]["columns"]["text"]
    for obj in objects(first):
        parsed = MISPObject("osquery-result", strict=True, misp_objects_template_custom=module._template())
        parsed.from_dict(**copy.deepcopy(obj))
        assert parsed.to_json(strict=True)


def test_bad_requests_filename_and_bom():
    for q in ["null", "[]", "{}", json.dumps({"data": "%%%"}), request(b"\xff")]:
        assert "error" in module.handler(q)
    raw = b"\xef\xbb\xbf" + json.dumps(event()).encode()
    result = module.handler(request(raw, {}, filename="C:\\uploads\\results.json"))
    assert fields(objects(result, "file")[0])["filename"] == "results.json"


class TestOSQueryImportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"osquery_import": module, "type:osquery_import": "import_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_import_and_errors(self):
        modules = json.loads(self.fetch("/modules").body)
        assert modules[0]["name"] == "osquery_import" and modules[0]["mispattributes"]["format"] == "misp_standard"
        assert module.handler() is False
        response = self.fetch(
            "/query",
            method="POST",
            body=request((FIXTURES / "event.jsonl").read_bytes(), {"sources": SOURCES}, module="osquery_import"),
        )
        assert response.code == 200 and json.loads(response.body)["summary"]["rows"] == 2
        response = self.fetch("/query", method="POST", body=json.dumps({"module": "osquery_import", "data": "%%%"}))
        assert response.code == 200 and "error" in json.loads(response.body)
