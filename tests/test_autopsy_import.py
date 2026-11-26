"""Selected forensic rows, TSK mappings, provenance, selection and HTTP contract."""

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.import_mod import autopsy_import as module

ROOT = Path(__file__).parent / "fixtures" / "autopsy"


def request(raw, config=None, **kwargs):
    return json.dumps({"data": base64.b64encode(raw).decode(), "config": config, **kwargs})


def document():
    return json.loads((ROOT / "selected.json").read_text())


def imported(doc=None, raw=None, **config):
    if raw is None:
        raw = json.dumps(doc if doc is not None else document()).encode()
    result = module.handler(request(raw, config))
    assert "error" not in result, result
    return result


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def fields(obj):
    return {attribute["object_relation"]: attribute["value"] for attribute in obj["Attribute"]}


def references(obj, relation):
    return [ref["referenced_uuid"] for ref in obj.get("ObjectReference", []) if ref["relationship_type"] == relation]


def test_mixed_mobile_interchange_maps_all_requested_categories():
    raw = (ROOT / "selected.json").read_bytes()
    result = imported(raw=raw)
    assert result["summary"] == {
        "input_records": 9,
        "selected_records": 9,
        "mapped_records": 8,
        "unmapped_records": 1,
        "source_attached": True,
    }
    source = objects(result, "file")[0]
    assert fields(source)["sha256"] == hashlib.sha256(raw).hexdigest()
    attached = next(a for a in source["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attached["data"]) == raw
    records = objects(result, "forensic-artifact")
    assert len(records) == 9
    assert [fields(record)["record-number"] for record in records] == [str(number) for number in range(1, 10)]
    assert fields(records[0])["case-id"] == "case-a"
    assert fields(records[0])["source-file"] == "/users/alice/History"
    assert fields(records[0])["source-object-id"] == "450"
    assert fields(records[5])["device-id"] == "phone-b"
    assert fields(records[7])["application-id"] == "org.example.app"
    assert json.loads(fields(records[0])["raw-record"]) == document()["artifacts"][0]
    assert fields(objects(result, "tsk-web-history")[0])["URL"] == "https://example.org/a?x=1&y=two%20words"
    assert fields(objects(result, "tsk-web-history")[0])["datetime-accessed"] == "2023-11-14T22:13:20+00:00"
    assert fields(objects(result, "tsk-web-bookmark")[0])["datetime-bookmarked"] == "2026-11-15T09:00:00+00:00"
    assert fields(objects(result, "tsk-web-cookie")[0])["value"] == "test-only-cookie"
    assert fields(objects(result, "tsk-web-search-query")[0])["text"] == "test query"
    download = fields(objects(result, "tsk-web-downloads")[0])
    assert download["name"] == "evidence.bin"
    assert download["pathID"] == "999"
    chats = objects(result, "tsk-chats")
    assert [fields(obj)["message-type"] for obj in chats] == ["SMS", "Email"]
    assert fields(chats[0])["Source"] == "+12025550101"
    assert fields(chats[0])["message"].endswith("Second line.")
    software = fields(objects(result, "software")[0])
    assert software == {"name": "Example App", "version": "1.2.3"}
    assert json.loads(fields(records[7])["raw-record"])["attributes"]["TSK_ORGANIZATION"] == "Example"
    assert any("Unsupported artifact type" in warning for warning in result["warnings"])
    known = {obj["uuid"] for obj in result["results"]["Object"]}
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])
        assert all(ref["referenced_uuid"] in known for ref in obj.get("ObjectReference", []))
        if obj["name"] == "forensic-artifact":
            assert references(obj, "derived-from") == [source["uuid"]]
            assert fields(obj)["review-status"] == "unreviewed"
        elif obj["name"] != "file":
            assert references(obj, "derived-from")[0] in {record["uuid"] for record in records}


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"], ids=["lf", "crlf"])
def test_native_autopsy_selected_csv_preserves_export_and_english_labels(ending):
    raw = (ROOT / "history.csv").read_bytes().replace(b"\n", ending)
    result = imported(raw=raw, artifact_type="TSK_WEB_HISTORY", case_id="case-csv", data_source_id="17")
    assert len(objects(result, "tsk-web-history")) == 2
    history = fields(objects(result, "tsk-web-history")[0])
    assert history["URL"] == "https://example.org/?q=one%20two"
    assert history["title"] == 'A title, with "quotes"'
    assert history["datetime-accessed"] == "2026-11-15T10:30:00+00:00"
    record = fields(objects(result, "forensic-artifact")[0])
    assert record["producer"] == "Autopsy"
    assert record["source-format"] == "autopsy-csv"
    assert record["artifact-id"] == "42"
    assert record["data-source"] == "disk-image.E01"
    assert record["data-source-id"] == "17"
    assert record["case-id"] == "case-csv"
    assert json.loads(record["raw-record"])["Unmapped"] == "Preserved, not discarded"
    attachment = next(a for a in objects(result, "file")[0]["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == raw


@pytest.mark.parametrize("rows", ["2,8", [2, 8], ["2", "8"]])
def test_selection_omits_full_source_and_keeps_original_ordinals(rows):
    result = imported(rows=rows)
    source = objects(result, "file")[0]
    assert "attachment" not in fields(source)
    records = objects(result, "forensic-artifact")
    assert [fields(record)["record-number"] for record in records] == ["2", "8"]
    assert len(objects(result, "tsk-web-bookmark")) == len(objects(result, "software")) == 1
    assert not objects(result, "tsk-chats")
    assert "test-only-cookie" not in json.dumps(result)
    assert result["summary"]["source_attached"] is False
    assert json.loads(fields(records[0])["source-context"])["selection"]["rows"] == [2, 8]
    assert any("attachment omitted" in warning for warning in result["warnings"])


def test_csv_row_selection_omits_excluded_record_bytes():
    result = imported(raw=(ROOT / "history.csv").read_bytes(), artifact_type="TSK_WEB_HISTORY", rows="2")
    assert len(objects(result, "forensic-artifact")) == 1
    assert fields(objects(result, "forensic-artifact")[0])["record-number"] == "2"
    assert "A title" not in json.dumps(result)
    assert "attachment" not in fields(objects(result, "file")[0])


@pytest.mark.parametrize(
    "location,expected",
    [
        ("https://example.org/sign-in", {"URL": "https://example.org/sign-in"}),
        (".example.org", {"domain-name": ".example.org"}),
        ("about:blank", None),
    ],
)
def test_cookie_location_uses_the_template_relation_that_matches_the_value(location, expected):
    doc = document()
    row = {
        "artifact_type": "TSK_WEB_COOKIE",
        "attributes": {
            "TSK_URL": location,
            "TSK_NAME": "session",
            "TSK_VALUE": "fixture-value",
            "TSK_DATETIME_CREATED": 1700000000,
            "TSK_DATETIME_ACCESSED": 1700000001,
        },
    }
    doc["artifacts"] = [row]
    result = imported(doc)
    assert json.loads(fields(objects(result, "forensic-artifact")[0])["raw-record"]) == row
    cookies = objects(result, "tsk-web-cookie")
    if expected is None:
        assert not cookies
        assert result["summary"]["unmapped_records"] == 1
        return
    [cookie] = cookies
    assert fields(cookie) == {
        **expected,
        "name": "session",
        "value": "fixture-value",
        "datetime-created": "2023-11-14T22:13:20+00:00",
        "datetime-accessed": "2023-11-14T22:13:21+00:00",
    }


@pytest.mark.parametrize(
    "value,config,expected",
    [
        ("2026-11-15 10:00:00", {}, None),
        ("2026-11-15 10:00:00 CST", {}, None),
        ("2026-11-15 10:00:00 CST", {"timezone": "-06:00"}, "2026-11-15T16:00:00+00:00"),
        ("2026-11-15 10:00:00", {"timezone": "+01:00"}, "2026-11-15T09:00:00+00:00"),
        ("2026-11-15 10:00:00 GMT+05:30", {}, "2026-11-15T04:30:00+00:00"),
        ("2026-11-15T10:00:00-00:00", {}, None),
        ("2026-11-15T10:00:00.123456789Z", {}, None),
        (1700000000000, {}, None),  # Milliseconds must not be guessed as Unix seconds.
        (0, {}, None),  # Sleuth Kit renders zero as an unknown date.
        ("1970-01-01T00:00:00Z", {}, "1970-01-01T00:00:00+00:00"),
    ],
)
def test_timezones_units_and_precision_are_explicit(value, config, expected):
    doc = document()
    row = copy.deepcopy(doc["artifacts"][0])
    row["attributes"]["TSK_DATETIME_ACCESSED"] = value
    doc["artifacts"] = [row]
    result = imported(doc, **config)
    if expected is None:
        assert not objects(result, "tsk-web-history")  # Required date is not fabricated.
        assert result["summary"]["unmapped_records"] == 1
        assert result["warnings"]
    else:
        assert fields(objects(result, "tsk-web-history")[0])["datetime-accessed"] == expected
    assert json.loads(fields(objects(result, "forensic-artifact")[0])["raw-record"]) == row


@pytest.mark.parametrize("profile", ["TSK_WEB_COOKIE", "TSK_WEB_DOWNLOAD", "TSK_MESSAGE", "TSK_INSTALLED_PROG"])
def test_incomplete_profiles_remain_raw_instead_of_invalid_tsk_objects(profile):
    doc = document()
    doc["artifacts"] = [{"artifact_type": profile, "attributes": {"unknown": "retained"}}]
    result = imported(doc)
    assert [obj["name"] for obj in result["results"]["Object"]] == ["file", "forensic-artifact"]
    assert result["summary"]["unmapped_records"] == 1


@pytest.mark.parametrize("format_", ["selected-json", "autopsy-csv"])
@pytest.mark.parametrize("report_timezone", [None, "-06:00"])
@pytest.mark.parametrize(
    "offset,expected",
    [
        ("+01:00", "2026-11-15T09:00:00+00:00"),
        ("-05:30", "2026-11-15T15:30:00+00:00"),
    ],
)
def test_explicit_utc_offset_overrides_report_timezone(format_, report_timezone, offset, expected):
    value = "2026-11-15 10:00:00 UTC" + offset
    config = {} if report_timezone is None else {"timezone": report_timezone}
    if format_ == "autopsy-csv":
        raw = f"URL,Date Accessed\nhttps://example.org/,{value}\n".encode()
        result = imported(raw=raw, artifact_type="TSK_WEB_HISTORY", **config)
    else:
        doc = document()
        doc["artifacts"] = [doc["artifacts"][0]]
        doc["artifacts"][0]["attributes"]["TSK_DATETIME_ACCESSED"] = value
        result = imported(doc, **config)
    assert fields(objects(result, "tsk-web-history")[0])["datetime-accessed"] == expected
    assert not result["warnings"]


def test_conflicting_aliases_are_not_silently_selected():
    doc = document()
    doc["artifacts"] = [doc["artifacts"][0]]
    doc["artifacts"][0]["attributes"]["URL"] = "https://different.example/"
    result = imported(doc)
    assert not objects(result, "tsk-web-history")
    assert any("conflicting TSK_URL" in warning for warning in result["warnings"])


def test_application_and_communication_times_are_not_execution_or_direction_claims():
    doc = document()
    doc["artifacts"] = [doc["artifacts"][5], doc["artifacts"][7]]
    del doc["artifacts"][0]["attributes"]["TSK_DATETIME_SENT"]
    result = imported(doc)
    assert "datetime-sent" not in fields(objects(result, "tsk-chats")[0])
    assert "event-time" in fields(objects(result, "forensic-artifact")[0])
    assert all("first_seen" not in attribute for obj in result["results"]["Object"] for attribute in obj["Attribute"])


def test_identity_does_not_join_duplicate_artifact_ids_or_cases():
    doc = document()
    doc["artifacts"] = [doc["artifacts"][0], copy.deepcopy(doc["artifacts"][0])]
    result = imported(doc)
    ids = [obj["uuid"] for obj in objects(result, "forensic-artifact")]
    assert len(set(ids)) == 2
    assert ids == [obj["uuid"] for obj in objects(imported(doc), "forensic-artifact")]
    doc["context"]["case_id"] = "different-case"
    assert ids != [obj["uuid"] for obj in objects(imported(doc), "forensic-artifact")]


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b'{"format":"ufed","records":[]}',
        b"<UFEDReport/>",
        b"\xff",
        b"URL,URL\none,two\n",
        b"URL,Title\none\n",
        b'URL\n"unterminated',
        b'{"format":"misp-forensic-selected","format":"other"}',
    ],
)
def test_unsupported_native_reports_and_malformed_exports_reject_atomically(raw):
    result = module.handler(request(raw, {"artifact_type": "TSK_WEB_HISTORY"}))
    assert "error" in result and "results" not in result


@pytest.mark.parametrize(
    "config",
    [
        [],
        False,
        {"rows": []},
        {"rows": [True]},
        {"rows": "0"},
        {"rows": "1000"},
        {"format": "pdf"},
        {"format": False},
        {"tool_version": False},
        {"timezone": "Europe/Paris"},
        {"timezone": "-00:00"},
        {"unsupported": True},
    ],
)
def test_invalid_config_is_rejected(config):
    result = module.handler(request((ROOT / "selected.json").read_bytes(), config))
    assert "error" in result and "results" not in result


def test_csv_requires_explicit_artifact_type():
    result = module.handler(request((ROOT / "history.csv").read_bytes()))
    assert "artifact_type" in result["error"]


def test_limits_reject_without_partial_results(monkeypatch):
    raw = (ROOT / "selected.json").read_bytes()
    for name, limit in [("MAX_INPUT", 10), ("MAX_ROWS", 2), ("MAX_ROW", 30), ("MAX_OUTPUT", 10)]:
        with monkeypatch.context() as patch:
            patch.setattr(module, name, limit)
            result = module.handler(request(raw))
            assert "error" in result and "results" not in result


def test_json_nonfinite_depth_and_surrogates_rejected():
    doc = document()
    for value in [float("nan"), "\ud800", {"nested": []}]:
        doc["artifacts"][0]["attributes"]["extra"] = value
        if isinstance(value, dict):
            node = value["nested"]
            for _ in range(34):
                node.append([])
                node = node[0]
        assert "error" in module.handler(request(json.dumps(doc).encode()))


def test_selected_json_retains_exact_row_text_and_high_precision_numbers():
    lexical = (
        '{ "artifact_type" : "TSK_INSTALLED_PROG", "artifact_id":18446744073709551615,'
        ' "attributes" : {"TSK_PROG_NAME":"Selected"}, "native_record":'
        '{"number":0.12345678901234567890123456789,"escaped":"\\u00e9"} }'
    )
    raw = (
        '{"format":"misp-forensic-selected","version":1,"producer":{"name":"Parser"},"artifacts":['
        + lexical
        + ',{"artifact_type":"OTHER","attributes":{"secret":"DO-NOT-IMPORT"}}]}'
    ).encode()
    result = imported(raw=raw, rows="1")
    record = fields(objects(result, "forensic-artifact")[0])
    assert record["raw-record"] == lexical
    assert record["artifact-id"] == "18446744073709551615"
    assert "DO-NOT-IMPORT" not in json.dumps(result)


def test_explicit_false_row_type_and_producer_version_are_not_defaulted():
    for field in ("artifact_type", "producer.version"):
        doc = document()
        if field == "artifact_type":
            doc["artifacts"][0]["artifact_type"] = False
        else:
            doc["producer"]["version"] = False
        result = module.handler(request(json.dumps(doc).encode(), {"artifact_type": "TSK_WEB_HISTORY"}))
        assert "error" in result and "results" not in result


class TestAutopsyHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"autopsy_import": module, "type:autopsy_import": "import_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_selected_query(self):
        modules = json.loads(self.fetch("/modules").body)
        assert modules[0]["name"] == "autopsy_import"
        assert module.handler() is False
        response = self.fetch(
            "/query",
            method="POST",
            body=request(
                (ROOT / "selected.json").read_bytes(),
                {"rows": "2,8"},
                module="autopsy_import",
            ),
        )
        assert response.code == 200
        result = json.loads(response.body)
        assert result["summary"]["selected_records"] == 2
        assert not result["summary"]["source_attached"]

    def test_discovered_config_supports_selected_autopsy_csv(self):
        [metadata] = json.loads(self.fetch("/modules").body)
        user_config = metadata["mispattributes"]["userConfig"]
        assert user_config.keys() == set(metadata["meta"]["config"])
        config = {"artifact_type": "TSK_WEB_COOKIE", "rows": "1", "timezone": "+01:00"}
        assert all(user_config[key]["type"] == "String" for key in config)
        response = self.fetch(
            "/query",
            method="POST",
            body=request((ROOT / "cookies.csv").read_bytes(), config, module="autopsy_import"),
        )
        assert response.code == 200
        result = json.loads(response.body)
        assert result["summary"]["mapped_records"] == 1
        assert not result["summary"]["source_attached"]
        [cookie] = objects(result, "tsk-web-cookie")
        assert cookie["template_uuid"] == "40d23a4f-43be-4c9e-8328-382a2188eb1d"
        assert int(cookie["template_version"]) >= 2
        assert fields(cookie) == {
            "browser": "Chrome",
            "domain-name": "example.org",
            "name": "session",
            "value": "fixture-value",
            "datetime-accessed": "2026-11-15T09:30:00+00:00",
        }
        [record] = objects(result, "forensic-artifact")
        assert references(cookie, "derived-from") == [record["uuid"]]
        assert json.loads(fields(record)["raw-record"])["URL"] == ".example.org"
        assert "excluded-fixture-value" not in json.dumps(result)
