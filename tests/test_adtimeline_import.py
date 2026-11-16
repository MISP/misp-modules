import base64
import csv
import hashlib
import io
import json
from pathlib import Path

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.import_mod import adtimeline_import as ad

FIXTURE = Path(__file__).parent / "fixtures/adtimeline/timeline_example.test.csv"


def imported(raw=None, **kwargs):
    raw = FIXTURE.read_bytes() if raw is None else raw
    return ad.handler(json.dumps({"data": base64.b64encode(raw).decode(), **kwargs}))


def observations(result):
    assert "error" not in result, result
    return [obj for obj in result["results"]["Object"] if obj["name"] == "ad-replication-metadata"]


def values(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def csv_bytes(rows, header=None):
    header = header or list(rows[0])
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=header, delimiter=";")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


def row(**kwargs):
    return {
        "DN": "CN=Test,DC=example,DC=test",
        "pszAttributeName": "member",
        "ftimeLastOriginatingChange": "2026-01-01T01:02:03Z",
        **kwargs,
    }


def test_native_powershell_export_preserves_metadata_and_source():
    result = imported(
        filename="C:\\collection\\timeline.csv",
        config={"collection_server": "dc02.example.test", "domain_scope": "example.test"},
    )
    objs = observations(result)
    assert len(objs) == 3
    source = next(obj for obj in result["results"]["Object"] if obj["name"] == "file")
    assert values(source)["sha256"] == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    attachment = next(a for a in source["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == FIXTURE.read_bytes()
    assert values(source)["filename"] == "timeline.csv"
    by_attribute = {values(obj)["attribute-name"]: values(obj) for obj in objs}
    assert by_attribute["member"]["link-deleted"].startswith("2026-01-02T03:04:05")
    assert by_attribute["altRecipient"]["linked-value-dn"] == "CN=Target,DC=example,DC=test"
    assert by_attribute["altRecipient"]["link-deleted-raw"] == "1601-01-01T00:00:00Z"
    assert "link-deleted" not in by_attribute["altRecipient"]
    assert "linked-value-dn" not in by_attribute["nTSecurityDescriptor"]
    for obj in objs:
        data = values(obj)
        assert data["originating-usn"] == "18446744073709551610"
        assert data["local-usn"] == "9007199254740993"
        assert data["object-name"] == 'Synthetic; "group"'
        assert data["collection-server"] == "dc02.example.test"
        assert json.loads(data["raw-record"])["dwVersion"] == "3"
        assert obj["ObjectReference"][0]["referenced_uuid"] == source["uuid"]
        assert obj["ObjectReference"][0]["relationship_type"] == "derived-from"
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])
        loaded = MISPObject("ad-replication-metadata", strict=True, misp_objects_template_custom=ad._template())
        loaded.from_dict(**obj)
        loaded.to_json(strict=True)
    assert result["warnings"] == []


def test_identity_stable_and_context_scoped_duplicate_records_retained():
    first = imported()
    assert first == imported()
    other = imported(config={"collection_server": "another"})
    assert [o["uuid"] for o in observations(first)] != [o["uuid"] for o in observations(other)]
    assert len(observations(imported(csv_bytes([row(), row()])))) == 2


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-be"])
def test_bom_encodings_and_unknown_columns_multiline_unicode(encoding):
    raw = csv_bytes([row(extra='line one\nquoted; "é"')]).decode().encode(encoding)
    if encoding == "utf-16-be":
        raw = b"\xfe\xff" + raw
    data = values(observations(imported(raw))[0])
    assert json.loads(data["raw-record"])["extra"] == 'line one\nquoted; "é"'
    assert data["record-index"] in ("1", 1)


@pytest.mark.parametrize(
    "time",
    [
        "01/02/2026 03:04:05",
        "2026-01-01T00:00:00",
        "2026-02-30T00:00:00Z",
        "2026-01-01T00:00:00-00:00",
        "2026-01-01T00:00:00.1234567Z",
    ],
)
def test_ambiguous_invalid_and_excess_precision_times_retained(time):
    result = imported(csv_bytes([row(ftimeLastOriginatingChange=time)]))
    data = values(observations(result)[0])
    assert data["change-time-raw"] == time and "change-time" not in data
    assert result["warnings"]


def test_known_offset_times_normalize_and_no_actor_or_verdict_is_inferred():
    result = imported(csv_bytes([row(ftimeLastOriginatingChange="2026-01-01T02:00:00+02:00")]))
    data = values(observations(result)[0])
    assert data["change-time"].startswith("2026-01-01T00:00:00")
    assert data["review-status"] == "unreviewed"
    assert "actor" not in data and "deleted" not in observations(result)[0]


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"a,b,c\n1,2,3",
        b"DN;DN;pszAttributeName;ftimeLastOriginatingChange\na;b;c;d",
        b"DN;pszAttributeName;ftimeLastOriginatingChange\na;b",
        b"DN;pszAttributeName;ftimeLastOriginatingChange\n",
        b'DN;pszAttributeName;ftimeLastOriginatingChange\n"unterminated',
        b"\xffgarbage",
        b"DN;pszAttributeName;ftimeLastOriginatingChange\na;b;\x00",
    ],
)
def test_invalid_csv_is_atomic(raw):
    result = imported(raw)
    assert "error" in result and "results" not in result


@pytest.mark.parametrize("config", [[], False, "x", {"domain_scope": 4}, {"collection_server": "a\x00b"}])
def test_invalid_context(config):
    assert "error" in imported(csv_bytes([row()]), config=config)


def test_limits_missing_required_and_partial_output(monkeypatch):
    for field in ("DN", "pszAttributeName", "ftimeLastOriginatingChange"):
        assert "error" in imported(csv_bytes([row(**{field: ""})]))
    monkeypatch.setattr(ad, "MAX_ROWS", 1)
    assert "error" in imported(csv_bytes([row(), row()]))
    monkeypatch.setattr(ad, "MAX_INPUT", 10)
    assert "error" in imported(csv_bytes([row()]))


@pytest.mark.parametrize("payload", [None, [], {}, {"data": "%%%bad"}, {"data": 1}])
def test_protocol_errors(payload):
    assert "error" in ad.handler(json.dumps(payload))
    assert ad.handler() is False


class TestADTimelineHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous = service.MODULES_HANDLERS.copy()
        self.cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"adtimeline_import": ad, "type:adtimeline_import": "import_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_import(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "adtimeline_import"
        response = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "adtimeline_import", "data": base64.b64encode(csv_bytes([row()])).decode()}),
        )
        assert response.code == 200
        assert len(observations(json.loads(response.body))) == 1
