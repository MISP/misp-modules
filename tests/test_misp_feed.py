import base64
import copy
import csv
import hashlib
import io
import json
import uuid
import zipfile
from unittest.mock import patch

import pytest
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import misp_feed as module


def identifier(number):
    return str(uuid.UUID(int=number, version=4))


def event(number=1):
    return {
        "uuid": identifier(number),
        "id": str(number),
        "info": "Feed event café " + str(number),
        "Orgc": {"id": "23", "uuid": identifier(200), "name": "Example org"},
        "distribution": "3",
        "published": True,
        "date": "2026-11-09",
        "timestamp": "1794200000",
        "Tag": [
            {"name": "tlp:clear", "exportable": True},
            {"name": "internal", "local": True},
            {"name": "not-exportable", "exportable": False},
        ],
        "Attribute": [
            {
                "uuid": identifier(100 + number),
                "id": "72",
                "type": "domain",
                "value": "example.org",
                "category": "Network activity",
                "to_ids": True,
                "distribution": "5",
                "Tag": [{"name": "local-attribute-tag", "local": True}],
            },
            {
                "uuid": identifier(300 + number),
                "type": "text",
                "value": "Context",
                "to_ids": False,
                "category": "Other",
                "distribution": "3",
            },
        ],
    }


@pytest.fixture(autouse=True)
def no_network():
    with patch(
        "requests.sessions.Session.send", side_effect=AssertionError("Feed export must not query another service")
    ):
        yield


def request(data, **config):
    return json.dumps({"data": data, "config": config})


def archive(data, **config):
    result = module.handler(request(data, **config))
    assert "error" not in result, result
    return result, zipfile.ZipFile(io.BytesIO(base64.b64decode(result["data"])))


def test_multi_event_archive_native_feed_contract_and_roundtrip():
    events = [{"Event": event(1)}, {"Event": event(2)}]
    before = copy.deepcopy(events)
    result, feed = archive(events)
    assert events == before and result["summary"]["events"] == 2
    manifest = json.loads(feed.read("manifest.json"))
    assert set(manifest) == {identifier(1), identifier(2)}
    assert set(feed.namelist()) == {"manifest.json", "hashes.csv", identifier(1) + ".json", identifier(2) + ".json"}
    expected = set()
    for key in manifest:
        body = json.loads(feed.read(key + ".json"))
        model = MISPEvent()
        model.load(copy.deepcopy(body))
        assert model.uuid == key and model.info == manifest[key]["info"]
        assert set(body) == {"Event"}
        assert "_hashes" not in body["Event"] and "_manifest" not in body["Event"]
        assert "id" not in body["Event"] and "id" not in body["Event"]["Orgc"]
        assert body["Event"]["Tag"] == manifest[key]["Tag"]
        for attr in body["Event"]["Attribute"]:
            assert "id" not in attr
            expected.add((hashlib.md5(attr["value"].encode()).hexdigest(), key))
        assert any(attr["to_ids"] is False for attr in body["Event"]["Attribute"])
    assert set(map(tuple, csv.reader(io.StringIO(feed.read("hashes.csv").decode())))) == expected
    assert all("/" not in name and ".." not in name for name in feed.namelist())


@pytest.mark.parametrize("shape", ["bare", "wrapped", "legacy", "response"])
def test_event_envelopes(shape):
    source = event()
    if shape == "bare":
        data = source
    elif shape == "wrapped":
        data = [{"Event": source}]
    elif shape == "response":
        data = {"response": [{"Event": source}]}
    else:
        data = [
            {
                "Event": {key: value for key, value in source.items() if key not in ("Attribute", "Tag", "Orgc")},
                "Attribute": source["Attribute"],
                "EventTag": [{"Tag": tag} for tag in source["Tag"]],
                "Orgc": source["Orgc"],
            }
        ]
    _, feed = archive(data)
    assert len(json.loads(feed.read(identifier(1) + ".json"))["Event"]["Attribute"]) == 2


def test_public_published_defaults_and_explicit_private_snapshot():
    public, private, draft, deleted = event(1), event(2), event(3), event(4)
    private["distribution"] = "0"
    draft["published"] = "0"
    deleted["deleted"] = "1"
    result, feed = archive([public, private, draft, deleted])
    assert result["summary"]["skipped"] == {"distribution": 1, "unpublished": 1, "deleted": 1}
    assert set(json.loads(feed.read("manifest.json"))) == {identifier(1)}
    result, feed = archive([private, draft], valid_distributions="0,3,5", include_unpublished="true")
    assert result["summary"]["events"] == 2
    assert json.loads(feed.read(identifier(3) + ".json"))["Event"]["published"] is False


def test_filter_attributes_objects_reports_and_hashes_consistently():
    source = event()
    source["Attribute"] += [
        dict(source["Attribute"][0], uuid=identifier(601), value="deleted.example", deleted=True),
        dict(source["Attribute"][0], uuid=identifier(602), value="private.example", distribution="0"),
    ]
    source["Object"] = [
        {
            "uuid": identifier(700),
            "name": "file",
            "distribution": "5",
            "Attribute": [
                {
                    "uuid": identifier(701),
                    "type": "filename",
                    "value": "sample.exe",
                    "object_relation": "filename",
                    "to_ids": False,
                },
                {
                    "uuid": identifier(702),
                    "type": "text",
                    "value": "exclude me",
                    "object_relation": "comment",
                    "to_ids": False,
                },
            ],
            "ObjectReference": [
                {"uuid": identifier(703), "referenced_uuid": identifier(602), "relationship_type": "related-to"}
            ],
        },
        {"uuid": identifier(704), "name": "file", "deleted": True, "Attribute": []},
        {"uuid": identifier(705), "name": "file", "distribution": "0", "Attribute": []},
    ]
    source["EventReport"] = [
        {"uuid": identifier(800), "name": "Public report", "content": "Context", "distribution": 5},
        {"uuid": identifier(801), "name": "Private", "content": "private-report-content", "distribution": 0},
    ]
    _, feed = archive([source], exclude_attribute_types="text")
    body = json.loads(feed.read(identifier(1) + ".json"))["Event"]
    assert [a["value"] for a in body["Attribute"]] == ["example.org"]
    assert len(body["Object"]) == 1 and [a["value"] for a in body["Object"][0]["Attribute"]] == ["sample.exe"]
    assert not body["Object"][0].get("ObjectReference")
    assert [r["name"] for r in body["EventReport"]] == ["Public report"]
    assert set(row[0] for row in csv.reader(io.StringIO(feed.read("hashes.csv").decode()))) == {
        hashlib.md5(value.encode()).hexdigest() for value in ("example.org", "sample.exe")
    }
    assert b"private-report-content" not in feed.read(identifier(1) + ".json")


def test_exportable_local_tags_filter_applies_to_manifest_event_and_attributes():
    source = event()
    source["Tag"].append({"name": "global-false-string", "local": "false", "exportable": "true"})
    source["Attribute"][0]["Tag"].append({"name": "hidden", "exportable": "false"})
    _, feed = archive([source])
    body = json.loads(feed.read(identifier(1) + ".json"))["Event"]
    assert {t["name"] for t in body["Tag"]} == {"tlp:clear", "global-false-string"}
    assert body["Attribute"][0].get("Tag", []) == []
    assert json.loads(feed.read("manifest.json"))[identifier(1)]["Tag"] == body["Tag"]
    _, feed = archive([source], with_local_tags="true")
    body = json.loads(feed.read(identifier(1) + ".json"))["Event"]
    assert "internal" in {t["name"] for t in body["Tag"]}
    assert body["Attribute"][0]["Tag"][0]["name"] == "local-attribute-tag"


def test_distribution_export_does_not_pollute_following_exports_or_pymisp_classes():
    source = event()
    fields_before = set(MISPEvent._fields_for_feed)
    _, included = archive([source], with_distribution="true")
    assert json.loads(included.read(identifier(1) + ".json"))["Event"]["distribution"] == "3"
    _, omitted = archive([source], with_distribution="false")
    body = json.loads(omitted.read(identifier(1) + ".json"))["Event"]
    assert "distribution" not in body and "distribution" not in body["Attribute"][0]
    assert MISPEvent._fields_for_feed == fields_before


def test_available_attachment_data_and_composite_hashes():
    source = event()
    source["Attribute"] = [
        {
            "uuid": identifier(902),
            "type": "attachment",
            "value": "note.txt",
            "to_ids": False,
            "data": base64.b64encode(b"Attachment contents").decode(),
        },
        {"uuid": identifier(903), "type": "domain|ip", "value": "example.org|192.0.2.1", "to_ids": True},
    ]
    _, feed = archive([source])
    body = json.loads(feed.read(identifier(1) + ".json"))["Event"]
    assert base64.b64decode(body["Attribute"][0]["data"]) == b"Attachment contents"
    hashes = {r[0] for r in csv.reader(io.StringIO(feed.read("hashes.csv").decode()))}
    assert hashes == {hashlib.md5(v.encode()).hexdigest() for v in ("note.txt", "example.org", "192.0.2.1")}


def test_archive_is_repeatable_and_does_not_refetch_full_event_for_empty_selection():
    assert archive([event()])[0]["data"] == archive([event()])[0]["data"]
    source = event()
    source["Attribute"] = []
    _, feed = archive([{"Event": event(), "Attribute": []}])
    assert json.loads(feed.read(identifier(1) + ".json"))["Event"].get("Attribute", []) == []
    assert feed.read("hashes.csv") == b""


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"data":[]}', '{"data":[null]}', '{"data":[],"config":[]}'])
def test_malformed_requests_return_no_artifact(raw):
    result = module.handler(raw)
    assert "error" in result and "data" not in result


@pytest.mark.parametrize(
    "change",
    [
        {"uuid": "../../escape"},
        {"uuid": None},
        {"uuid": str(uuid.UUID(int=0))},
        {"Orgc": {}},
        {"timestamp": None},
        {"published": "maybe"},
        {"distribution": 5},
        {"date": "invalid"},
        {"protected": "true"},
    ],
)
def test_invalid_metadata_or_protected_event_fails_whole_export(change):
    source = event(2)
    source.update(change)
    result = module.handler(request([event(1), source]))
    assert "error" in result and "data" not in result


@pytest.mark.parametrize(
    "config",
    [
        {"valid_distributions": []},
        {"valid_distributions": "6"},
        {"include_unpublished": "maybe"},
        {"exclude_attribute_types": []},
        {"max_events": 0},
        {"max_size_mb": True},
    ],
)
def test_bad_configuration(config):
    assert "error" in module.handler(request([event()], **config))


def test_duplicate_events_event_and_size_limits_do_not_truncate():
    for data, config in [([event(), event()], {}), ([event(1), event(2)], {"max_events": "1"})]:
        result = module.handler(request(data, **config))
        assert "error" in result and "data" not in result
    source = event()
    source["Attribute"][1]["value"] = "x" * 1048576
    assert "max_size_mb" in module.handler(request([source], max_size_mb="1"))["error"]


def test_discovery_contract():
    assert module.handler(False) is False
    assert module.version()["require_standard_format"]
    assert module.introspection()["inputSource"] == ["event", "event-collection"]
    assert module.introspection()["responseType"] == "application/zip"


class TestFeedHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"misp_feed": module, "type:misp_feed": "export"})
        service.ListModules.CACHE = None
        return Application([(r"/query", service.QueryModule), (r"/modules", service.ListModules)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_collection_query_and_discovery(self):
        response = self.fetch(
            "/query", method="POST", body=json.dumps({"module": "misp_feed", "data": [event(1), event(2)]})
        )
        assert response.code == 200
        result = json.loads(response.body)
        assert result["summary"]["events"] == 2 and "data" in result
        assert json.loads(self.fetch("/modules").body)[0]["mispattributes"]["outputFileExtension"] == "zip"
