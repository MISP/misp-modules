import base64
import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import ocsf_export as ocsf

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "tests/test_files/ocsf_1_9_0_osint.schema.json").read_text())
VALIDATOR = Draft7Validator(SCHEMA)


def attribute(kind="domain", value="example.org", **metadata):
    return {"type": kind, "value": value, "to_ids": True, "uuid": "attribute-1", **metadata}


def event(attributes=None, objects=None, **metadata):
    return {
        "uuid": "event-1",
        "id": "42",
        "info": "Example event",
        "timestamp": "1792281600",
        "Attribute": attributes or [],
        "Object": objects or [],
        **metadata,
    }


def export(data, config=None):
    response = ocsf.handler(json.dumps({"data": data, "config": config}))
    assert "error" not in response, response
    payload = base64.b64decode(response["data"], validate=True).decode("utf-8")
    assert not payload or payload.endswith("\n")
    documents = [json.loads(line) for line in payload.splitlines()]
    for document in documents:
        VALIDATOR.validate(document)
        assert document["metadata"]["version"] == "1.9.0"
        assert document["class_uid"] == 5021
        assert document["type_uid"] == document["class_uid"] * 100 + document["activity_id"]
        for observable in document["observables"]:
            value = document
            for component in re.sub(r"\[(\d+)\]", r".\1", observable["name"]).split("."):
                value = value[int(component)] if isinstance(value, list) else value[component]
            assert str(value) == observable["value"]
    return documents, response


@pytest.mark.parametrize("shape", ["bare", "wrapped", "legacy"])
def test_all_events_and_object_attributes_are_exported(shape):
    first = event(
        [attribute()],
        [
            {
                "uuid": "object-1",
                "name": "domain-ip",
                "Attribute": [attribute("ip-dst", "192.0.2.1", uuid="attribute-2", object_relation="ip")],
            }
        ],
    )
    second = event([attribute(value="second.example")], uuid="event-2")
    data = [first, second]
    if shape == "wrapped":
        data = [{"Event": item} for item in data]
    elif shape == "legacy":
        data = [
            {
                "Event": {k: v for k, v in item.items() if k not in ("Attribute", "Object")},
                "Attribute": item["Attribute"],
                "Object": item["Object"],
            }
            for item in data
        ]
    before = copy.deepcopy(data)
    documents, _ = export(data)
    assert len(documents) == 3
    assert data == before
    assert documents[1]["unmapped"]["misp"]["object"]["uuid"] == "object-1"
    assert documents[1]["unmapped"]["misp"]["attribute"]["object_relation"] == "ip"
    assert documents[2]["metadata"]["original_event_uid"] == "event-2"


@pytest.mark.parametrize("flag", [True, 1, "true", "1"])
def test_only_ids_attributes_are_included_by_default(flag):
    sources = [
        attribute(to_ids=flag),
        attribute(uuid="context", to_ids=False),
        attribute(uuid="missing", to_ids=None),
        attribute(uuid="string-false", to_ids="false"),
    ]
    assert len(export([event(sources)])[0]) == 1
    documents, _ = export([event(sources)], {"include_non_ids": flag})
    assert len(documents) == 4
    assert [d["unmapped"]["misp"]["to_ids"] for d in documents] == [True, False, False, False]


@pytest.mark.parametrize("deleted", [True, 1, "true", "1"])
def test_deleted_events_objects_and_attributes_are_excluded(deleted):
    data = [
        event([attribute()], deleted=deleted),
        event(
            [attribute(uuid="deleted", deleted=deleted), attribute(uuid="live", deleted="0")],
            [{"deleted": deleted, "Attribute": [attribute(uuid="object-attribute")]}],
            uuid="live-event",
        ),
    ]
    documents, _ = export(data, {"include_non_ids": True})
    assert len(documents) == 1
    assert documents[0]["osint"][0]["external_uid"] == "live"


@pytest.mark.parametrize(
    "kind,value,type_id,observable_id",
    [
        ("ip-src", "2001:0db8::1", 1, 2),
        ("ip-dst", "192.0.2.1", 1, 2),
        ("domain", "example.org", 2, 1),
        ("hostname", "host.example.org", 3, 1),
        ("url", "https://example.org:8443/path?q=1", 5, 6),
        ("user-agent", "Example/1.0", 6, 16),
        ("email-src", "sender@example.org", 9, 5),
        ("email-dst", "recipient@example.org", 9, 5),
        ("filename", "résumé.exe", 11, 7),
        ("regkey", r"HKLM\Software\Example", 12, 46),
        *[(kind, "A" * length, 4, 8) for kind, (length, _) in ocsf.HASH_TYPES.items()],
    ],
)
def test_atomic_indicators_follow_ocsf_types(kind, value, type_id, observable_id):
    documents, _ = export([event([attribute(kind, value)])])
    document = documents[0]
    assert document["osint"][0]["type_id"] == type_id
    assert document["observables"][0]["type_id"] == observable_id
    assert document["unmapped"]["misp"]["attribute"]["value"] == value
    if kind in ocsf.HASH_TYPES:
        assert document["osint"][0]["value"] == value.lower()
        # A hash alone provides no filename; do not invent one to fill a File object.
        assert "file" not in document["osint"][0]
    elif kind == "ip-src":
        assert document["osint"][0]["value"] == "2001:db8::1"


@pytest.mark.parametrize(
    "kind,length,algorithm",
    [
        *[(f"filename|{kind}", length, algorithm) for kind, (length, algorithm) in ocsf.HASH_TYPES.items()],
        ("malware-sample", 32, 1),
    ],
)
def test_filename_hash_composites_use_ocsf_fingerprints(kind, length, algorithm):
    documents, _ = export([event([attribute(kind, "a|b.exe|" + "A" * length)])])
    indicator = documents[0]["osint"][0]
    assert indicator["value"] == "a" * length
    assert indicator["file"] == {
        "name": "a|b.exe",
        "type_id": 0,
        "hashes": [{"algorithm_id": algorithm, "value": "a" * length}],
    }


def test_domain_ip_components_remain_in_one_source_record():
    documents, _ = export([event([attribute("domain|ip", "example.org|2001:db8::1")])])
    assert len(documents) == 1
    indicators = documents[0]["osint"]
    assert [(i["type_id"], i["value"]) for i in indicators] == [(2, "example.org"), (1, "2001:db8::1")]
    assert len({i["uid"] for i in indicators}) == 2
    assert all(i["external_uid"] == "attribute-1" for i in indicators)


@pytest.mark.parametrize(
    "kind,value,port",
    [
        ("ip-src|port", "2001:db8::1|443", 443),
        ("ip-dst|port", "192.0.2.1|0", 0),
        ("hostname|port", "example.org|65535", 65535),
    ],
)
def test_port_constraints_are_preserved(kind, value, port):
    documents, _ = export([event([attribute(kind, value)])])
    assert documents[0]["unmapped"]["misp"]["port"] == port
    assert documents[0]["observables"][1]["type_id"] == 11
    assert documents[0]["observables"][1]["value"] == str(port)


def test_ids_are_stable_across_updates_distinct_across_sources_and_deduplicate():
    sources = [event([attribute()]), event([attribute()], uuid="event-2"), event([attribute(uuid="attribute-2")])]
    documents, _ = export(sources + [event([attribute(value="updated.example")])])
    assert len(documents) == 3
    assert len({d["metadata"]["uid"] for d in documents}) == 3
    assert documents[0]["osint"][0]["value"] == "updated.example"
    assert documents[0]["metadata"]["uid"] == export(sources)[0][0]["metadata"]["uid"]
    fallback = [event([attribute(uuid=None)], uuid=None, id=None)]
    assert export(fallback)[0][0]["metadata"]["uid"] == export(fallback)[0][0]["metadata"]["uid"]


@pytest.mark.parametrize(
    "tag,expected",
    [
        ("tlp:white", "WHITE"),
        ("tlp:clear", "CLEAR"),
        ("tlp:GREEN", "GREEN"),
        ("tlp:amber", "AMBER"),
        ("tlp:amber+strict", "AMBER STRICT"),
        ("tlp:red", "RED"),
    ],
)
def test_scoped_tags_and_most_restrictive_tlp(tag, expected):
    obj = {
        "name": "domain-ip",
        "Tag": [{"name": "object-tag"}],
        "Attribute": [attribute(Tag=[{"name": tag}], AttributeTag=[{"Tag": {"name": "attribute-tag"}}])],
    }
    documents, _ = export([event(objects=[obj], EventTag=[{"Tag": {"name": "tlp:white"}}])])
    indicator = documents[0]["osint"][0]
    assert indicator["tlp"] == expected
    assert indicator["labels"] == sorted({tag, "tlp:white", "object-tag", "attribute-tag"})


def test_collection_time_source_timestamp_and_provenance_have_distinct_meanings():
    before = int(datetime.now(timezone.utc).timestamp() * 1000)
    source = attribute(
        timestamp="2026-10-01T14:00:00+02:00",
        first_seen="2026-09-01T00:00:00Z",
        last_seen="2026-09-30T00:00:00Z",
        comment="Analyst\ncomment: é",
    )
    documents, _ = export(
        [event([source], Orgc={"name": "Example Org"}, threat_level_id="1")], {"misp_url": "https://misp.example/misp/"}
    )
    document = documents[0]
    indicator = document["osint"][0]
    assert before <= document["time"] <= int(datetime.now(timezone.utc).timestamp() * 1000)
    assert document["time"] == document["metadata"]["processed_time"]
    assert indicator["modified_time"] == 1790856000000
    assert indicator["src_url"] == "https://misp.example/misp/events/view/event-1"
    assert indicator["comment"] == source["comment"]
    assert indicator["confidence_id"] == 0
    assert document["severity_id"] == 1
    assert not {"created_time", "expiration_time", "tlp"} & indicator.keys()
    assert document["unmapped"]["misp"]["attribute"]["first_seen"] == source["first_seen"]
    assert document["unmapped"]["misp"]["attribute"]["last_seen"] == source["last_seen"]
    assert document["unmapped"]["misp"]["event"]["Orgc"]["name"] == "Example Org"


@pytest.mark.parametrize("timestamp", ["1792281600", 1792281600, "2026-10-18T00:00:00Z"])
def test_event_timestamp_is_modification_fallback(timestamp):
    documents, _ = export([event([attribute()], timestamp=timestamp)])
    assert documents[0]["osint"][0]["modified_time"] == 1792281600000


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-dst", "invalid"),
        ("ip-src", "2001:db8::1%eth0"),
        ("ip-dst", "192.0.2.0/24"),
        ("url", "relative/path"),
        ("url", "https://example.org:bad"),
        ("md5", "x" * 32),
        ("domain", ""),
        ("domain", None),
        ("domain|ip", "example.org|invalid"),
        ("domain|ip", "a|b|192.0.2.1"),
        ("filename|sha256", "no-separator"),
        ("ip-dst|port", "192.0.2.1|-1"),
        ("ip-dst|port", "192.0.2.1|65536"),
    ],
)
def test_malformed_values_are_skipped_without_losing_valid_records(kind, value):
    documents, response = export([event([attribute(kind, value), attribute(uuid="valid")])])
    assert len(documents) == 1
    assert response["warnings"] == ["Skipped 1 malformed attribute(s)."]


def test_invalid_timestamps_and_unsupported_types_report_counts():
    documents, response = export(
        [
            event(
                [
                    attribute(timestamp="2026-10-01T12:00:00"),
                    attribute("text", "context", uuid="text"),
                    attribute(uuid="bad-time", timestamp=True),
                ]
            )
        ]
    )
    assert len(documents) == 2
    assert all("modified_time" not in d["osint"][0] for d in documents)
    assert response["warnings"] == [
        "Skipped 2 invalid modification timestamp(s).",
        "Skipped 1 unsupported attribute(s).",
    ]


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"data": {}},
        {"data": [1]},
        {"data": [{"Event": "bad"}]},
        {"data": [{"Attribute": {}}]},
        {"data": [{"Object": [1]}]},
        {"data": [], "config": []},
        {"data": [], "config": {"include_non_ids": "maybe"}},
        *[
            {"data": [], "config": {"misp_url": url}}
            for url in (
                [],
                "invalid",
                "ftp://host",
                "https://u:p@host",
                "https://@host",
                "https://host/?q=x",
                "https://host/#fragment",
                "https://host:bad",
            )
        ],
    ],
)
def test_invalid_requests_return_errors(payload):
    response = ocsf.handler(json.dumps(payload))
    assert "error" in response
    assert "data" not in response


@pytest.mark.parametrize(
    "template,relation,value",
    [
        ("domain-ip", "domain", "example.org"),
        ("file", "sha256", "a" * 64),
        ("email", "from", "sender@example.org"),
    ],
)
def test_existing_misp_object_templates(template, relation, value):
    obj = MISPObject(template, strict=True)
    obj.add_attribute(relation, value=value, to_ids=True)
    obj._validate()
    documents, _ = export([event(objects=[json.loads(obj.to_json())])])
    assert documents[0]["unmapped"]["misp"]["object"]["uuid"] == obj.uuid


def test_contract_empty_input_and_legacy_repository_fixture():
    assert ocsf.handler() is False
    assert "error" in ocsf.handler("not json")
    assert ocsf.introspection()["outputFileExtension"] == "ndjson"
    assert ocsf.version()["module-type"] == ["export"]
    assert ocsf.version()["config"] == ["include_non_ids", "misp_url"]
    assert export([]) == ([], {"response": [], "data": ""})
    fixture = json.loads((ROOT / "tests/test_files/misp_event.json").read_text())
    assert export([fixture])[0] == []
    documents, response = export([fixture], {"include_non_ids": True})
    assert len(documents) == 1
    assert [indicator["value"] for indicator in documents[0]["osint"]] == ["google.com", "127.0.0.1"]
    assert response["warnings"] == ["Skipped 2 unsupported attribute(s)."]
    Draft7Validator.check_schema(SCHEMA)


class TestOCSFExportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous_handlers = service.MODULES_HANDLERS.copy()
        self.previous_cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"ocsf_export": ocsf, "type:ocsf_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous_handlers)
        service.ListModules.CACHE = self.previous_cache
        super().tearDown()

    def test_discovery_and_query(self):
        module = json.loads(self.fetch("/modules").body)[0]
        assert module["name"] == "ocsf_export"
        assert module["mispattributes"]["responseType"] == "application/x-ndjson"
        response = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "ocsf_export", "data": [event([attribute()])]}),
        )
        assert response.code == 200
        document = json.loads(base64.b64decode(json.loads(response.body)["data"]))
        VALIDATOR.validate(document)
        assert document["osint"][0]["value"] == "example.org"
