import base64
import copy
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import elastic_ecs_export as ecs

ROOT = Path(__file__).resolve().parent.parent
PROPERTIES = json.loads((ROOT / "documentation/export_mod/elastic_ecs_export_template.json").read_text())["template"][
    "mappings"
]["properties"]


def validate_mapping(document, properties):
    """Ensure every emitted field will be indexed with the template's intended type."""
    for name, value in document.items():
        assert name in properties, name
        mapping = properties[name]
        if "properties" in mapping:
            validate_mapping(value, mapping["properties"])
        elif mapping["type"] == "flattened":
            assert isinstance(value, dict)
        else:
            for item in value if isinstance(value, list) else [value]:
                if mapping["type"] == "long":
                    assert isinstance(item, int) and not isinstance(item, bool)
                elif mapping["type"] == "date":
                    assert datetime.fromisoformat(item.replace("Z", "+00:00")).tzinfo
                elif mapping["type"] == "ip":
                    assert ipaddress.ip_address(item)
                else:
                    assert mapping["type"] in ("keyword", "wildcard") and isinstance(item, str)


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
    response = ecs.handler(json.dumps({"data": data, "config": config}))
    assert "error" not in response, response
    payload = base64.b64decode(response["data"]).decode("utf-8")
    lines = [json.loads(line) for line in payload.splitlines()]
    assert len(lines) % 2 == 0
    assert not payload or payload.endswith("\n")
    for document in lines[1::2]:
        validate_mapping(document, PROPERTIES)
    return list(zip(lines[::2], lines[1::2])), response


def test_standard_legacy_bare_events_objects_and_provenance_are_not_mutated():
    obj = {
        "uuid": "object-1",
        "name": "domain-ip",
        "Tag": [{"name": "object-tag"}],
        "Attribute": [attribute("ip-dst", "2001:db8::1", object_relation="ip")],
    }
    bare = event(
        [attribute(comment='Evidence, "quoted"\nCafé')],
        [obj],
        Orgc={"name": "CERT Example"},
        Tag=[{"name": "tlp:amber"}],
    )
    legacy = {
        "Event": {k: v for k, v in bare.items() if k not in ("Attribute", "Object", "Tag", "Orgc")},
        "Attribute": bare["Attribute"],
        "Object": bare["Object"],
        "Orgc": bare["Orgc"],
        "EventTag": [{"Tag": {"name": "tlp:amber"}}],
    }
    original = copy.deepcopy([bare, legacy])
    results = [export([value])[0] for value in (bare, {"Event": bare}, legacy)]
    for pairs in results:
        assert len(pairs) == 2
        assert pairs[0][1]["threat"]["indicator"]["description"] == 'Evidence, "quoted"\nCafé'
        doc = pairs[1][1]
        assert doc["misp"]["object"] == {"uuid": "object-1", "name": "domain-ip"}
        assert doc["misp"]["attribute"]["object_relation"] == "ip"
        assert doc["misp"]["event"]["uuid"] == "event-1"
        assert doc["threat"]["indicator"]["provider"] == "CERT Example"
        assert doc["tags"] == ["object-tag", "tlp:amber"]
    assert [[pair[0] for pair in pairs] for pairs in results] == [[pair[0] for pair in results[0]]] * 3
    assert [bare, legacy] == original


@pytest.mark.parametrize(
    "kind,value,indicator_type,expected",
    [
        ("ip-src", "192.0.2.1", "ipv4-addr", {"ip": "192.0.2.1"}),
        ("ip-dst", "2001:0DB8:0000::1", "ipv6-addr", {"ip": "2001:db8::1"}),
        ("domain", "example.org", "domain-name", {"url": {"domain": "example.org"}}),
        ("hostname", "host.example.org", "domain-name", {"url": {"domain": "host.example.org"}}),
        (
            "url",
            "https://example.org:8443/a?b=c",
            "url",
            {
                "url": {
                    "full": "https://example.org:8443/a?b=c",
                    "domain": "example.org",
                    "scheme": "https",
                    "port": 8443,
                }
            },
        ),
        ("email-src", "sender@example.org", "email-addr", {"email": {"address": "sender@example.org"}}),
        ("email-dst", "recipient@example.org", "email-addr", {"email": {"address": "recipient@example.org"}}),
        ("filename", "O'Brien.exe", "file", {"file": {"name": "O'Brien.exe"}}),
        ("md5", "A" * 32, "file", {"file": {"hash": {"md5": "a" * 32}}}),
        ("sha1", "A" * 40, "file", {"file": {"hash": {"sha1": "a" * 40}}}),
        ("sha256", "A" * 64, "file", {"file": {"hash": {"sha256": "a" * 64}}}),
        ("sha384", "A" * 96, "file", {"file": {"hash": {"sha384": "a" * 96}}}),
        ("sha512", "A" * 128, "file", {"file": {"hash": {"sha512": "a" * 128}}}),
        ("AS", "AS64500", "autonomous-system", {"as": {"number": 64500}}),
    ],
)
def test_simple_indicators_map_to_ecs_fields(kind, value, indicator_type, expected):
    pairs, _ = export([event([attribute(kind, value)])])
    indicator = pairs[0][1]["threat"]["indicator"]
    assert indicator["type"] == indicator_type
    for key, expected_value in expected.items():
        assert indicator[key] == expected_value
    assert pairs[0][1]["misp"]["attribute"]["value"] == value


@pytest.mark.parametrize(
    "kind,value",
    [
        ("filename|md5", "a|b.exe|" + "a" * 32),
        ("filename|sha1", "a|b.exe|" + "a" * 40),
        ("filename|sha256", "a|b.exe|" + "a" * 64),
        ("filename|sha384", "a|b.exe|" + "a" * 96),
        ("filename|sha512", "a|b.exe|" + "a" * 128),
        ("malware-sample", "a|b.exe|" + "a" * 32),
    ],
)
def test_file_composites_keep_name_and_hash_in_the_same_indicator(kind, value):
    pairs, _ = export([event([attribute(kind, value)])])
    assert len(pairs) == 1
    indicator = pairs[0][1]["threat"]["indicator"]
    assert indicator["file"]["name"] == "a|b.exe"
    assert len(indicator["file"]["hash"]) == 1
    assert pairs[0][1]["misp"]["attribute"]["value"] == value


def test_domain_ip_creates_two_typed_indicators_with_shared_source_uuid():
    pairs, _ = export([event([attribute("domain|ip", "example.org|2001:db8::1")])])
    assert [doc["threat"]["indicator"]["type"] for _, doc in pairs] == ["domain-name", "ipv6-addr"]
    assert len({action["index"]["_id"] for action, _ in pairs}) == 2
    assert all(doc["misp"]["attribute"]["uuid"] == "attribute-1" for _, doc in pairs)


@pytest.mark.parametrize(
    "kind,value,port",
    [
        ("ip-src|port", "2001:db8::1|443", 443),
        ("ip-dst|port", "192.0.2.1|0", 0),
        ("hostname|port", "host.example.org|65535", 65535),
    ],
)
def test_composite_ports_are_integers(kind, value, port):
    pairs, _ = export([event([attribute(kind, value)])])
    assert pairs[0][1]["threat"]["indicator"]["port"] == port


def test_bulk_ids_are_stable_across_updates_and_distinct_across_sources():
    first = event([attribute()])
    pairs, _ = export(
        [first, first, event([attribute()], uuid="event-2"), event([attribute(uuid="attribute-2")])],
        {"index": "custom-indicators"},
    )
    assert len(pairs) == 3
    assert len({action["index"]["_id"] for action, _ in pairs}) == 3
    for action, doc in pairs:
        assert action["index"]["_index"] == "custom-indicators"
        assert action["index"]["_id"] == doc["event"]["id"]
    changed, _ = export([event([attribute(value="changed.example", comment="Updated")])])
    assert changed[0][0]["index"]["_id"] == pairs[0][0]["index"]["_id"]
    fallback = event([attribute(uuid=None)], uuid=None)
    assert export([fallback])[0][0][0] == export([fallback])[0][0][0]


def test_duplicate_source_uses_last_document_and_timestamp_is_export_time():
    start = datetime.now(timezone.utc)
    pairs, _ = export([event([attribute()]), event([attribute(value="updated.example")])])
    end = datetime.now(timezone.utc)
    assert len(pairs) == 1
    doc = pairs[0][1]
    timestamp = datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00"))
    assert start.timestamp() - 0.001 <= timestamp.timestamp() <= end.timestamp()
    assert doc["threat"]["indicator"]["url"]["domain"] == "updated.example"
    assert doc["event"]["kind"] == "enrichment"
    assert doc["event"]["category"] == ["threat"]
    assert doc["event"]["type"] == ["indicator"]


@pytest.mark.parametrize(
    "tags,tlp,version",
    [
        (["tlp:white"], "WHITE", "1.0"),
        (["tlp:clear"], "CLEAR", "2.0"),
        (["tlp:green"], "GREEN", None),
        (["tlp:amber"], "AMBER", None),
        (["tlp:amber+strict"], "AMBER+STRICT", "2.0"),
        (["tlp:green", "tlp:RED"], "RED", None),
    ],
)
def test_most_restrictive_scoped_tlp_is_preserved(tags, tlp, version):
    source = attribute(Tag=[{"name": tag} for tag in tags])
    pairs, _ = export([event([source], Tag=[{"name": "tlp:white"}])])
    marking = pairs[0][1]["threat"]["indicator"]["marking"]
    assert marking["tlp"] == tlp
    assert marking.get("tlp_version") == version


def test_confidence_is_not_inferred_from_threat_level_or_unrecognized_tags():
    pairs, _ = export([event([attribute()], threat_level_id="1", Tag=[{"name": "confidence:high"}])])
    indicator = pairs[0][1]["threat"]["indicator"]
    assert indicator["confidence"] == "Not Specified"
    assert "marking" not in indicator
    assert pairs[0][1]["tags"] == ["confidence:high"]


def test_observation_dates_modified_at_and_reference_preserve_source_semantics():
    pairs, _ = export(
        [event([attribute(first_seen="2026-10-01T14:00:00+02:00", last_seen="2026-10-02T12:00:00Z")])],
        {"misp_url": "https://misp.example/misp/"},
    )
    indicator = pairs[0][1]["threat"]["indicator"]
    assert indicator["first_seen"] == "2026-10-01T12:00:00.000Z"
    assert indicator["last_seen"] == "2026-10-02T12:00:00.000Z"
    assert indicator["modified_at"] == "2026-10-18T00:00:00.000Z"
    assert indicator["reference"] == "https://misp.example/misp/events/view/event-1"
    assert "valid_until" not in indicator


@pytest.mark.parametrize("value", ["not-a-date", "2026-10-18T12:00:00", {}, True, 10**100])
def test_invalid_observation_time_does_not_drop_valid_indicator(value):
    pairs, response = export([event([attribute(first_seen=value)])])
    assert len(pairs) == 1
    assert "first_seen" not in pairs[0][1]["threat"]["indicator"]
    assert response["warnings"] == ["Skipped 1 invalid timestamp field(s)."]


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-dst", "192.0.2.0/24"),
        ("ip-dst", "not-an-ip"),
        ("ip-src", "fe80::1%eth0"),
        ("ip-dst|port", "192.0.2.1|65536"),
        ("ip-src|port", "192.0.2.1|-1"),
        ("domain|ip", "example.org|"),
        ("domain|ip", "a|b|192.0.2.1"),
        ("md5", "a" * 31),
        ("sha256", "g" * 64),
        ("AS", "AS4294967296"),
        ("url", "example.org/a"),
        ("url", "https://example.org:bad/"),
        ("domain", ""),
        ("domain", None),
    ],
)
def test_malformed_attributes_are_reported_without_losing_good_indicators(kind, value):
    pairs, response = export([event([attribute(kind, value), attribute()])])
    assert len(pairs) == 1
    assert response["warnings"] == ["Skipped 1 malformed attribute(s)."]


@pytest.mark.parametrize("flag", [False, 0, "false", "0", "", None, True, 1, "true", "1"])
def test_non_ids_filter_and_deleted_data(flag):
    pairs, _ = export(
        [
            event(
                [attribute(to_ids="0"), attribute(value="deleted", deleted="1")],
                [{"deleted": True, "Attribute": [attribute()]}],
            ),
            event([attribute()], deleted=True),
        ],
        {"include_non_ids": flag},
    )
    assert len(pairs) == (1 if flag in (True, 1, "true", "1") else 0)


@pytest.mark.parametrize(
    "template,relation,value",
    [
        ("domain-ip", "domain", "example.org"),
        ("file", "sha256", "a" * 64),
        ("email", "from", "sender@example.org"),
    ],
)
def test_existing_misp_object_templates_are_sufficient(template, relation, value):
    obj = MISPObject(template, strict=True)
    obj.add_attribute(relation, value=value, to_ids=True)
    obj._validate()
    pairs, _ = export([event(objects=[json.loads(obj.to_json())])])
    assert pairs[0][1]["misp"]["object"]["uuid"] == obj.uuid


def test_legacy_repository_fixture_empty_and_unsupported_inputs():
    fixture = json.loads((ROOT / "tests/test_files/misp_event.json").read_text())
    assert export([fixture])[0] == []
    pairs, response = export([fixture], {"include_non_ids": True})
    assert len(pairs) == 2
    assert response["warnings"] == ["Skipped 2 unsupported attribute(s)."]
    assert export([])[0] == []


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
        {"data": [], "config": {"index": False}},
        {"data": [], "config": {"misp_url": []}},
        {"data": [], "config": {"include_non_ids": "maybe"}},
        *[{"data": [], "config": {"index": name}} for name in ("Upper", "_hidden", "a/b", "a*", "x" * 256)],
        *[
            {"data": [], "config": {"misp_url": url}}
            for url in ("invalid", "ftp://host", "https://u:p@host", "https://host/?q=x")
        ],
    ],
)
def test_invalid_requests_are_errors(payload):
    assert "error" in ecs.handler(json.dumps(payload))


@pytest.mark.parametrize("userinfo", ["user:password", ":password", "user", "user:", "", ":"])
def test_misp_url_rejects_all_userinfo_without_exporting_credentials(userinfo):
    response = ecs.handler(
        json.dumps({"data": [event([attribute()])], "config": {"misp_url": f"https://{userinfo}@misp.example"}})
    )
    assert response == {
        "error": "Elastic ECS export: misp_url must be an HTTP(S) base URL without credentials, query or fragment."
    }


def test_template_bounds_all_string_terms():
    def check(properties):
        for mapping in properties.values():
            if "properties" in mapping:
                check(mapping["properties"])
            elif mapping["type"] in ("keyword", "wildcard", "flattened"):
                # Reserve room for flattened key prefixes even with four-byte UTF-8 characters.
                assert 0 < mapping.get("ignore_above", 0) <= 4096

    check(PROPERTIES)


@pytest.mark.parametrize("text", ["x" * 40000, "\U0001f600" * 9000], ids=["ascii", "unicode"])
def test_oversized_metadata_remains_in_source_with_bounded_index_terms(text):
    assert len(text.encode("utf-8")) > 32766
    url = "https://example.org/" + text
    pairs, _ = export([event([attribute("url", url, comment=text, Tag=[{"name": text}])], info=text)])
    document = pairs[0][1]
    assert document["threat"]["indicator"]["url"]["full"] == url
    assert document["threat"]["indicator"]["description"] == text
    assert document["tags"] == [text]
    assert document["misp"]["event"]["info"] == text
    assert document["misp"]["attribute"]["comment"] == text


def test_handler_contract_and_template_field_types():
    assert ecs.handler() is False
    assert "error" in ecs.handler("not json")
    assert ecs.introspection()["outputFileExtension"] == "ndjson"
    assert ecs.version()["module-type"] == ["export"]
    template = json.loads((ROOT / "documentation/export_mod/elastic_ecs_export_template.json").read_text())
    properties = template["template"]["mappings"]["properties"]
    assert properties["misp"]["type"] == "flattened"
    indicator = properties["threat"]["properties"]["indicator"]["properties"]
    assert indicator["ip"]["type"] == "ip"
    assert indicator["port"]["type"] == "long"
    assert indicator["first_seen"]["type"] == "date"
    assert indicator["url"]["properties"]["full"]["type"] == "wildcard"


class TestElasticECSExportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous_handlers = service.MODULES_HANDLERS.copy()
        self.previous_cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"elastic_ecs_export": ecs, "type:elastic_ecs_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous_handlers)
        service.ListModules.CACHE = self.previous_cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "elastic_ecs_export"
        response = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "elastic_ecs_export", "data": [event([attribute("ip-dst", "192.0.2.1")])]}),
        )
        assert response.code == 200
        lines = base64.b64decode(json.loads(response.body)["data"]).decode().splitlines()
        assert json.loads(lines[0])["index"]["_index"] == "misp-indicators"
        assert ipaddress.ip_address(json.loads(lines[1])["threat"]["indicator"]["ip"]).version == 4
