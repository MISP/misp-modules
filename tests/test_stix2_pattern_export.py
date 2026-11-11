import base64
import json
from unittest.mock import patch

import pytest
from pymisp import MISPEvent, MISPObject
from stix2patterns.v21.pattern import Pattern
from stix2patterns.validator import run_validator
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.modules.export_mod import stix2_pattern_export as module

STORED = "[domain-name:value = 'example.org' OR domain-name:value = 'example.net']"


def attribute(kind="domain", value="example.org", **metadata):
    return {"type": kind, "value": value, "to_ids": True, **metadata}


def export(data):
    result = module.handler(json.dumps({"data": data}))
    assert "error" not in result, result
    patterns = json.loads(base64.b64decode(result["data"], validate=True))
    assert all(not run_validator(pattern, stix_version="2.1") for pattern in patterns)
    return patterns, result


def test_discovery():
    assert module.handler() is False
    assert module.introspection()["inputSource"] == ["event", "event-collection"]
    assert module.introspection()["responseType"] == "application/json"
    assert module.introspection()["outputFileExtension"] == "json"
    assert module.version()["module-type"] == ["export"]


@pytest.mark.parametrize("shape", ["bare", "standard", "legacy"])
def test_export_envelopes_and_objects(shape):
    attributes = [attribute()]
    objects = [{"name": "file", "Attribute": [attribute("sha256", "a" * 64)]}]
    event = {"info": "Example", "Attribute": attributes, "Object": objects}
    data = event if shape == "bare" else {"Event": event}
    if shape == "legacy":
        data = {"Event": {"info": "Example"}, "Attribute": attributes, "Object": objects}
    patterns, result = export([data])
    assert len(patterns) == 2
    assert "[domain-name:value = 'example.org']" in patterns
    assert result["summary"]["generated_attributes"] == 2


def test_real_pymisp_event_and_object():
    event = MISPEvent()
    event.info = "Example"
    event.add_attribute("domain", "example.org")
    obj = MISPObject("file")
    obj.add_attribute("sha256", "a" * 64)
    event.add_object(obj)
    patterns, _ = export(json.loads(event.to_json()))
    assert len(patterns) == 2


def test_stored_patterns_are_validated_whole_and_exported_without_ids():
    patterns, result = export({"Attribute": [attribute("stix2-pattern", STORED, to_ids=False)]})
    assert patterns == [STORED]
    assert result["summary"]["stored_attributes"] == 1


def test_complex_stored_pattern_keeps_operators_and_qualifiers():
    pattern = "([domain-name:value = 'example.org'] FOLLOWEDBY [file:name = 'test.exe']) WITHIN 60 SECONDS"
    patterns, _ = export({"Attribute": [attribute("stix2-pattern", pattern)]})
    assert patterns == [pattern]


def test_multiline_stored_pattern_is_preserved_exactly():
    pattern = "[domain-name:value = 'example.org'\n OR domain-name:value = 'example.net']"
    patterns, _ = export({"Attribute": [attribute("stix2-pattern", pattern)]})
    assert patterns == [pattern]


def test_composites_are_not_split_into_independent_patterns():
    patterns, _ = export(
        {
            "Attribute": [
                attribute("filename|sha256", "test.exe|" + "a" * 64),
                attribute("ip-dst|port", "2001:db8::1|443"),
            ]
        }
    )
    assert len(patterns) == 2
    file_comparisons = next(Pattern(p).inspect().comparisons["file"] for p in patterns if "file:name" in p)
    assert len(file_comparisons) == 2
    traffic = next(Pattern(p).inspect().comparisons["network-traffic"] for p in patterns if "network-traffic" in p)
    assert (["dst_ref", "value"], "=", "'2001:db8::1'") in traffic
    assert (["dst_port"], "=", "'443'") in traffic


def test_literals_are_escaped_by_upstream_mapping():
    patterns, _ = export({"Attribute": [attribute("filename", r"C:\O'Brien\test.exe' OR file:name = 'other")]})
    assert len(Pattern(patterns[0]).inspect().comparisons["file"]) == 1


@pytest.mark.parametrize("false", [False, 0, "0", "false", None])
def test_non_ids_is_skipped(false):
    patterns, result = export(
        {"Attribute": [attribute(to_ids=false), attribute("stix2-pattern", STORED, to_ids=false)]}
    )
    assert patterns == [STORED]
    assert result["summary"]["skipped"] == {"non-IDS": 1}


@pytest.mark.parametrize("true", [True, 1, "1", "true"])
def test_ids_and_deleted_flags(true):
    data = [
        {"deleted": true, "Attribute": [attribute("domain", "deleted-event.example")]},
        {"Object": [{"deleted": true, "Attribute": [attribute("domain", "deleted-object.example")]}]},
        {"Attribute": [attribute("domain", "deleted-attribute.example", deleted=true), attribute(to_ids=true)]},
    ]
    patterns, _ = export(data)
    assert patterns == ["[domain-name:value = 'example.org']"]


def test_multiple_events_deduplicate_and_sort_deterministically():
    data = [
        {"Attribute": [attribute(), attribute("domain", "example.net")]},
        {"Attribute": [attribute(), attribute("stix2-pattern", STORED)]},
    ]
    patterns, result = export(data)
    assert len(patterns) == 3
    assert patterns == sorted(patterns)
    assert export(list(reversed(data)))[1]["data"] == result["data"]


@pytest.mark.parametrize(
    "bad",
    [
        attribute("sha256", "bad"),
        attribute("filename|sha256", "missing separator"),
        attribute("domain|ip", "example.org"),
        attribute("ip-dst|port", "192.0.2.1|65536"),
        attribute("stix2-pattern", "[domain-name:value = 'example.org'] trailing garbage"),
        attribute("yara", "rule x { condition: true }"),
        attribute("text", "context"),
        attribute("domain", None),
    ],
)
def test_unusable_conversion_is_reported_and_valid_patterns_survive(bad):
    patterns, result = export({"Attribute": [attribute(), bad]})
    assert patterns == ["[domain-name:value = 'example.org']"]
    assert result["summary"]["skipped"] == {"invalid or unsupported conversion": 1}
    assert result["warnings"]
    failed = module.handler(json.dumps({"data": {"Attribute": [bad]}}))
    assert "error" in failed and "data" not in failed


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"data": None},
        {"data": []},
        {"data": [1]},
        {"data": {"Event": []}},
        {"data": {"Attribute": {}}},
        {"data": {"Object": [None]}},
        {"data": {"Attribute": [None]}},
    ],
)
def test_invalid_input_returns_error(payload):
    assert "error" in module.handler(json.dumps(payload))


def test_invalid_json():
    assert "error" in module.handler("{")


class TestSTIX2PatternExportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        handlers = {"stix2_pattern_export": module, "type:stix2_pattern_export": "export_mod"}
        self.handlers_patch = patch.object(server, "MODULES_HANDLERS", handlers)
        self.handlers_patch.start()
        self.addCleanup(self.handlers_patch.stop)
        return Application([(r"/query", server.QueryModule), (r"/modules", server.ListModules)])

    def test_discovery_and_export(self):
        discovery = json.loads(self.fetch("/modules").body)
        assert discovery[0]["name"] == "stix2_pattern_export"
        query = {"module": "stix2_pattern_export", "data": {"Attribute": [attribute()]}}
        response = self.fetch("/query", method="POST", body=json.dumps(query))
        assert response.code == 200
        result = json.loads(response.body)
        assert json.loads(base64.b64decode(result["data"])) == ["[domain-name:value = 'example.org']"]
