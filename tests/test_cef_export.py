import base64
import copy
import json
import re

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import cef_export as export


def attribute(kind="ip-dst", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "category": "Network activity", "timestamp": "1700000000", **metadata}


def run(attributes, config=None):
    query = {"data": [{"Attribute": attributes}]}
    if config is not None:
        query["config"] = config
    result = export.handler(json.dumps(query))
    assert "error" not in result, result
    assert result["response"] == []
    return base64.b64decode(result["data"], validate=True).decode("utf-8")


def unescape(value):
    return re.sub(r"\\(.)", lambda match: {"n": "\n", "r": "\r"}.get(match[1], match[1]), value)


def parse(line):
    """Read escaped header delimiters and space-separated extension keys independently."""
    fields = []
    start, escaped = 0, False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|":
            fields.append(unescape(line[start:index]))
            start = index + 1
            if len(fields) == 7:
                break
    assert len(fields) == 7
    extension = line[start:].removesuffix("\n")
    keys = list(re.finditer(r"(?:^| )([A-Za-z0-9]+)=", extension))
    values = {}
    for index, match in enumerate(keys):
        end = keys[index + 1].start() if index + 1 < len(keys) else len(extension)
        assert match[1] not in values
        values[match[1]] = unescape(extension[match.end() : end])
    return fields, values


def test_file_record_and_timestamp_units():
    assert (
        run([attribute()])
        == "CEF:0|MISP|MISP|1|ip-dst|Network activity|1|dst=192.0.2.1 cat=Network activity "
        "deviceCustomDate1=1700000000000 deviceCustomDate1Label=MISP attribute timestamp\n"
    )


@pytest.mark.parametrize(
    "kind,value,key,version,expected",
    [
        ("ip-src", "192.0.2.2", "src", "CEF:0", "192.0.2.2"),
        ("ip-dst", "192.0.2.1", "dst", "CEF:0", "192.0.2.1"),
        ("ip-src", "2001:0DB8::1", "src", "CEF:1", "2001:db8::1"),
        ("ip-dst", "2001:db8::2", "dst", "CEF:1", "2001:db8::2"),
        ("hostname", "host.example.org", "dhost", "CEF:0", "host.example.org"),
        ("domain", "example.org", "dhost", "CEF:0", "example.org"),
        ("md5", "a" * 32, "fileHash", "CEF:0", "a" * 32),
        ("sha1", "b" * 40, "fileHash", "CEF:0", "b" * 40),
        ("sha256", "c" * 64, "fileHash", "CEF:0", "c" * 64),
        ("url", "https://example.org/?a=1&b=2", "request", "CEF:0", "https://example.org/?a=1&b=2"),
    ],
)
def test_mapping_and_ip_version(kind, value, key, version, expected):
    header, extension = parse(run([attribute(kind, value)]))
    assert header == [version, "MISP", "MISP", "1", kind, "Network activity", "1"]
    assert extension[key] == expected


def test_escaping_round_trip_and_record_injection():
    device = "MïSP | vendor\\=name"
    category = "Network | activity\\=data"
    value = "https://example.org/é?q=1\\2|three spaces dst=1.1.1.1\r\nCEF:0|fake"
    text = run([attribute("url", value, category=category)], {"Device_Vendor": device})
    assert text.count("\n") == 1 and "\r" not in text
    assert r"q\=1\\2|three spaces dst\=1.1.1.1\r\nCEF:0|fake" in text
    header, extension = parse(text)
    assert header[1] == device and header[5] == category
    assert extension == {
        "request": value,
        "cat": category,
        "deviceCustomDate1": "1700000000000",
        "deviceCustomDate1Label": "MISP attribute timestamp",
    }


@pytest.mark.parametrize(
    "severity", [*range(11), *map(str, range(11)), "Unknown", "Low", "Medium", "High", "Very-High"]
)
def test_valid_severity(severity):
    assert parse(run([attribute()], {"Default_Severity": severity}))[0][6] == str(severity)


@pytest.mark.parametrize(
    "severity", [-1, 11, "11", "-1", 1.5, 1.0, True, False, None, "", "critical", "low", "1|bad", "1\n", "１"]
)
def test_invalid_severity_returns_error(severity):
    result = export.handler(json.dumps({"data": [], "config": {"Default_Severity": severity}}))
    assert "Default_Severity" in result["error"] and "data" not in result


@pytest.mark.parametrize("key,limit", [("Device_Vendor", 63), ("Device_Product", 63), ("Device_Version", 31)])
def test_header_field_limits(key, limit):
    assert run([attribute()], {key: "é" * limit})
    for value in ("x" * (limit + 1), "", " ", "bad\nheader", "bad\rheader", "bad\x00header", None, True, [], "\ud800"):
        result = export.handler(json.dumps({"data": [], "config": {key: value}}))
        assert "error" in result and "data" not in result


@pytest.mark.parametrize(
    "metadata",
    [
        {"category": "bad\nheader"},
        {"category": "bad\rheader"},
        {"category": "x" * 513},
        {"category": 123},
        {"value": ""},
        {"value": None},
        {"value": 123},
        {"value": "999.1.2.3"},
        {"value": "192.0.2.0/24"},
        {"value": "2001:db8::/32"},
        {"value": "fe80::1%eth0"},
        {"timestamp": -1},
        {"timestamp": "1.5"},
        {"timestamp": 1.5},
        {"timestamp": True},
        {"timestamp": "１２３"},
        {"timestamp": None},
    ],
)
def test_invalid_attributes_do_not_return_partial_files(metadata):
    result = export.handler(json.dumps({"data": [{"Attribute": [attribute(), attribute(**metadata)]}]}))
    assert "error" in result and "data" not in result


@pytest.mark.parametrize("kind,limit", [("domain", 1023), ("url", 1023), ("md5", 255)])
def test_extension_string_limits_and_invalid_characters(kind, limit):
    assert parse(run([attribute(kind, "é" * limit)]))[1][export.cefmapping[kind]] == "é" * limit
    for value in ("a" * (limit + 1), "bad\x00value", "bad\x7fvalue", "bad\ud800value"):
        result = export.handler(json.dumps({"data": [{"Attribute": [attribute(kind, value)]}]}))
        assert "error" in result and "data" not in result


def test_event_shapes_objects_and_input_preservation():
    data = [
        {"Event": {"Attribute": [attribute()]}},
        {"Object": [{"Attribute": [attribute("ip-src", "2001:db8::1")]}]},
        {"Event": {"id": "42"}, "Attribute": [attribute("domain", "example.org")]},
        {"Event": {"id": "43"}, "Object": [{"Attribute": [attribute("sha1", "a" * 40)]}]},
    ]
    original = copy.deepcopy(data)
    result = export.handler(json.dumps({"data": data}))
    lines = base64.b64decode(result["data"]).decode().splitlines()
    assert [parse(line)[0][4] for line in lines] == ["ip-dst", "ip-src", "domain", "sha1"]
    assert data == original


def test_defaults_empty_events_unsupported_types_and_optional_metadata():
    assert export.handler() is False
    for data in ([], {}, {"Event": {}}, [{"Attribute": []}]):
        assert export.handler(json.dumps({"data": data}))["data"] == ""
    assert run([attribute()], {}) == run([attribute()])
    text = run([attribute("unsupported", "anything"), {"type": "domain", "value": "example.org", "to_ids": False}])
    assert parse(text) == (
        ["CEF:0", "MISP", "MISP", "1", "domain", "domain", "1"],
        {"dhost": "example.org", "cat": "domain"},
    )
    assert parse(run([attribute(timestamp=0)]))[1]["deviceCustomDate1"] == "0"


@pytest.mark.parametrize(
    "query",
    [
        "{",
        "null",
        "[]",
        "{}",
        {"data": None},
        {"data": [1]},
        {"data": {"Event": []}},
        {"data": {"Attribute": {}}},
        {"data": {"Attribute": [1]}},
        {"data": {"Object": [1]}},
        {"data": {"Object": [{"Attribute": [1]}]}},
        {"data": [], "config": None},
    ],
)
def test_invalid_requests_return_module_errors(query):
    result = export.handler(query if isinstance(query, str) else json.dumps(query))
    assert "error" in result and "data" not in result


class TestCEFHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"cef_export": export, "type:cef_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_export(self):
        response = self.fetch("/modules")
        descriptor = json.loads(response.body)[0]
        assert descriptor["meta"]["config"] == export.moduleconfig
        assert descriptor["mispattributes"] == {
            "input": list(export.cefmapping),
            "inputSource": ["event", "event-collection"],
            "outputFileExtension": "cef",
            "responseType": "text/plain",
        }
        response = self.fetch(
            "/query",
            method="POST",
            body=json.dumps({"module": "cef_export", "data": {"Event": {"Attribute": [attribute()]}}}),
        )
        assert response.code == 200
        assert base64.b64decode(json.loads(response.body)["data"]).decode() == run([attribute()])
