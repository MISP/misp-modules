import base64
import copy
import json
import shutil
import subprocess

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import pf_export as export


def attribute(kind="ip-dst", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "to_ids": True, **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"Attribute": attributes or [], "Object": objects or [], **metadata}


def run(data, **config):
    result = export.handler(json.dumps({"data": data, "config": config}))
    assert "error" not in result, result
    text = base64.b64decode(result["data"], validate=True).decode("ascii")
    return [line for line in text.splitlines() if not line.startswith("#")], result


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("ip-src", "192.0.2.1", ["block drop quick inet from 192.0.2.1 to any"]),
        ("ip-dst", "2001:0DB8::1", ["block drop quick inet6 from any to 2001:db8::1"]),
        ("ip-src", "192.0.2.7/24", ["block drop quick inet from 192.0.2.0/24 to any"]),
        ("ip-dst", "2001:db8:1::42/48", ["block drop quick inet6 from any to 2001:db8:1::/48"]),
        (
            "ip-src|port",
            "192.0.2.1|00443",
            ["block drop quick inet proto { tcp, udp } from 192.0.2.1 port = 443 to any"],
        ),
        (
            "ip-dst|port",
            "2001:db8::1|65535",
            ["block drop quick inet6 proto { tcp, udp } from any to 2001:db8::1 port = 65535"],
        ),
        (
            "ip-dst|port",
            "192.0.2.0/24|80",
            ["block drop quick inet proto { tcp, udp } from any to 192.0.2.0/24 port = 80"],
        ),
        (
            "domain",
            "EXAMPLE.org.",
            ["block drop quick from any to example.org", "block drop quick from example.org to any"],
        ),
        (
            "hostname",
            "bücher.example",
            [
                "block drop quick from any to xn--bcher-kva.example",
                "block drop quick from xn--bcher-kva.example to any",
            ],
        ),
        (
            "domain|ip",
            "example.org|192.0.2.1",
            ["block drop quick inet from 192.0.2.1 to any", "block drop quick inet from any to 192.0.2.1"],
        ),
        (
            "domain|ip",
            "example.org|2001:db8::1",
            ["block drop quick inet6 from 2001:db8::1 to any", "block drop quick inet6 from any to 2001:db8::1"],
        ),
        (
            "hostname|port",
            "EXAMPLE.org.|443",
            ["block drop quick proto { tcp, udp } from any to example.org port = 443"],
        ),
        ("port", "53", ["block drop quick proto { tcp, udp } from any to any port = 53"]),
        ("port", "0", ["block drop quick proto { tcp, udp } from any to any port = 0"]),
    ],
)
@pytest.mark.parametrize("mode", ["block", "log"])
def test_supported_types_preserve_address_family_direction_and_port(kind, value, expected, mode):
    rules, result = run(event([attribute(kind, value)]), mode=mode)
    if mode == "log":
        expected = [rule.replace("block drop quick", "match log (all)", 1) for rule in expected]
    assert rules == expected
    assert result["summary"] == {"count": len(expected), "skipped": {}}


@pytest.mark.parametrize("config", [None, {}, {"mode": None}, {"mode": ""}, {"mode": "block"}])
def test_unset_or_block_mode_keeps_blocking_default(config):
    result = export.handler(json.dumps({"data": event([attribute()]), "config": config}))
    assert "error" not in result
    assert base64.b64decode(result["data"]).splitlines()[1:] == [b"block drop quick inet from any to 192.0.2.1"]


@pytest.mark.parametrize("mode", ["pass", "LOG", "log\npass all", True, False, 0, 1, [], {}])
def test_invalid_mode_returns_error_without_rules(mode):
    result = export.handler(json.dumps({"data": event([attribute()]), "config": {"mode": mode}}))
    assert result == {"error": "OpenBSD PF export: mode must be block or log."}


@pytest.mark.parametrize("config", [True, "log", [], 1])
def test_invalid_config_returns_error_without_rules(config):
    result = export.handler(json.dumps({"data": event([attribute()]), "config": config}))
    assert result == {"error": "OpenBSD PF export: config must be an object."}


def test_logging_preserves_ids_filtering_deletion_and_deduplication():
    rules, result = run(event([attribute(), attribute(), attribute(to_ids=False), attribute(deleted=True)]), mode="log")
    assert rules == ["match log (all) inet from any to 192.0.2.1"]
    assert result["summary"] == {"count": 1, "skipped": {"non-IDS": 1, "deleted": 1}}


def test_all_event_shapes_objects_deduplication_and_no_mutation():
    obj = MISPObject("domain-ip", strict=True)
    obj.add_attribute("ip", value="192.0.2.1", to_ids=True)
    obj._validate()
    data = [
        {"Event": event([attribute()])},
        event(objects=[json.loads(obj.to_json())]),
        {"Event": {"id": "42"}, "Attribute": [attribute(value="192.0.2.2")]},
        {"Event": {"id": "43"}, "Object": [{"Attribute": [attribute(value="192.0.2.3")]}]},
    ]
    original = copy.deepcopy(data)
    rules, result = run(data)
    assert rules == [f"block drop quick inet from any to 192.0.2.{i}" for i in range(1, 4)]
    assert result["summary"]["count"] == 3
    assert data == original
    assert run(list(reversed(data)))[0] == rules


@pytest.mark.parametrize("flag", [True, 1, "1", "true", "TRUE"])
def test_true_ids_representations(flag):
    assert len(run(event([attribute(to_ids=flag)]))[0]) == 1


@pytest.mark.parametrize("flag", [False, 0, "0", "false", "FALSE", None, ""])
def test_false_ids_representations(flag):
    rules, result = run(event([attribute(to_ids=flag)]))
    assert not rules and result["summary"]["skipped"] == {"non-IDS": 1}


def test_missing_ids_and_deleted_event_object_and_attribute_are_excluded():
    missing = attribute()
    del missing["to_ids"]
    data = [
        event([attribute(deleted="true"), missing]),
        event([attribute()], deleted="1"),
        event(objects=[{"deleted": True, "Attribute": [attribute()]}]),
    ]
    rules, result = run(data)
    assert rules == []
    assert result["summary"]["skipped"] == {"deleted": 1, "non-IDS": 1}


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-src", "any"),
        ("ip-dst", "self"),
        ("ip-dst", "192.0.2.1\npass all"),
        ("ip-dst", "192.0.2.1 # comment"),
        ("ip-dst", "999.1.2.3"),
        ("ip-dst", "192.0.2.1/33"),
        ("ip-dst", "2001:db8::1/129"),
        ("ip-dst", "fe80::1%em0"),
        ("domain", "example.org\npass all"),
        ("domain", "example.org\x00"),
        ("domain", "bad..example"),
        ("domain", "bad\ud800.example"),
        ("domain", "*.example.org"),
        ("domain", "em0"),
        ("domain", "any"),
        ("domain", "192.0.2.1"),
        ("domain", "example.org:network"),
        ("hostname", 'example.org"'),
        ("hostname", "$hostname"),
        ("hostname", "a" * 64 + ".example"),
        ("hostname", ".".join(["a" * 63] * 4)),
        ("domain|ip", "example.org"),
        ("domain|ip", "example.org|192.0.2.1|443"),
        ("domain|ip", "example.org|any"),
        ("ip-src|port", "192.0.2.1"),
        ("ip-dst|port", "192.0.2.1|65536"),
        ("ip-dst|port", "192.0.2.1|https"),
        ("hostname|port", "example.org|443|80"),
        ("port", "-1"),
        ("port", "53:65535"),
        ("port", "443\npass all"),
        ("port", "４４３"),
        ("port", 443),
        ("ip-dst", None),
        ("domain", ""),
    ],
)
def test_invalid_and_pf_injection_values_are_skipped_without_partial_rules(kind, value):
    rules, result = run(event([attribute(kind, value), attribute()]))
    assert rules == ["block drop quick inet from any to 192.0.2.1"]
    assert result["summary"]["skipped"] == {"malformed": 1}


@pytest.mark.parametrize("kind", ["url", "uri", "AS", "mac-address", "email-src", "user-agent", "sha256"])
def test_unsupported_indicators_are_not_broadened_into_network_blocks(kind):
    rules, result = run(event([attribute(kind, "https://example.org/path")]))
    assert rules == [] and result["summary"]["skipped"] == {"unsupported": 1}


def test_dns_and_standalone_ports_explain_pf_semantics_without_resolving(monkeypatch):
    import socket

    def no_network(*args, **kwargs):
        pytest.fail("Export must not perform DNS lookups")

    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket, "gethostbyname", no_network)
    _, result = run(event([attribute("domain", "example.org"), attribute("port", "443")]))
    assert any("load time" in warning for warning in result["warnings"])
    assert any("all addresses" in warning for warning in result["warnings"])
    rules, result = run(event([attribute("domain|ip", "example.org|192.0.2.1")]))
    assert all("example.org" not in rule for rule in rules)
    assert "warnings" not in result


@pytest.mark.parametrize(
    "query",
    [
        "{",
        "null",
        "[]",
        "{}",
        {"data": None},
        {"data": "not an event"},
        {"data": [1]},
        {"data": {"Event": []}},
        {"data": {"Attribute": {}}},
        {"data": {"Object": [1]}},
        {"data": event(objects=[{"Attribute": [1]}])},
        {"data": event([attribute(to_ids="yes")])},
    ],
)
def test_invalid_requests_return_module_errors(query):
    result = export.handler(query if isinstance(query, str) else json.dumps(query))
    assert "error" in result and "data" not in result


def test_empty_events_and_metadata():
    assert export.handler() is False
    for data in ([], {}, {"Event": {}}, {"Attribute": []}):
        rules, result = run(data)
        assert not rules and result["summary"]["count"] == 0
    setup = export.introspection()
    assert setup["input"] == sorted(export.SUPPORTED_TYPES)
    assert setup["inputSource"] == ["event", "event-collection"]
    assert setup["outputFileExtension"] == "conf"
    assert setup["userConfig"]["mode"]["type"] == "String"
    assert export.version()["module-type"] == ["export"]
    assert export.version()["config"] == ["mode"]


class TestPFHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"pf_export": export, "type:pf_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_export(self):
        response = self.fetch("/modules")
        modules = json.loads(response.body)
        descriptor = next(module for module in modules if module["name"] == "pf_export")
        assert descriptor["meta"]["config"] == ["mode"]
        assert "mode" in descriptor["mispattributes"]["userConfig"]
        for config, expected in [
            ({}, b"block drop quick inet from any to 192.0.2.1\n"),
            ({"mode": "log"}, b"match log (all) inet from any to 192.0.2.1\n"),
        ]:
            response = self.fetch(
                "/query",
                method="POST",
                body=json.dumps({"module": "pf_export", "data": [{"Event": event([attribute()])}], "config": config}),
            )
            assert response.code == 200
            result = json.loads(response.body)
            assert expected in base64.b64decode(result["data"])


@pytest.mark.skipif(shutil.which("pfctl") is None, reason="Native OpenBSD pfctl is not installed")
@pytest.mark.parametrize("mode", ["block", "log"])
def test_native_pf_syntax(tmp_path, mode):
    rules, _ = run(
        event(
            [
                attribute("ip-src", "192.0.2.0/24"),
                attribute("ip-dst", "2001:db8::1"),
                attribute("ip-src|port", "192.0.2.2|80"),
                attribute("ip-dst|port", "2001:db8::2|443"),
                attribute("port", "53"),
            ]
        ),
        mode=mode,
    )
    path = tmp_path / "misp-pf.conf"
    path.write_text("\n".join(rules) + "\n")
    subprocess.run(["pfctl", "-n", "-f", str(path)], check=True, capture_output=True, text=True)
