import base64
import copy
import json
import shutil
import socket
import subprocess

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import netfilter_export as export


def attribute(kind="ip-dst", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "to_ids": True, **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"Attribute": attributes or [], "Object": objects or [], **metadata}


def run(data, **config):
    result = export.handler(json.dumps({"data": data, "config": config}))
    assert "error" not in result, result
    text = base64.b64decode(result["data"], validate=True).decode("ascii")
    return [line for line in text.splitlines() if not line.startswith("#")], result


@pytest.mark.parametrize("mode,action", [("block", "counter drop"), ("log", 'counter log prefix "MISP: " level info')])
@pytest.mark.parametrize(
    "kind,value,matches",
    [
        ("ip-src", "192.0.2.1", ["ip saddr 192.0.2.1"]),
        ("ip-dst", "2001:0DB8::1", ["ip6 daddr 2001:db8::1"]),
        ("ip-src", "2001:db8::1", ["ip6 saddr 2001:db8::1"]),
        ("ip-dst", "192.0.2.7/24", ["ip daddr 192.0.2.0/24"]),
        ("ip-src", "2001:db8:1::42/48", ["ip6 saddr 2001:db8:1::/48"]),
        ("ip-src|port", "192.0.2.1|00443", ["ip saddr 192.0.2.1 meta l4proto { tcp, udp } th sport 443"]),
        ("ip-dst|port", "2001:db8::1|65535", ["ip6 daddr 2001:db8::1 meta l4proto { tcp, udp } th dport 65535"]),
        ("ip-dst|port", "192.0.2.0/24|80", ["ip daddr 192.0.2.0/24 meta l4proto { tcp, udp } th dport 80"]),
        ("domain|ip", "EXAMPLE.org.|192.0.2.1", ["ip daddr 192.0.2.1", "ip saddr 192.0.2.1"]),
        ("domain|ip", "example.org|2001:db8::1", ["ip6 daddr 2001:db8::1", "ip6 saddr 2001:db8::1"]),
        ("port", "53", ["meta l4proto { tcp, udp } th dport 53"]),
        ("port", "0", ["meta l4proto { tcp, udp } th dport 0"]),
        ("mac-address", "AA:BB:CC:DD:EE:FF", ["ether saddr aa:bb:cc:dd:ee:ff"]),
        ("mac-address", "AA-BB-CC-DD-EE-FF", ["ether saddr aa:bb:cc:dd:ee:ff"]),
    ],
)
def test_supported_types_keep_family_direction_and_ports(kind, value, matches, mode, action):
    rules, result = run(event([attribute(kind, value)]), mode=mode)
    assert rules == [f"{match} {action}" for match in matches]
    assert result["summary"] == {"count": len(matches), "skipped": {}}


@pytest.mark.parametrize("mode", ["block", "log"])
def test_all_event_shapes_objects_deduplication_and_no_mutation(mode):
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
    rules, result = run(data, mode=mode)
    assert len(rules) == result["summary"]["count"] == 3
    assert data == original
    assert run(list(reversed(data)), mode=mode)[0] == rules


@pytest.mark.parametrize("flag", [True, 1, "1", "true", "TRUE"])
def test_true_ids_representations(flag):
    assert run(event([attribute(to_ids=flag)]))[0] == ["ip daddr 192.0.2.1 counter drop"]


@pytest.mark.parametrize("flag", [False, 0, "0", "false", "FALSE", None, ""])
def test_false_ids_representations(flag):
    rules, result = run(event([attribute(to_ids=flag)]))
    assert not rules and result["summary"]["skipped"] == {"non-IDS": 1}


def test_deleted_data_and_missing_ids_are_excluded_in_logging_mode():
    missing = attribute()
    del missing["to_ids"]
    data = [
        event([attribute(deleted="true"), missing]),
        event([attribute()], deleted="1"),
        event(objects=[{"deleted": True, "Attribute": [attribute()]}]),
        event([attribute(), attribute()]),
    ]
    rules, result = run(data, mode="log")
    assert rules == ['ip daddr 192.0.2.1 counter log prefix "MISP: " level info']
    assert result["summary"] == {"count": 1, "skipped": {"deleted": 1, "non-IDS": 1}}


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-src", "any"),
        ("ip-dst", "192.0.2.1\naccept"),
        ("ip-dst", "192.0.2.1; flush ruleset"),
        ("ip-dst", "$address"),
        ("ip-dst", "999.1.2.3"),
        ("ip-dst", "192.0.2.1/33"),
        ("ip-dst", "2001:db8::1/129"),
        ("ip-dst", "fe80::1%eth0"),
        ("domain", "example.org\naccept"),
        ("domain", "example.org\x00"),
        ("domain", "bad..example"),
        ("domain", "bad\ud800.example"),
        ("domain", "*.example.org"),
        ("domain", "localhost"),
        ("domain", "192.0.2.1"),
        ("hostname", 'example.org"'),
        ("hostname", "a" * 64 + ".example"),
        ("hostname", ".".join(["a" * 63] * 4)),
        ("domain|ip", "example.org"),
        ("domain|ip", "example.org|192.0.2.1|443"),
        ("domain|ip", "example.org|any"),
        ("ip-src|port", "192.0.2.1"),
        ("ip-dst|port", "192.0.2.1|65536"),
        ("ip-dst|port", "192.0.2.1|https"),
        ("hostname|port", "example.org|443|80"),
        ("hostname|port", "example.org|443\naccept"),
        ("port", "-1"),
        ("port", "53-65535"),
        ("port", "443\naccept"),
        ("port", "４４３"),
        ("port", 443),
        ("mac-address", "AA:BB:CC:DD:EE"),
        ("mac-address", "AA:BB:CC:DD:EE:FF:00:11"),
        ("mac-address", "AA:BB:CC:DD:EE:FF; accept"),
        ("ip-dst", None),
        ("domain", ""),
    ],
)
def test_invalid_values_and_rule_injection_are_skipped_without_partial_rules(kind, value):
    rules, result = run(event([attribute(kind, value), attribute()]), resolve_dns=True)
    assert rules == ["ip daddr 192.0.2.1 counter drop"]
    assert result["summary"]["skipped"] == {"malformed": 1}


@pytest.mark.parametrize("kind", ["url", "uri", "AS", "mac-eui-64", "email-src", "user-agent", "sha256"])
def test_unsupported_values_are_not_broadened_into_host_blocks(kind):
    rules, result = run(event([attribute(kind, "https://example.org/path")]))
    assert not rules and result["summary"]["skipped"] == {"unsupported": 1}


def test_default_does_not_resolve_names_and_domain_ip_always_uses_supplied_ip(monkeypatch):
    def no_network(*args, **kwargs):
        pytest.fail("DNS must require explicit opt-in and must not expand domain|ip")

    monkeypatch.setattr(export.socket, "getaddrinfo", no_network)
    data = event(
        [attribute(kind, "example.org|443" if kind == "hostname|port" else "example.org") for kind in export.DNS_TYPES]
    )
    rules, result = run(data)
    assert rules == [] and result["summary"]["skipped"] == {"DNS resolution disabled": 3}
    for enabled in (False, True):
        rules, result = run(event([attribute("domain|ip", "example.org|192.0.2.1")]), resolve_dns=enabled)
        assert rules == ["ip daddr 192.0.2.1 counter drop", "ip saddr 192.0.2.1 counter drop"]
        assert "warnings" not in result


@pytest.mark.parametrize("mode,action", [("block", "counter drop"), ("log", 'counter log prefix "MISP: " level info')])
def test_dns_opt_in_resolves_both_families_once_and_preserves_ports(monkeypatch, mode, action):
    calls = []

    def resolve(*args):
        calls.append(args)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%eth0", 0, 0, 2)),
        ]

    monkeypatch.setattr(export.socket, "getaddrinfo", resolve)
    data = [
        event([attribute("domain", "BÜCHER.example.")]),
        event(
            objects=[
                {
                    "Attribute": [
                        attribute("hostname", "bücher.example"),
                        attribute("hostname|port", "bücher.example|443"),
                    ]
                }
            ]
        ),
    ]
    rules, result = run(data, mode=mode, resolve_dns="true")
    matches = [
        "ip daddr 192.0.2.1",
        "ip saddr 192.0.2.1",
        "ip6 daddr 2001:db8::1",
        "ip6 saddr 2001:db8::1",
        "ip daddr 192.0.2.1 meta l4proto { tcp, udp } th dport 443",
        "ip6 daddr 2001:db8::1 meta l4proto { tcp, udp } th dport 443",
    ]
    assert rules == sorted(f"{match} {action}" for match in matches)
    assert result["summary"] == {"count": 6, "skipped": {}}
    assert calls == [("xn--bcher-kva.example.", None, socket.AF_UNSPEC, socket.SOCK_STREAM)]
    assert any("snapshots" in warning for warning in result["warnings"])


@pytest.mark.parametrize(
    "outcome", [socket.gaierror("not found"), [], [(socket.AF_INET6, 1, 6, "", ("fe80::1%eth0", 0, 0, 2))]]
)
def test_failed_dns_is_cached_skipped_and_does_not_abort_other_indicators(monkeypatch, outcome):
    calls = []

    def resolve(*args):
        calls.append(args)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(export.socket, "getaddrinfo", resolve)
    rules, result = run(
        event([attribute("domain", "example.org"), attribute("hostname", "EXAMPLE.org."), attribute()]),
        resolve_dns=True,
    )
    assert rules == ["ip daddr 192.0.2.1 counter drop"]
    assert result["summary"]["skipped"] == {"unresolved DNS": 2}
    assert len(calls) == 1


def test_non_ids_and_deleted_dns_attributes_are_not_resolved_even_with_opt_in(monkeypatch):
    def no_network(*args, **kwargs):
        pytest.fail("Excluded attributes must not cause DNS lookups")

    monkeypatch.setattr(export.socket, "getaddrinfo", no_network)
    rules, _ = run(
        event([attribute("domain", "example.org", to_ids=False), attribute("domain", "example.org", deleted=True)]),
        resolve_dns=True,
    )
    assert rules == []


@pytest.mark.parametrize("config", [None, {}, {"mode": None}, {"mode": ""}, {"mode": "block"}])
def test_default_mode_is_block(config):
    result = export.handler(json.dumps({"data": event([attribute()]), "config": config}))
    assert base64.b64decode(result["data"]).splitlines()[1:] == [b"ip daddr 192.0.2.1 counter drop"]


@pytest.mark.parametrize(
    "config",
    ["log", [], True, {"mode": []}, {"mode": {}}, {"mode": "pass"}, {"mode": "log\naccept"}, {"resolve_dns": "yes"}],
)
def test_invalid_configuration_returns_error_without_file(config):
    result = export.handler(json.dumps({"data": event([attribute()]), "config": config}))
    assert "error" in result and "data" not in result


@pytest.mark.parametrize(
    "query",
    [
        "{",
        "null",
        "[]",
        "{}",
        {"data": None},
        {"data": "bad"},
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


def test_empty_input_metadata_and_export_has_no_ruleset_management_commands():
    assert export.handler() is False
    for data in ([], {}, {"Event": {}}, {"Attribute": []}):
        assert run(data)[0] == []
    raw = base64.b64decode(run(event([attribute()]))[1]["data"]).decode("ascii")
    assert all(word not in raw for word in ("flush", "add table", "delete", "policy", "hook", "accept"))
    setup = export.introspection()
    assert setup["input"] == sorted(export.SUPPORTED_TYPES)
    assert setup["inputSource"] == ["event", "event-collection"]
    assert setup["outputFileExtension"] == "nft"
    assert setup["userConfig"]["mode"]["type"] == "String"
    assert setup["userConfig"]["resolve_dns"]["type"] == "Boolean"
    assert export.version()["config"] == ["mode", "resolve_dns"]


class TestNetfilterHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"netfilter_export": export, "type:netfilter_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_export_in_both_modes(self):
        descriptor = next(
            item for item in json.loads(self.fetch("/modules").body) if item["name"] == "netfilter_export"
        )
        assert descriptor["meta"]["config"] == ["mode", "resolve_dns"]
        assert "mode" in descriptor["mispattributes"]["userConfig"]
        for config, expected in [
            ({}, b"ip daddr 192.0.2.1 counter drop\n"),
            ({"mode": "log"}, b'ip daddr 192.0.2.1 counter log prefix "MISP: " level info\n'),
        ]:
            response = self.fetch(
                "/query",
                method="POST",
                body=json.dumps(
                    {"module": "netfilter_export", "data": [{"Event": event([attribute()])}], "config": config}
                ),
            )
            assert response.code == 200
            assert expected in base64.b64decode(json.loads(response.body)["data"])


@pytest.mark.skipif(shutil.which("nft") is None, reason="Native nft is not installed")
@pytest.mark.parametrize("mode", ["block", "log"])
def test_native_nft_check_of_included_fragment(tmp_path, mode):
    data = event(
        [
            attribute("ip-src", "192.0.2.0/24"),
            attribute("ip-dst", "2001:db8::1"),
            attribute("ip-src|port", "192.0.2.2|80"),
            attribute("ip-dst|port", "2001:db8::2|443"),
            attribute("port", "53"),
            attribute("mac-address", "aa:bb:cc:dd:ee:ff"),
        ]
    )
    _, result = run(data, mode=mode)
    fragment = tmp_path / "misp.nft"
    fragment.write_bytes(base64.b64decode(result["data"]))
    wrapper = tmp_path / "check.nft"
    wrapper.write_text('table inet misp_export_test {\n chain indicators {\n include "' + str(fragment) + '"\n }\n}\n')
    process = subprocess.run(["nft", "--check", "--file", str(wrapper)], capture_output=True, text=True)
    if process.returncode and "Operation not permitted" in process.stderr and "syntax error" not in process.stderr:
        pytest.skip("Native nft validation requires CAP_NET_ADMIN in a network namespace")
    assert process.returncode == 0, process.stderr
