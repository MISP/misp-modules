"""Shared input-contract tests and independent vendor syntax/semantics checks."""

import base64
import copy
import importlib
import json
import socket
from pathlib import Path

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules import import_from_path, is_valid_module
from misp_modules.lib import network_acl as acl

NAMES = ["panos_export", "junos_export", "fortios_export", "cisco_asa_export", "mikrotik_export"]
MODULES = [importlib.import_module(f"misp_modules.modules.export_mod.{name}") for name in NAMES]


def attribute(kind="ip-dst", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "to_ids": True, **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"Attribute": attributes or [], "Object": objects or [], **metadata}


def run(module, data, **config):
    result = module.handler(json.dumps({"data": data, "config": config}))
    assert "error" not in result, result
    return base64.b64decode(result["data"], validate=True).decode("ascii"), result


@pytest.fixture(params=MODULES, ids=NAMES)
def vendor(request):
    return request.param


@pytest.mark.parametrize("mode", ["block", "log"])
def test_event_formats_objects_normalization_deduplication_and_stable_order(vendor, mode):
    data = [
        {"Event": event([attribute()])},
        event([attribute(value="192.0.2.1/32")]),
        {"Event": {"id": "42"}, "Attribute": [attribute("ip-src", "2001:0DB8::1")]},
        {"Event": {"id": "43"}, "Object": [{"Attribute": [attribute("ip-src", "2001:db8::1/128")]}]},
        event(objects=[{"Attribute": [attribute("ip-dst|port", "192.0.2.7/24|00443")]}]),
    ]
    original = copy.deepcopy(data)
    text, result = run(vendor, data, mode=mode)
    assert result["summary"] == {"count": 4, "skipped": {}}
    assert data == original
    assert run(vendor, list(reversed(data)), mode=mode)[0] == text
    assert acl.PLACEMENT_WARNING in text and acl.PLACEMENT_WARNING in result["warnings"]


@pytest.mark.parametrize("flag", [True, 1, "1", "true", "TRUE"])
def test_true_ids_flags(vendor, flag):
    assert run(vendor, event([attribute(to_ids=flag)]))[1]["summary"]["count"] == 1


@pytest.mark.parametrize("flag", [False, 0, "0", "false", "FALSE", None, ""])
def test_false_ids_flags(vendor, flag):
    assert run(vendor, event([attribute(to_ids=flag)]))[1]["summary"] == {"count": 0, "skipped": {"non-IDS": 1}}


def test_deleted_data_missing_ids_and_unsupported_types(vendor):
    missing = attribute()
    del missing["to_ids"]
    data = [
        event([attribute()], deleted="true"),
        event(objects=[{"deleted": "1", "Attribute": [attribute()]}]),
        event([attribute(deleted=True), missing, attribute("url", "https://example.org/path"), attribute()]),
    ]
    assert run(vendor, data)[1]["summary"] == {
        "count": 1,
        "skipped": {"deleted": 1, "non-IDS": 1, "unsupported": 1},
    }


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-dst", "192.0.2.1\npermit ip any any"),
        ("ip-src", "any"),
        ("ip-src", "192.0.2.1/33"),
        ("ip-dst", "2001:db8::1/129"),
        ("ip-dst", "fe80::1%eth0"),
        ("ip-dst", "192.0.2.1;end"),
        ("ip-dst", 123),
        ("domain|ip", "example.org|192.0.2.1|443"),
        ("domain|ip", "bad..example|192.0.2.1"),
        ("ip-src|port", "192.0.2.1"),
        ("ip-dst|port", "192.0.2.1|65536"),
        ("ip-dst|port", "192.0.2.1|４４３"),
        ("hostname|port", "example.org|443|80"),
        ("port", "-1"),
        ("port", "53-80"),
        ("domain", "bad\ud800.example"),
        ("domain", "example.org\x7f"),
        ("domain", "*.example.org"),
        ("domain", "localhost"),
    ],
)
def test_malformed_indicators_never_produce_partial_or_broader_rules(vendor, kind, value):
    _, result = run(vendor, event([attribute(kind, value), attribute()]), resolve_dns=True)
    assert result["summary"] == {"count": 1, "skipped": {"malformed": 1}}


def test_dns_is_opt_in_and_domain_ip_never_resolves(vendor, monkeypatch):
    def forbidden(*args):
        pytest.fail("Unexpected DNS query")

    monkeypatch.setattr(acl.socket, "getaddrinfo", forbidden)
    data = event(
        [
            attribute("domain", "example.org"),
            attribute("hostname", "example.org"),
            attribute("hostname|port", "example.org|443"),
        ]
    )
    assert run(vendor, data)[1]["summary"] == {"count": 0, "skipped": {"DNS resolution disabled": 3}}
    _, result = run(vendor, event([attribute("domain|ip", "EXAMPLE.org.|2001:db8::1")]), resolve_dns=True)
    assert result["summary"] == {"count": 2, "skipped": {}}
    assert not any("snapshots" in warning for warning in result["warnings"])


@pytest.mark.parametrize("families", [(4,), (6,), (4, 6)])
def test_dns_normalization_cache_address_families_and_port_constraints(vendor, monkeypatch, families):
    calls = []

    def resolve(*args):
        calls.append(args)
        answers = []
        if 4 in families:
            answers.extend([(socket.AF_INET, 1, 6, "", ("192.0.2.1", 0))] * 2)
        if 6 in families:
            answers.append((socket.AF_INET6, 1, 6, "", ("2001:db8::1", 0, 0, 0)))
        answers.append((socket.AF_INET6, 1, 6, "", ("fe80::1%eth0", 0, 0, 1)))
        return answers

    monkeypatch.setattr(acl.socket, "getaddrinfo", resolve)
    data = event(
        [
            attribute("domain", "BÜCHER.example."),
            attribute("hostname", "bücher.example"),
            attribute("hostname|port", "bücher.example|443"),
        ]
    )
    _, result = run(vendor, data, resolve_dns="true")
    assert result["summary"] == {"count": 4 * len(families), "skipped": {}}
    assert calls == [("xn--bcher-kva.example.", None, socket.AF_UNSPEC, socket.SOCK_STREAM)]
    assert any("snapshots" in warning for warning in result["warnings"])


def test_failed_dns_is_cached_and_other_attributes_survive(vendor, monkeypatch):
    calls = []

    def resolve(*args):
        calls.append(args)
        raise socket.gaierror("not found")

    monkeypatch.setattr(acl.socket, "getaddrinfo", resolve)
    _, result = run(
        vendor,
        event([attribute("domain", "example.org"), attribute("hostname", "EXAMPLE.org."), attribute()]),
        resolve_dns=True,
    )
    assert result["summary"] == {"count": 1, "skipped": {"unresolved DNS": 2}}
    assert len(calls) == 1


@pytest.mark.parametrize(
    "config",
    [
        [],
        "block",
        True,
        {"mode": []},
        {"mode": "accept"},
        {"resolve_dns": "yes"},
        {"name_prefix": 123},
        {"name_prefix": "Bad\ncommit"},
        {"name_prefix": "A" * 28},
        {"name_prefix": "éxample"},
    ],
)
def test_invalid_configuration_has_no_download(vendor, config):
    result = vendor.handler(json.dumps({"data": event([attribute()]), "config": config}))
    assert "error" in result and "data" not in result


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
        {"data": {"Object": [1]}},
        {"data": event([attribute(to_ids="yes")])},
    ],
)
def test_invalid_requests_have_no_download(vendor, query):
    result = vendor.handler(query if isinstance(query, str) else json.dumps(query))
    assert "error" in result and "data" not in result


@pytest.mark.parametrize("data", [[], {}, {"Event": {}}, {"Attribute": []}])
def test_empty_events_create_no_configuration(vendor, data):
    text, result = run(vendor, data)
    assert result["summary"] == {"count": 0, "skipped": {}}
    assert all(line.startswith(("#", "!")) for line in text.splitlines())
    assert vendor.handler() is False


def test_standalone_ports_cover_both_families_and_warn(vendor):
    _, result = run(vendor, event([attribute("port", "53")]))
    assert result["summary"] == {"count": 4, "skipped": {}}
    assert any("all IPv4 and IPv6" in warning for warning in result["warnings"])


def test_zero_ports_are_supported_or_explicitly_skipped_without_broadening(vendor):
    _, result = run(vendor, event([attribute("ip-src|port", "192.0.2.1|0")]))
    if vendor.__name__.endswith(("panos_export", "fortios_export")):
        assert result["summary"] == {"count": 0, "skipped": {"unsupported port zero": 1}}
    else:
        assert result["summary"] == {"count": 2, "skipped": {}}


def test_metadata_and_service_style_file_loading(vendor):
    path = Path(vendor.__file__)
    assert is_valid_module(path)
    module = import_from_path(path.stem, str(path))
    info = module.introspection()
    assert info["input"] == sorted(acl.SUPPORTED_TYPES)
    assert info["inputSource"] == ["event", "event-collection"]
    assert info["outputFileExtension"] == "cfg"
    assert set(info["userConfig"]) == set(module.version()["config"])
    assert module.version()["module-type"] == ["export"]
    assert run(module, event([attribute()]))[1]["summary"]["count"] == 1


def module(name):
    return MODULES[NAMES.index(name)]


def commands(text):
    return [line for line in text.splitlines() if not line.startswith(("#", "!"))]


def test_panos_services_source_and_destination_ports_and_actions():
    exporter = module("panos_export")
    text, _ = run(
        exporter,
        event([attribute("ip-src|port", "192.0.2.7/24|443"), attribute("ip-dst|port", "2001:db8::1|53")]),
        from_zone="Trust",
        to_zone="Untrust",
    )
    lines = commands(text)
    assert len([line for line in lines if line.startswith("set service ")]) == 4
    assert any("protocol tcp port 1-65535 source-port 443" in line for line in lines)
    assert any("protocol udp port 53" in line for line in lines)
    assert sum(line.endswith(" source 192.0.2.0/24") for line in lines) == 2
    assert sum(line.endswith(" destination 2001:db8::1/128") for line in lines) == 2
    assert sum(line.endswith(" action drop") for line in lines) == 4
    assert sum(line.endswith(" from Trust") for line in lines) == 4
    assert sum(line.endswith(" to Untrust") for line in lines) == 4
    log, result = run(exporter, event([attribute()]), mode="log")
    assert any(line.endswith(" action allow") for line in commands(log))
    assert acl.PERMIT_LOG_WARNING in result["warnings"]


def test_junos_address_families_protocol_keywords_and_nonterminating_log():
    exporter = module("junos_export")
    text, _ = run(
        exporter, event([attribute("ip-src|port", "192.0.2.1|443"), attribute("ip-dst|port", "2001:db8::1|53")])
    )
    lines = commands(text)
    assert sum("family inet filter MISP-IOC-V4" in line and line.endswith(" from protocol tcp") for line in lines) == 1
    assert (
        sum("family inet6 filter MISP-IOC-V6" in line and line.endswith(" from next-header udp") for line in lines) == 1
    )
    assert sum(line.endswith(" from source-port 443") for line in lines) == 2
    assert sum(line.endswith(" from destination-port 53") for line in lines) == 2
    assert sum(line.endswith(" then discard") for line in lines) == 4
    log, _ = run(exporter, event([attribute()]), mode="log")
    assert sum(line.endswith(" then log") for line in commands(log)) == 1
    assert sum(line.endswith(" then next term") for line in commands(log)) == 1
    assert "then accept" not in log and "then discard" not in log


def test_asa_uses_netmasks_not_ios_wildcards_and_preserves_port_sides():
    text, result = run(
        module("cisco_asa_export"),
        event([attribute("ip-src|port", "192.0.2.7/24|443"), attribute("ip-dst|port", "2001:db8::1|53")]),
    )
    assert commands(text) == [
        "access-list MISP-IOC extended deny tcp 192.0.2.0 255.255.255.0 eq 443 any4",
        "access-list MISP-IOC extended deny udp 192.0.2.0 255.255.255.0 eq 443 any4",
        "access-list MISP-IOC extended deny tcp any6 host 2001:db8::1 eq 53",
        "access-list MISP-IOC extended deny udp any6 host 2001:db8::1 eq 53",
    ]
    assert result["summary"]["count"] == 4
    text, result = run(module("cisco_asa_export"), event([attribute()]), mode="log")
    assert commands(text) == ["access-list MISP-IOC extended permit ip any4 host 192.0.2.1 log"]
    assert acl.PERMIT_LOG_WARNING in text and acl.PERMIT_LOG_WARNING in result["warnings"]


@pytest.mark.parametrize("mode", ["block", "log"])
@pytest.mark.parametrize("name_prefix", ["MISP-IOC", "Threat_42"])
def test_asa_dual_stack_export_uses_one_attachable_acl(mode, name_prefix):
    text, result = run(
        module("cisco_asa_export"),
        event([attribute(), attribute(value="2001:db8::1"), attribute("port", "443")]),
        mode=mode,
        name_prefix=name_prefix,
    )
    entries = commands(text)
    # ASA permits one extended ACL per interface/direction, so both families
    # and standalone-port entries must be usable through a single binding.
    assert {line.split()[1] for line in entries} == {name_prefix}
    assert len(entries) == result["summary"]["count"] == 6
    assert sum("any4" in line for line in entries) == 3
    assert sum("any6" in line for line in entries) == 3
    assert all(("any4" in line) != ("any6" in line) for line in entries)
    if mode == "log":
        assert all(" extended permit " in line and line.endswith(" log") for line in entries)
    else:
        assert all(" extended deny " in line and not line.endswith(" log") for line in entries)


def test_routeros_separate_ipv6_path_and_nonterminating_log():
    text, _ = run(
        module("mikrotik_export"),
        event([attribute("ip-src|port", "192.0.2.1|443"), attribute("ip-dst|port", "2001:db8::1|53")]),
        chain="input",
    )
    lines = commands(text)
    assert (
        sum(
            line.startswith("/ip firewall filter add chain=input action=drop src-address=192.0.2.1/32")
            for line in lines
        )
        == 2
    )
    assert (
        sum(
            line.startswith(
                "/ipv6 firewall filter add chain=input action=drop src-address=::/0 dst-address=2001:db8::1/128"
            )
            for line in lines
        )
        == 2
    )
    assert sum("src-port=443" in line for line in lines) == 2
    assert sum("dst-port=53" in line for line in lines) == 2
    text, _ = run(module("mikrotik_export"), event([attribute()]), mode="log")
    assert "action=log" in text and 'log-prefix="MISP-IOC "' in text


def test_fortios_unified_policy_dependencies_and_source_service_constraint():
    text, result = run(
        module("fortios_export"),
        event([attribute("ip-src|port", "192.0.2.7/24|443"), attribute("ip-dst", "2001:db8::1")]),
        srcintf="port1",
        dstintf="port2",
        start_policy_id="42",
    )
    lines = commands(text)
    assert "        set subnet 192.0.2.0 255.255.255.0" in lines
    assert "        set ip6 2001:db8::1/128" in lines
    assert "        set ip6 ::/0" in lines
    assert "        set tcp-portrange 1-65535:443" in lines
    assert "        set udp-portrange 1-65535:443" in lines
    assert text.count("config firewall policy\n") == 3
    assert text.count("        set action deny\n") == 3
    assert text.count('        set srcintf "port1"\n') == 3
    assert text.count('        set dstintf "port2"\n') == 3
    assert "    edit 42\n" in text and "    edit 44\n" in text
    assert text.count("        unset srcaddr6\n") == 2
    assert text.count("        unset srcaddr\n") == 1
    # Every named reference is either an object defined earlier or a built-in service.
    defined = set()
    for line in lines:
        if line.startswith('    edit "'):
            defined.add(line.split('"')[1])
        if line.strip().startswith(("set srcaddr", "set dstaddr", "set service")):
            assert line.split('"')[1] in defined | {"ALL"}
    assert result["summary"]["count"] == 3
    text, result = run(module("fortios_export"), event([attribute()]), mode="log")
    assert "set action accept" in text and "set logtraffic all" in text
    assert acl.PERMIT_LOG_WARNING in result["warnings"]


@pytest.mark.parametrize(
    "name,config",
    [
        ("panos_export", {"from_zone": "any;commit"}),
        ("panos_export", {"to_zone": []}),
        ("mikrotik_export", {"chain": "custom"}),
        ("mikrotik_export", {"chain": "forward\n/system reset-configuration"}),
        ("fortios_export", {"srcintf": 'port1"\nend'}),
        ("fortios_export", {"start_policy_id": 0}),
        ("fortios_export", {"start_policy_id": True}),
        ("fortios_export", {"start_policy_id": "1;end"}),
        ("fortios_export", {"start_policy_id": 4294967295}),
        ("fortios_export", {"start_policy_id": 4294967294}),
        ("fortios_export", {"name_prefix": "A" * 19}),
    ],
)
def test_vendor_settings_and_policy_id_overflow_return_no_partial_file(name, config):
    result = module(name).handler(json.dumps({"data": event([attribute("port", "443")]), "config": config}))
    assert "error" in result and "data" not in result


def test_fortios_generated_policy_names_respect_35_character_limit():
    text, _ = run(module("fortios_export"), event([attribute()]), name_prefix="A" * 18)
    name_line = next(line for line in commands(text) if line.strip().startswith("set name "))
    assert len(name_line.split('"')[1]) == 35


def test_export_never_commits_binds_saves_or_exports_event_metadata(vendor):
    text, _ = run(vendor, event([attribute(comment="private comment")], info="private event title"))
    for forbidden in (
        "private comment",
        "private event title",
        "commit",
        "access-group",
        "write memory",
        "set interfaces",
        "/system",
    ):
        assert forbidden not in "\n".join(commands(text))


class TestVendorACLHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        for name, exporter in zip(NAMES, MODULES):
            service.MODULES_HANDLERS.update({name: exporter, f"type:{name}": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_both_modes(self):
        descriptors = {item["name"]: item for item in json.loads(self.fetch("/modules").body)}
        for name, exporter in zip(NAMES, MODULES):
            assert descriptors[name]["meta"]["config"] == exporter.moduleconfig
            for mode in ("block", "log"):
                response = self.fetch(
                    "/query",
                    method="POST",
                    body=json.dumps(
                        {"module": name, "config": {"mode": mode}, "data": [{"Event": event([attribute()])}]}
                    ),
                )
                assert response.code == 200
                result = json.loads(response.body)
                assert result["summary"]["count"] == 1
                assert b"192.0.2.1" in base64.b64decode(result["data"], validate=True)
