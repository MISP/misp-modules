import base64
import copy
import json
import socket

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import cisco_acl_export as export


def attribute(kind="ip-dst", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "to_ids": True, **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"Attribute": attributes or [], "Object": objects or [], **metadata}


def run(data, **config):
    result = export.handler(json.dumps({"data": data, "config": config}))
    assert "error" not in result, result
    text = base64.b64decode(result["data"], validate=True).decode("ascii")
    sections = {4: [], 6: []}
    family = None
    for line in text.splitlines():
        if line.startswith("!"):
            continue
        if line.startswith("ip access-list extended "):
            family = 4
        elif line.startswith("ipv6 access-list "):
            family = 6
        elif line == "exit":
            assert family is not None
            family = None
        else:
            assert family is not None and line.startswith(" ")
            sections[family].append(line.strip())
    assert family is None
    return sections, result, text


@pytest.mark.parametrize("mode,action,suffix", [("block", "deny", ""), ("log", "permit", " log")])
@pytest.mark.parametrize(
    "kind,value,matches",
    [
        ("ip-src", "192.0.2.1", {4: ["ip host 192.0.2.1 any"]}),
        ("ip-dst", "2001:0DB8::1", {6: ["ipv6 any host 2001:db8::1"]}),
        ("ip-src", "2001:db8::1", {6: ["ipv6 host 2001:db8::1 any"]}),
        ("ip-dst", "192.0.2.7/24", {4: ["ip any 192.0.2.0 0.0.0.255"]}),
        ("ip-src", "192.0.2.5/31", {4: ["ip 192.0.2.4 0.0.0.1 any"]}),
        ("ip-dst", "192.0.2.1/32", {4: ["ip any host 192.0.2.1"]}),
        ("ip-src", "192.0.2.1/0", {4: ["ip any any"]}),
        ("ip-dst", "2001:db8::1/0", {6: ["ipv6 any any"]}),
        ("ip-dst", "2001:db8::1/128", {6: ["ipv6 any host 2001:db8::1"]}),
        ("ip-src", "2001:db8:1::42/48", {6: ["ipv6 2001:db8:1::/48 any"]}),
        ("ip-src|port", "192.0.2.1|00443", {4: ["tcp host 192.0.2.1 eq 443 any", "udp host 192.0.2.1 eq 443 any"]}),
        (
            "ip-dst|port",
            "2001:db8::1|65535",
            {6: ["tcp any host 2001:db8::1 eq 65535", "udp any host 2001:db8::1 eq 65535"]},
        ),
        (
            "ip-dst|port",
            "192.0.2.7/24|80",
            {4: ["tcp any 192.0.2.0 0.0.0.255 eq 80", "udp any 192.0.2.0 0.0.0.255 eq 80"]},
        ),
        ("domain|ip", "EXAMPLE.org.|192.0.2.1", {4: ["ip any host 192.0.2.1", "ip host 192.0.2.1 any"]}),
        ("domain|ip", "example.org|2001:db8::1", {6: ["ipv6 any host 2001:db8::1", "ipv6 host 2001:db8::1 any"]}),
        ("port", "53", {4: ["tcp any any eq 53", "udp any any eq 53"], 6: ["tcp any any eq 53", "udp any any eq 53"]}),
        ("port", "0", {4: ["tcp any any eq 0", "udp any any eq 0"], 6: ["tcp any any eq 0", "udp any any eq 0"]}),
    ],
)
def test_address_families_wildcards_ports_and_actions(kind, value, matches, mode, action, suffix):
    sections, result, text = run(event([attribute(kind, value)]), mode=mode)
    for family in (4, 6):
        assert sections[family] == [f"{action} {match}{suffix}" for match in matches.get(family, [])]
        assert (f"MISP-IOC-V{family}" in text) == bool(matches.get(family))
    assert result["summary"] == {"count": sum(map(len, matches.values())), "skipped": {}}


@pytest.mark.parametrize("mode", ["block", "log"])
def test_standard_bare_legacy_objects_deduplication_and_no_mutation(mode):
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
    sections, result, text = run(data, mode=mode)
    assert len(sections[4]) == result["summary"]["count"] == 3 and not sections[6]
    assert data == original
    assert run(list(reversed(data)), mode=mode)[2] == text


def test_equivalent_host_and_network_values_are_deduplicated():
    sections, result, _ = run(
        event(
            [
                attribute(value="192.0.2.1"),
                attribute(value="192.0.2.1/32"),
                attribute(value="2001:db8::1"),
                attribute(value="2001:0db8::1/128"),
            ]
        )
    )
    assert result["summary"]["count"] == 2
    assert sections == {4: ["deny ip any host 192.0.2.1"], 6: ["deny ipv6 any host 2001:db8::1"]}


@pytest.mark.parametrize("flag", [True, 1, "1", "true", "TRUE"])
def test_true_ids_representations(flag):
    assert run(event([attribute(to_ids=flag)]))[0][4] == ["deny ip any host 192.0.2.1"]


@pytest.mark.parametrize("flag", [False, 0, "0", "false", "FALSE", None, ""])
def test_false_ids_representations(flag):
    sections, result, _ = run(event([attribute(to_ids=flag)]))
    assert sections == {4: [], 6: []} and result["summary"]["skipped"] == {"non-IDS": 1}


def test_deleted_events_objects_attributes_and_missing_ids_are_excluded():
    missing = attribute()
    del missing["to_ids"]
    data = [
        event([attribute(deleted="true"), missing]),
        event([attribute()], deleted="1"),
        event(objects=[{"deleted": True, "Attribute": [attribute()]}]),
        event([attribute(), attribute()]),
    ]
    sections, result, _ = run(data, mode="log")
    assert sections == {4: ["permit ip any host 192.0.2.1 log"], 6: []}
    assert result["summary"] == {"count": 1, "skipped": {"deleted": 1, "non-IDS": 1}}


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-src", "any"),
        ("ip-dst", "192.0.2.1\npermit ip any any"),
        ("ip-dst", "192.0.2.1; end"),
        ("ip-dst", "host 192.0.2.1"),
        ("ip-dst", "999.1.2.3"),
        ("ip-dst", "192.0.2.1/33"),
        ("ip-dst", "2001:db8::1/129"),
        ("ip-dst", "fe80::1%eth0"),
        ("domain", "example.org\nexit"),
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
        ("hostname|port", "example.org|443\nexit"),
        ("port", "-1"),
        ("port", "53-65535"),
        ("port", "443\nexit"),
        ("port", "４４３"),
        ("port", 443),
        ("ip-dst", None),
        ("domain", ""),
    ],
)
def test_invalid_values_and_cli_injection_do_not_produce_partial_entries(kind, value):
    sections, result, _ = run(event([attribute(kind, value), attribute()]), resolve_dns=True)
    assert sections == {4: ["deny ip any host 192.0.2.1"], 6: []}
    assert result["summary"]["skipped"] == {"malformed": 1}


@pytest.mark.parametrize("kind", ["url", "uri", "AS", "mac-address", "mac-eui-64", "email-src", "user-agent", "sha256"])
def test_types_outside_layer_three_acl_scope_are_not_broadened(kind):
    sections, result, _ = run(event([attribute(kind, "https://example.org/path")]))
    assert sections == {4: [], 6: []} and result["summary"]["skipped"] == {"unsupported": 1}


def test_dns_disabled_by_default_and_domain_ip_never_looks_up_names(monkeypatch):
    def no_network(*args, **kwargs):
        pytest.fail("Unexpected name lookup")

    monkeypatch.setattr(export.socket, "getaddrinfo", no_network)
    data = event(
        [attribute(kind, "example.org|443" if kind == "hostname|port" else "example.org") for kind in export.DNS_TYPES]
    )
    sections, result, _ = run(data)
    assert sections == {4: [], 6: []}
    assert result["summary"]["skipped"] == {"DNS resolution disabled": 3}
    for enabled in (False, True):
        sections, result, _ = run(event([attribute("domain|ip", "example.org|192.0.2.1")]), resolve_dns=enabled)
        assert sections[4] == ["deny ip any host 192.0.2.1", "deny ip host 192.0.2.1 any"]
        assert not any("snapshot" in warning for warning in result["warnings"])


@pytest.mark.parametrize("mode,action,suffix", [("block", "deny", ""), ("log", "permit", " log")])
@pytest.mark.parametrize("families", [(4,), (6,), (4, 6)])
def test_opt_in_dns_handles_single_dual_stack_caching_and_ports(monkeypatch, families, mode, action, suffix):
    calls = []

    def resolve(*args):
        calls.append(args)
        answers = []
        if 4 in families:
            answers.extend([(socket.AF_INET, 1, 6, "", ("192.0.2.1", 0))] * 2)
        if 6 in families:
            answers.append((socket.AF_INET6, 1, 6, "", ("2001:db8::1", 0, 0, 0)))
        answers.append((socket.AF_INET6, 1, 6, "", ("fe80::1%eth0", 0, 0, 2)))
        return answers

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
    sections, result, _ = run(data, mode=mode, resolve_dns="true")
    for family in (4, 6):
        if family not in families:
            assert not sections[family]
            continue
        protocol, host = ("ip", "192.0.2.1") if family == 4 else ("ipv6", "2001:db8::1")
        matches = [
            f"{protocol} any host {host}",
            f"{protocol} host {host} any",
            f"tcp any host {host} eq 443",
            f"udp any host {host} eq 443",
        ]
        assert sections[family] == sorted(f"{action} {match}{suffix}" for match in matches)
    assert result["summary"] == {"count": 4 * len(families), "skipped": {}}
    assert calls == [("xn--bcher-kva.example.", None, socket.AF_UNSPEC, socket.SOCK_STREAM)]
    assert any("snapshots" in warning for warning in result["warnings"])


@pytest.mark.parametrize("answers", [None, []])
def test_dns_failure_is_cached_and_other_attributes_survive(monkeypatch, answers):
    calls = []

    def resolve(*args):
        calls.append(args)
        if answers is None:
            raise socket.gaierror("not found")
        return answers

    monkeypatch.setattr(export.socket, "getaddrinfo", resolve)
    sections, result, _ = run(
        event([attribute("domain", "example.org"), attribute("hostname", "EXAMPLE.org."), attribute()]),
        resolve_dns=True,
    )
    assert sections[4] == ["deny ip any host 192.0.2.1"]
    assert result["summary"]["skipped"] == {"unresolved DNS": 2} and len(calls) == 1


@pytest.mark.parametrize("config", [None, {}, {"mode": None}, {"mode": ""}, {"mode": "block"}])
def test_unset_mode_defaults_to_deny(config):
    result = export.handler(json.dumps({"data": event([attribute()]), "config": config}))
    assert " deny ip any host 192.0.2.1\n" in base64.b64decode(result["data"]).decode("ascii")


@pytest.mark.parametrize(
    "config",
    [
        "log",
        [],
        True,
        {"mode": []},
        {"mode": {}},
        {"mode": "permit"},
        {"mode": "log\nexit"},
        {"resolve_dns": "yes"},
        {"acl_name": []},
        {"acl_name": 10},
        {"acl_name": "10"},
        {"acl_name": "MISP\nexit"},
        {"acl_name": "ACL;end"},
        {"acl_name": "ACL name"},
        {"acl_name": "A" * 49},
        {"acl_name": "éxample"},
    ],
)
def test_invalid_configuration_produces_no_file(config):
    result = export.handler(json.dumps({"data": event([attribute()]), "config": config}))
    assert "error" in result and "data" not in result


def test_maximum_acl_name_prefix_keeps_both_generated_names_within_ios_limit():
    prefix = "A" * 27
    _, _, text = run(event([attribute(), attribute("ip-src", "2001:db8::1")]), acl_name=prefix)
    assert f"ip access-list extended {prefix}-V4\n" in text
    assert f"ipv6 access-list {prefix}-V6\n" in text
    assert len(prefix + "-V4") == len(prefix + "-V6") == 30


@pytest.mark.parametrize("length", [28, 48])
def test_overlong_acl_name_prefix_returns_error_without_configuration(length):
    result = export.handler(json.dumps({"data": event([attribute()]), "config": {"acl_name": "A" * length}}))
    assert "error" in result and "data" not in result


def test_custom_names_and_log_warnings_are_visible_in_download_and_api():
    sections, result, text = run(
        event([attribute(), attribute("ip-src", "2001:db8::1")]), mode="log", acl_name="Threat_42"
    )
    assert "ip access-list extended Threat_42-V4\n" in text
    assert "ipv6 access-list Threat_42-V6\n" in text
    assert "! " + export.LOG_WARNING in text
    assert export.LOG_WARNING in result["warnings"] and export.POLICY_WARNING in result["warnings"]
    assert all(
        entry.startswith("permit ") and entry.endswith(" log") for entries in sections.values() for entry in entries
    )


def test_export_does_not_add_terminal_policy_interface_or_management_commands():
    data = event([attribute(comment="exit\npermit ip any any")], info="private event info")
    _, _, text = run(data)
    for command in (
        "permit ip any any",
        "permit ipv6 any any",
        "ip access-group",
        "ipv6 traffic-filter",
        "configure terminal",
        "write memory",
        "no ip access-list",
        "private event info",
    ):
        assert command not in text


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
def test_invalid_requests_return_errors(query):
    result = export.handler(query if isinstance(query, str) else json.dumps(query))
    assert "error" in result and "data" not in result


def test_empty_events_do_not_create_empty_acls_and_metadata_is_discoverable():
    assert export.handler() is False
    for data in ([], {}, {"Event": {}}, {"Attribute": []}):
        sections, result, text = run(data)
        assert sections == {4: [], 6: []} and result["summary"]["count"] == 0
        assert "access-list" not in text
    setup = export.introspection()
    assert setup["input"] == sorted(export.SUPPORTED_TYPES)
    assert setup["inputSource"] == ["event", "event-collection"]
    assert setup["outputFileExtension"] == "cfg"
    assert set(setup["userConfig"]) == {"mode", "acl_name", "resolve_dns"}
    assert export.version()["config"] == ["mode", "acl_name", "resolve_dns"]


class TestCiscoACLHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"cisco_acl_export": export, "type:cisco_acl_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_both_modes(self):
        descriptor = next(
            item for item in json.loads(self.fetch("/modules").body) if item["name"] == "cisco_acl_export"
        )
        assert descriptor["meta"]["config"] == ["mode", "acl_name", "resolve_dns"]
        assert "permits" in descriptor["mispattributes"]["userConfig"]["mode"]["message"]
        for config, expected in [
            ({}, b" deny ip any host 192.0.2.1\n"),
            ({"mode": "log"}, b" permit ip any host 192.0.2.1 log\n"),
        ]:
            response = self.fetch(
                "/query",
                method="POST",
                body=json.dumps(
                    {"module": "cisco_acl_export", "data": [{"Event": event([attribute()])}], "config": config}
                ),
            )
            assert response.code == 200
            assert expected in base64.b64decode(json.loads(response.body)["data"])
