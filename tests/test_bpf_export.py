import base64
import copy
import ipaddress
import json
import os
import shutil
import struct
import subprocess

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import bpf_export as export


def attribute(kind="ip-dst", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "to_ids": True, **metadata}


def run(attributes=None, data=None):
    result = export.handler(json.dumps({"data": data if data is not None else {"Attribute": attributes or []}}))
    assert "error" not in result, result
    return base64.b64decode(result["data"], validate=True).decode("ascii"), result


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("ip-src", "192.0.2.1", "(ip src host 192.0.2.1)"),
        ("ip-dst", "2001:0DB8::1", "(ip6 dst host 2001:db8::1)"),
        ("ip-src", "192.0.2.7/24", "(ip src net 192.0.2.0/24)"),
        ("ip-dst", "2001:db8:1::42/48", "(ip6 dst net 2001:db8:1::/48)"),
        ("ip-src|port", "192.0.2.1|00443", "(ip src host 192.0.2.1 and (tcp or udp) and src port 443)"),
        ("ip-dst|port", "2001:db8::/32|65535", "(ip6 dst net 2001:db8::/32 and (tcp or udp) and dst port 65535)"),
        ("domain", "EXAMPLE.org.", "(host example.org)"),
        ("hostname", "bücher.example", "(host xn--bcher-kva.example)"),
        ("domain|ip", "example.org|192.0.2.1", "(ip host 192.0.2.1)"),
        ("domain|ip", "example.org|2001:db8::1", "(ip6 host 2001:db8::1)"),
        ("hostname|port", "example.org|80", "(dst host example.org and (tcp or udp) and dst port 80)"),
        ("port", "0", "((tcp or udp) and dst port 0)"),
        ("mac-address", "AA-BB-CC-DD-EE-FF", "(ether host aa:bb:cc:dd:ee:ff)"),
    ],
)
def test_supported_types(kind, value, expected):
    text, result = run([attribute(kind, value)])
    assert text == expected + "\n"
    assert result["summary"] == {"count": 1, "skipped": {}}


def test_event_shapes_objects_deduplication_and_no_mutation():
    data = [
        {"Event": {"Attribute": [attribute()]}},
        {"Object": [{"Attribute": [attribute(), attribute(value="192.0.2.2")]}]},
        {"Event": {"id": "42"}, "Attribute": [attribute(value="192.0.2.3")]},
        {"Event": {"id": "43"}, "Object": [{"Attribute": [attribute()]}]},
    ]
    original = copy.deepcopy(data)
    text, result = run(data=data)
    assert text == " or\n".join(f"(ip dst host 192.0.2.{i})" for i in range(1, 4)) + "\n"
    assert result["summary"]["count"] == 3
    assert data == original
    assert run(data=list(reversed(data)))[0] == text


@pytest.mark.parametrize("flag", [True, 1, "1", "true", "TRUE"])
def test_ids_flags(flag):
    assert run([attribute(to_ids=flag)])[1]["summary"]["count"] == 1


def test_exclusions():
    data = [
        {
            "Attribute": [
                attribute(),
                attribute(to_ids=False),
                attribute(to_ids="false"),
                attribute(deleted="true"),
                attribute("url", "https://example.org/path"),
            ]
        },
        {"deleted": True, "Attribute": [attribute(value="192.0.2.2")]},
        {"Object": [{"deleted": "1", "Attribute": [attribute(value="192.0.2.3")]}]},
    ]
    text, result = run(data=data)
    assert text == "(ip dst host 192.0.2.1)\n"
    assert result["summary"]["skipped"] == {"non-IDS": 2, "deleted": 1, "unsupported": 1}


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-dst", "192.0.2.1 or host 203.0.113.1"),
        ("ip-dst", "192.0.2.1\n"),
        ("ip-src", "any"),
        ("ip-dst", "999.1.2.3"),
        ("ip-dst", "fe80::1%eth0"),
        ("ip-src", "192.0.2.1/33"),
        ("ip-dst", "2001:db8::/129"),
        ("ip-src|port", "192.0.2.1"),
        ("ip-dst|port", "192.0.2.1|65536"),
        ("port", "https"),
        ("port", "４４３"),
        ("port", "-1"),
        ("port", 443),
        ("domain", "*.example.org"),
        ("hostname", "tcp"),
        ("domain", "192.0.2.1"),
        ("domain", "a..example"),
        ("domain", "bad\ud800.example"),
        ("domain", "example.org\x00"),
        ("domain|ip", "example.org|192.0.2.1|443"),
        ("domain|ip", "example.org"),
        ("hostname|port", "example.org|443|80"),
        ("mac-address", "aa:bb:cc:dd:ee:ff or ip"),
        ("ip-src", None),
    ],
)
def test_malformed_values_are_skipped_atomically(kind, value):
    text, result = run([attribute(), attribute(kind, value)])
    assert text == "(ip dst host 192.0.2.1)\n"
    assert result["summary"]["skipped"] == {"malformed": 1}


@pytest.mark.parametrize("data", [[], {}, {"Event": {}}, {"Attribute": [attribute(to_ids=False)]}])
def test_no_matches_never_produces_an_empty_capture_filter(data):
    result = export.handler(json.dumps({"data": data}))
    assert "error" in result and "data" not in result
    assert result["summary"]["count"] == 0


@pytest.mark.parametrize(
    "data",
    [None, "event", [1], {"Event": []}, {"Attribute": {}}, {"Object": [1]}, {"Attribute": [attribute(to_ids="yes")]}],
)
def test_invalid_input(data):
    result = export.handler(json.dumps({"data": data}))
    assert "error" in result and "data" not in result


def test_metadata_and_no_dns_at_export_time(monkeypatch):
    import socket

    def no_network(*args, **kwargs):
        pytest.fail("Export must not resolve DNS")

    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket, "gethostbyname", no_network)
    _, result = run(
        [attribute("domain", "example.org"), attribute("port", "443"), attribute("mac-address", "00:11:22:33:44:55")]
    )
    assert len(result["warnings"]) == 3
    assert export.handler() is False
    assert "error" in export.handler("{")
    assert "error" in export.handler("[]")
    assert export.introspection()["input"] == sorted(export.SUPPORTED_TYPES)
    assert export.introspection()["outputFileExtension"] == "bpf"
    assert export.version()["config"] == []


class TestBPFHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"bpf_export": export, "type:bpf_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_export(self):
        modules = json.loads(self.fetch("/modules").body)
        descriptor = next(module for module in modules if module["name"] == "bpf_export")
        assert descriptor["mispattributes"]["outputFileExtension"] == "bpf"
        response = self.fetch(
            "/query",
            method="POST",
            body=json.dumps(
                {
                    "module": "bpf_export",
                    "data": [{"Event": {"Attribute": [attribute()]}}],
                }
            ),
        )
        assert response.code == 200
        assert base64.b64decode(json.loads(response.body)["data"]) == b"(ip dst host 192.0.2.1)\n"


TCPDUMP = os.environ.get("TCPDUMP") or shutil.which("tcpdump")


def packet(source, destination, sport=12345, dport=443, protocol=6):
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    transport = struct.pack("!HH", sport, dport) + b"\0" * 16
    if src.version == 4:
        network = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, protocol, 0, src.packed, dst.packed)
        ethertype = 0x0800
    else:
        network = struct.pack("!IHBB16s16s", 6 << 28, 20, protocol, 64, src.packed, dst.packed)
        ethertype = 0x86DD
    return bytes.fromhex("001122334455aabbccddeeff") + struct.pack("!H", ethertype) + network + transport


@pytest.mark.skipif(not TCPDUMP, reason="tcpdump is not installed")
@pytest.mark.parametrize(
    "kind,value,packets,expected",
    [
        ("ip-src", "192.0.2.1", [packet("192.0.2.1", "198.51.100.1"), packet("198.51.100.1", "192.0.2.1")], 1),
        ("ip-dst", "2001:db8::/32", [packet("2001:db8::1", "2001:db9::1"), packet("2001:db9::1", "2001:db8::2")], 1),
        (
            "ip-src|port",
            "192.0.2.0/24|443",
            [
                packet("192.0.2.1", "198.51.100.1", sport=443),
                packet("192.0.2.1", "198.51.100.1"),
                packet("192.0.2.1", "198.51.100.1", sport=443, protocol=132),
            ],
            1,
        ),
        (
            "ip-dst|port",
            "2001:db8::1|443",
            [
                packet("2001:db9::1", "2001:db8::1"),
                packet("2001:db9::1", "2001:db8::1", dport=80),
                packet("2001:db9::1", "2001:db8::1", protocol=17),
            ],
            2,
        ),
        (
            "domain|ip",
            "example.org|192.0.2.1",
            [
                packet("192.0.2.1", "198.51.100.1"),
                packet("198.51.100.1", "192.0.2.1"),
                packet("198.51.100.1", "203.0.113.1"),
            ],
            2,
        ),
        ("port", "443", [packet("192.0.2.1", "198.51.100.1"), packet("192.0.2.1", "198.51.100.1", dport=80)], 1),
        ("mac-address", "aa:bb:cc:dd:ee:ff", [packet("192.0.2.1", "198.51.100.1")], 1),
    ],
)
def test_tcpdump_packet_matching(tmp_path, kind, value, packets, expected):
    capture = tmp_path / "input.pcap"
    with capture.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(packets):
            stream.write(struct.pack("<IIII", index, 0, len(frame), len(frame)))
            stream.write(frame)
    # Include an unrelated OR branch to check precedence as well as each individual match.
    expression, _ = run([attribute(kind, value), attribute(value="203.0.113.99")])
    filter_file = tmp_path / "filter.bpf"
    filter_file.write_text(expression)
    compiled = subprocess.run(
        [TCPDUMP, "-ddd", "-r", str(capture), "-F", str(filter_file)], capture_output=True, text=True
    )
    assert compiled.returncode == 0, compiled.stderr
    filtered = subprocess.run(
        [TCPDUMP, "-nn", "-r", str(capture), "-F", str(filter_file)], capture_output=True, text=True
    )
    assert filtered.returncode == 0, filtered.stderr
    assert len(filtered.stdout.splitlines()) == expected
