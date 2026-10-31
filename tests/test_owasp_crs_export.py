import base64
import copy
import ctypes
import ctypes.util
import json
import re

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import owasp_crs_export as export


def attribute(kind="ip-src", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "to_ids": True, **metadata}


def run(attributes=None, *, data=None, config=None):
    result = export.handler(
        json.dumps({"data": {"Attribute": attributes or []} if data is None else data, "config": config})
    )
    assert "error" not in result, result
    return base64.b64decode(result["data"], validate=True).decode("ascii"), result


@pytest.mark.parametrize("flag", [True, 1, "true", "TRUE", "1"])
def test_only_explicit_ids_flags_are_exported(flag):
    _, result = run([attribute(to_ids=flag)])
    assert result["summary"] == {"count": 1, "skipped": {}}


@pytest.mark.parametrize("flag", [False, 0, "false", "FALSE", "0", None, ""])
def test_false_ids_flags_are_excluded(flag):
    text, result = run([attribute(to_ids=flag)])
    assert "SecRule " not in text
    assert result["summary"] == {"count": 0, "skipped": {"non-IDS": 1}}


def test_missing_ids_deleted_events_objects_and_attributes():
    missing = attribute()
    del missing["to_ids"]
    data = [
        {"Event": {"Attribute": [missing, attribute(deleted="true")]}},
        {"Event": {"deleted": True, "Attribute": [attribute()]}},
        {"Object": [{"deleted": "1", "Attribute": [attribute()]}]},
        {"Object": [{"Attribute": [attribute(to_ids="0")]}]},
    ]
    text, result = run(data=data)
    assert "SecRule " not in text
    assert result["summary"] == {"count": 0, "skipped": {"non-IDS": 2, "deleted": 1}}


def test_event_shapes_deduplication_order_and_no_mutation():
    data = [
        {"Event": {"Attribute": [attribute()]}},
        {"Attribute": [attribute(value="192.0.2.2")]},
        {"Event": {"id": "42"}, "Attribute": [attribute(value="192.0.2.3")]},
        {"Event": {"Object": [{"Attribute": [attribute(value="192.0.2.4")]}]}},
        {"Event": {"id": "43"}, "Object": [{"Attribute": [attribute(value="192.0.2.5")]}]},
        {"Attribute": [attribute()]},
    ]
    original = copy.deepcopy(data)
    first, result = run(data=data)
    assert result["summary"] == {"count": 5, "skipped": {}}
    assert run(data=list(reversed(data)))[0] == first
    assert run(data=data[0])[1]["summary"]["count"] == 1
    assert data == original
    assert re.findall(r"id:(\d+)", first) == [str(number) for number in range(10000, 10005)]


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-src", "all"),
        ("ip-src", "192.0.2.1\nSecRuleEngine Off"),
        ("ip-src", "192.0.2.1/33"),
        ("ip-src", "2001:db8::/129"),
        ("ip-src", "fe80::1%eth0"),
        ("ip-src|port", "192.0.2.1"),
        ("ip-src|port", "192.0.2.1|0"),
        ("ip-src|port", "192.0.2.1|65536"),
        ("ip-src|port", "192.0.2.1|４４３"),
        ("domain", 'example.org"'),
        ("domain", "example.org\x00"),
        ("domain", "example.org\x7f"),
        ("domain", "example.org SecRuleEngine Off"),
        ("domain", "*.example.org"),
        ("domain", "bad..example"),
        ("domain", "bad\ud800.example"),
        ("domain", "a" * 64 + ".example"),
        ("hostname", "192.0.2.1"),
        ("hostname|port", "example.org|80|443"),
        ("url", "file:///etc/passwd"),
        ("url", "https://user:password@example.org/"),
        ("url", "https://example.org:/"),
        ("url", "https://example.org:0/"),
        ("url", "https://example.org:65536/"),
        ("url", "https://[fe80::1%25eth0]/"),
        ("url", "https://[v1.example]/"),
        ("url", "https://example.org/é"),
        ("url", "https://example.org/%xx"),
        ("url", "https://example.org/\\file"),
        ("uri", "relative/path"),
        ("uri", "/path#fragment"),
        ("uri", "/path\nSecRuleEngine Off"),
        ("user-agent", "agent\r\nSecRuleEngine Off"),
        ("user-agent", "ü"),
        ("user-agent", 123),
        ("domain", None),
        ("domain", ""),
    ],
)
def test_malformed_values_never_emit_partial_rules(kind, value):
    text, result = run([attribute(kind, value), attribute()])
    assert text.count("SecRule ") == 1
    assert "@ipMatch 192.0.2.1" in text
    assert result["summary"] == {"count": 1, "skipped": {"malformed": 1}}


@pytest.mark.parametrize("kind", ["ip-dst", "ip-dst|port", "domain|ip", "port", "sha256", "email-src", "AS"])
def test_unsupported_types_do_not_become_broader_blocks(kind):
    text, result = run([attribute(kind, "example.org|192.0.2.1")])
    assert "SecRule " not in text
    assert result["summary"]["skipped"] == {"unsupported": 1}


@pytest.mark.parametrize("value", [10000, "20000", 99999, "", None])
def test_configurable_ids(value):
    text, _ = run([attribute()], config={"rule_id_start": value})
    assert f"id:{value or 10000}," in text


@pytest.mark.parametrize("value", [True, False, 10000.0, 9999, 100000, "10000,pass", [], {}])
def test_invalid_rule_id_configuration(value):
    result = export.handler(json.dumps({"data": {}, "config": {"rule_id_start": value}}))
    assert "error" in result and "data" not in result


def test_id_range_exhaustion_and_chained_rule_ids():
    text, result = run([attribute("ip-src|port", "192.0.2.1|443")], config={"rule_id_start": 99999})
    assert result["summary"]["count"] == 1
    assert text.count("id:") == 1 and text.count("SecRule ") == 2
    assert ',chain"\nSecRule REMOTE_PORT' in text
    result = export.handler(
        json.dumps(
            {"data": {"Attribute": [attribute(), attribute(value="192.0.2.2")]}, "config": {"rule_id_start": 99999}}
        )
    )
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
        {"data": {"Object": [{"Attribute": [1]}]}},
        {"data": {"Attribute": [attribute(to_ids="yes")]}},
        {"data": {}, "config": []},
    ],
)
def test_invalid_requests_return_errors_without_output(query):
    result = export.handler(query if isinstance(query, str) else json.dumps(query))
    assert "error" in result and "data" not in result


def test_empty_events_metadata_and_offline_export(monkeypatch):
    import socket

    def no_dns(*args, **kwargs):
        pytest.fail("Exporter must not resolve indicators")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    monkeypatch.setattr(socket, "gethostbyname", no_dns)
    assert export.handler() is False
    for data in ([], {}, {"Event": {}}):
        assert "SecRule " not in run(data=data)[0]
    _, result = run([attribute("domain", "example.org"), attribute("url", "https://example.org/path")])
    assert any("CONNECT" in message for message in result["warnings"])
    assert any("anomaly" in message for message in result["warnings"])
    assert export.introspection()["input"] == sorted(export.SUPPORTED_TYPES)
    assert export.introspection()["outputFileExtension"] == "conf"
    assert export.version()["module-type"] == ["export"]
    assert export.version()["config"] == ["rule_id_start"]


class TestCRSHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"owasp_crs_export": export, "type:owasp_crs_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_export(self):
        response = self.fetch("/modules")
        descriptor = next(module for module in json.loads(response.body) if module["name"] == "owasp_crs_export")
        assert descriptor["mispattributes"]["outputFileExtension"] == "conf"
        response = self.fetch(
            "/query",
            method="POST",
            body=json.dumps(
                {"module": "owasp_crs_export", "data": {"Event": {"Attribute": [attribute(), attribute(to_ids=False)]}}}
            ),
        )
        assert response.code == 200
        result = json.loads(response.body)
        assert b"@ipMatch 192.0.2.1" in base64.b64decode(result["data"])
        assert result["summary"] == {"count": 1, "skipped": {"non-IDS": 1}}


@pytest.fixture(scope="module")
def modsecurity():
    """Optional native checks: install libmodsecurity3 (or expose it through LD_LIBRARY_PATH)."""
    try:
        library = ctypes.CDLL(ctypes.util.find_library("modsecurity") or "libmodsecurity.so.3")
    except OSError:
        pytest.skip("libmodsecurity3 is not installed")
    pointer, string, integer = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
    signatures = {
        "msc_init": (pointer, []),
        "msc_create_rules_set": (pointer, []),
        "msc_rules_add": (integer, [pointer, string, ctypes.POINTER(string)]),
        "msc_new_transaction": (pointer, [pointer, pointer, pointer]),
        "msc_process_connection": (integer, [pointer, string, integer, string, integer]),
        "msc_process_uri": (integer, [pointer, string, string, string]),
        "msc_add_request_header": (integer, [pointer, string, string]),
        "msc_process_request_headers": (integer, [pointer]),
        "msc_intervention": (integer, [pointer, pointer]),
        "msc_intervention_cleanup": (None, [pointer]),
        "msc_transaction_cleanup": (None, [pointer]),
        "msc_rules_cleanup": (integer, [pointer]),
        "msc_cleanup": (None, [pointer]),
    }
    for name, (restype, argtypes) in signatures.items():
        getattr(library, name).restype = restype
        getattr(library, name).argtypes = argtypes
    return library


class Intervention(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("pause", ctypes.c_int),
        ("url", ctypes.c_void_p),
        ("log", ctypes.c_void_p),
        ("disruptive", ctypes.c_int),
    ]


def native_status(
    library, attributes, *, host="example.org", uri="/", client="198.51.100.1", port=12345, agent="test", mode="On"
):
    text, _ = run(attributes)
    engine, rules = library.msc_init(), library.msc_create_rules_set()
    transaction = None
    intervention = Intervention(status=200)
    try:
        error = ctypes.c_char_p()
        # Inherited transformations must not alter exact indicator matching.
        config = f'SecRuleEngine {mode}\nSecDefaultAction "phase:1,pass,log,t:lowercase"\n' + text
        assert library.msc_rules_add(rules, config.encode(), ctypes.byref(error)) >= 0, error.value
        transaction = library.msc_new_transaction(engine, rules, None)
        library.msc_process_connection(transaction, client.encode(), port, b"203.0.113.1", 80)
        library.msc_process_uri(transaction, uri.encode(), b"GET", b"1.1")
        library.msc_add_request_header(transaction, b"Host", host.encode())
        library.msc_add_request_header(transaction, b"User-Agent", agent.encode())
        library.msc_process_request_headers(transaction)
        library.msc_intervention(transaction, ctypes.byref(intervention))
        return intervention.status
    finally:
        library.msc_intervention_cleanup(ctypes.byref(intervention))
        if transaction:
            library.msc_transaction_cleanup(transaction)
        library.msc_rules_cleanup(rules)
        library.msc_cleanup(engine)


@pytest.mark.parametrize(
    "kind,value,traffic,blocked",
    [
        ("ip-src", "198.51.100.7/24", {}, True),
        ("ip-src", "2001:db8::/32", {"client": "2001:db8::7"}, True),
        ("ip-src", "192.0.2.1", {}, False),
        ("ip-src|port", "198.51.100.1|12345", {}, True),
        ("ip-src|port", "198.51.100.1|12345", {"port": 54321}, False),
        ("ip-src|port", "192.0.2.1|12345", {}, False),
        ("domain", "EXAMPLE.org.", {"host": "a.EXAMPLE.org.:443"}, True),
        ("domain", "example.org", {"host": "evilexample.org"}, False),
        ("domain", "example.org", {"host": "example.org.evil.test"}, False),
        ("hostname", "example.org", {"host": "a.example.org"}, False),
        ("hostname", "bücher.example", {"host": "xn--bcher-kva.example:80"}, True),
        ("hostname|port", "EXAMPLE.org|00443", {"host": "example.org:443"}, True),
        ("hostname|port", "example.org|443", {"host": "example.org:80"}, False),
        ("hostname|port", "example.org|443", {}, False),
        ("url", "https://example.org/A?x=1#fragment", {"uri": "/A?x=1"}, True),
        ("url", "https://example.org/A?x=1", {"uri": "/a?x=1"}, False),
        ("url", "https://example.org/A?x=1", {"uri": "/A?x=1&y=2"}, False),
        ("url", "https://example.org/A?x=1", {"host": "other.example", "uri": "/A?x=1"}, False),
        ("url", "https://example.org/A?x=1", {"uri": "https://EXAMPLE.org:443/A?x=1"}, True),
        ("url", "https://example.org/A?x=1", {"uri": "http://example.org/A?x=1"}, False),
        ("url", "https://example.org:8443/", {"host": "example.org:8443"}, True),
        ("url", "https://example.org:8443/", {}, False),
        ("url", "http://[2001:db8::1]:8080/", {"host": "[2001:db8::1]:8080"}, True),
        ("url", "http://example.org", {}, True),
        ("url", "https://example.org/A", {"uri": "HTTPS://EXAMPLE.org/A"}, True),
        ("url", "http://example.org/?", {"uri": "/?"}, True),
        ("url", "http://example.org/?", {}, False),
        ("url", "http://example.org/a'b", {"uri": "/a'b"}, True),
        ("uri", "/A+(b)?q=$x&y=%20", {"uri": "/A+(b)?q=$x&y=%20"}, True),
        ("uri", "/A", {"uri": "/a"}, False),
        ("uri", "/A", {"uri": "/AA"}, False),
        ("user-agent", "Bot/1.0 (Exact)", {"agent": "Bot/1.0 (Exact)"}, True),
        ("user-agent", "Bot/1.0 (Exact)", {"agent": "bot/1.0 (exact)"}, False),
        ("user-agent", "x\" ,pass,' \\ %{TX.foo} #", {"agent": "x\" ,pass,' \\ %{TX.foo} #"}, True),
    ],
)
def test_native_modsecurity_matching(modsecurity, kind, value, traffic, blocked):
    assert native_status(modsecurity, [attribute(kind, value)], **traffic) == (403 if blocked else 200)


def test_native_detection_only_and_ids_filter(modsecurity):
    assert native_status(modsecurity, [attribute("domain", "example.org")], mode="DetectionOnly") == 200
    assert native_status(modsecurity, [attribute("domain", "example.org", to_ids="false")]) == 200
