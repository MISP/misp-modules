import base64
import copy
import json
import re
import shutil
import subprocess

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import squid_export as export


def attribute(kind="ip-dst", value="192.0.2.1", **metadata):
    return {"type": kind, "value": value, "to_ids": True, **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"Attribute": attributes or [], "Object": objects or [], **metadata}


def run(data):
    result = export.handler(json.dumps({"data": data}))
    assert "error" not in result, result
    text = base64.b64decode(result["data"], validate=True).decode("ascii")
    return [line for line in text.splitlines() if not line.startswith("#")], result


@pytest.mark.parametrize(
    "kind,value,conditions",
    [
        ("ip-src", "192.0.2.1", ["src 192.0.2.1"]),
        ("ip-dst", "2001:0DB8::1", ["dst 2001:db8::1"]),
        ("ip-src", "192.0.2.7/24", ["src 192.0.2.0/24"]),
        ("ip-dst", "2001:db8:1::42/48", ["dst 2001:db8:1::/48"]),
        ("ip-dst|port", "192.0.2.1|00443", ["dst 192.0.2.1", "port 443"]),
        ("ip-dst|port", "2001:db8::/32|65535", ["dst 2001:db8::/32", "port 65535"]),
        ("domain", "EXAMPLE.org.", ["dstdomain -n .example.org"]),
        ("hostname", "bücher.example", ["dstdomain -n xn--bcher-kva.example"]),
        ("domain|ip", "EXAMPLE.org.|192.0.2.1", ["dstdomain -n .example.org", "dst 192.0.2.1"]),
        ("domain|ip", "example.org|2001:db8::1", ["dstdomain -n .example.org", "dst 2001:db8::1"]),
        ("hostname|port", "EXAMPLE.org.|443", ["dstdomain -n example.org", "port 443"]),
        ("port", "80", ["port 80"]),
        ("url", "HTTP://EXAMPLE.org:80", [r"url_regex ^http://example\.org/$"]),
        ("url", "https://example.org/a?b=c#fragment", [r"url_regex ^https://example\.org/a\?b=c$"]),
        ("url", "https://[2001:0DB8::1]:8443/", [r"url_regex ^https://\[2001:db8::1\]:8443/$"]),
        ("url", "https://bücher.example/", [r"url_regex ^https://xn--bcher-kva\.example/$"]),
    ],
)
def test_squid_conditions_and_composite_conjunctions(kind, value, conditions):
    rules, result = run(event([attribute(kind, value)]))
    names = [f"misp_squid_1_{part}" for part in range(1, len(conditions) + 1)]
    assert rules == [
        *(f"acl {name} {condition}" for name, condition in zip(names, conditions)),
        f"http_access deny {' '.join(names)}",
    ]
    assert result["summary"] == {"count": 1, "skipped": {}}


def test_urls_are_exact_literal_case_sensitive_regexes():
    url = "http://example.org/A+(B)*[C]?q=$value&other=1.2%20test"
    rules, _ = run(event([attribute("url", url)]))
    pattern = rules[0].split(" ", 3)[3]
    assert re.fullmatch(pattern, url)
    for other in (url.lower(), url + "more", "prefix" + url, url.replace("example.org", "exampleXorg")):
        assert not re.search(pattern, other)
    assert " -i " not in rules[0]


def test_event_shapes_objects_order_deduplication_and_no_mutation():
    data = [
        {"Event": event([attribute()])},
        event(objects=[{"Attribute": [attribute(value="192.0.2.2")]}]),
        {"Event": {"id": "42"}, "Attribute": [attribute(value="192.0.2.3")]},
        {"Event": {"id": "43"}, "Object": [{"Attribute": [attribute()]}]},
    ]
    original = copy.deepcopy(data)
    rules, result = run(data)
    assert result["summary"] == {"count": 3, "skipped": {}}
    assert sum(line.startswith("http_access deny ") for line in rules) == 3
    assert data == original
    assert run(list(reversed(data)))[0] == rules


@pytest.mark.parametrize("flag", [True, 1, "1", "true", "TRUE"])
def test_true_ids_representations(flag):
    assert run(event([attribute(to_ids=flag)]))[1]["summary"]["count"] == 1


@pytest.mark.parametrize("flag", [False, 0, "0", "false", "FALSE", None, ""])
def test_false_ids_representations(flag):
    rules, result = run(event([attribute(to_ids=flag)]))
    assert not rules and result["summary"]["skipped"] == {"non-IDS": 1}


def test_missing_ids_deleted_records_and_non_ids_object_attributes_are_excluded():
    missing = attribute()
    del missing["to_ids"]
    data = [
        event([attribute(deleted="true"), missing]),
        event([attribute()], deleted="1"),
        event(objects=[{"deleted": True, "Attribute": [attribute()]}]),
        event(objects=[{"Attribute": [attribute(to_ids="0")]}]),
    ]
    rules, result = run(data)
    assert not rules
    assert result["summary"]["skipped"] == {"deleted": 1, "non-IDS": 2}


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-src", "all"),
        ("ip-dst", "192.0.2.1\nhttp_access allow all"),
        ("ip-dst", "192.0.2.1 #comment"),
        ("ip-dst", "999.1.2.3"),
        ("ip-dst", "192.0.2.1/33"),
        ("ip-dst", "2001:db8::/129"),
        ("ip-src", "fe80::1%eth0"),
        ("domain", "example.org\nhttp_access allow all"),
        ("domain", "example.org\x00"),
        ("domain", "example.org\x7f"),
        ("domain", "bad..example"),
        ("domain", "bad\ud800.example"),
        ("domain", "*.example.org"),
        ("domain", "all"),
        ("hostname", "192.0.2.1"),
        ("hostname", 'example.org"'),
        ("hostname", "a" * 64 + ".example"),
        ("hostname", ".".join(["a" * 63] * 4)),
        ("domain|ip", "example.org"),
        ("domain|ip", "example.org|192.0.2.1|80"),
        ("domain|ip", "example.org|all"),
        ("ip-dst|port", "192.0.2.1"),
        ("ip-dst|port", "192.0.2.1|65536"),
        ("hostname|port", "example.org|443|80"),
        ("port", "0"),
        ("port", "443-444"),
        ("port", "https"),
        ("port", "４４３"),
        ("port", 443),
        ("url", "file:///etc/passwd"),
        ("url", "https://user:password@example.org/a"),
        ("url", "https://example.org:65536/"),
        ("url", "https://example.org:/"),
        ("url", "https://example.org:0/"),
        ("url", "https://[fe80::1%25eth0]/"),
        ("url", "https://example.org/\nhttp_access allow all"),
        ("url", 'https://example.org/"file"'),
        ("url", "https://example.org/'file'"),
        ("url", "https://example.org/\\file"),
        ("url", "https://example.org/é"),
        ("url", "https://example.org/%xx"),
        ("ip-dst", None),
        ("domain", ""),
    ],
)
def test_malformed_and_injection_values_are_skipped_without_partial_rules(kind, value):
    rules, result = run(event([attribute(kind, value), attribute()]))
    assert rules == ["acl misp_squid_1_1 dst 192.0.2.1", "http_access deny misp_squid_1_1"]
    assert result["summary"]["skipped"] == {"malformed": 1}


@pytest.mark.parametrize("kind", ["ip-src|port", "uri", "AS", "mac-address", "email-src", "sha256", "user-agent"])
def test_unsupported_types_are_not_broadened(kind):
    rules, result = run(event([attribute(kind, "example.org|80")]))
    assert not rules and result["summary"]["skipped"] == {"unsupported": 1}


def test_export_is_offline_and_explains_url_and_port_scope(monkeypatch):
    import socket

    def no_network(*args, **kwargs):
        pytest.fail("Export must not perform DNS lookups")

    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket, "gethostbyname", no_network)
    _, result = run(
        event(
            [attribute("domain", "example.org"), attribute("url", "https://example.org/path"), attribute("port", "443")]
        )
    )
    assert any("CONNECT" in warning for warning in result["warnings"])
    assert any("all hosts" in warning for warning in result["warnings"])


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
    assert setup["responseType"] == "text/plain"
    assert export.version()["module-type"] == ["export"]
    assert export.version()["config"] == []


class TestSquidHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"squid_export": export, "type:squid_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_export(self):
        response = self.fetch("/modules")
        descriptor = next(module for module in json.loads(response.body) if module["name"] == "squid_export")
        assert descriptor["mispattributes"]["outputFileExtension"] == "conf"
        response = self.fetch(
            "/query",
            method="POST",
            body=json.dumps(
                {"module": "squid_export", "data": [{"Event": event([attribute(), attribute(to_ids=False)])}]}
            ),
        )
        assert response.code == 200
        result = json.loads(response.body)
        assert b"http_access deny misp_squid_1_1\n" in base64.b64decode(result["data"])
        assert result["summary"] == {"count": 1, "skipped": {"non-IDS": 1}}


@pytest.mark.skipif(shutil.which("squid") is None, reason="Squid is not installed")
def test_native_squid_syntax(tmp_path):
    rules, _ = run(
        event(
            [
                attribute("ip-src", "192.0.2.0/24"),
                attribute("ip-dst", "2001:db8::/32"),
                attribute("ip-dst|port", "2001:db8::1|443"),
                attribute("domain", "example.org"),
                attribute("hostname", "host.example.org"),
                attribute("domain|ip", "example.net|192.0.2.1"),
                attribute("hostname|port", "host.example.net|443"),
                attribute("url", "http://example.org/A+(B)*[C]?q=$value&n=1.2"),
                attribute("url", "https://[2001:db8::2]:8443/"),
                attribute("port", "8080"),
            ]
        )
    )
    path = tmp_path / "squid.conf"
    path.write_text("\n".join(["visible_hostname misp-test", *rules, "http_access deny all"]) + "\n")
    subprocess.run(["squid", "-k", "parse", "-f", str(path)], check=True, capture_output=True, text=True)
