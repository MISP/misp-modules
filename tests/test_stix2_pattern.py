import json
from unittest.mock import patch

import pytest
from stix2patterns.v21.pattern import Pattern
from stix2patterns.validator import run_validator
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.modules.expansion import stix2_pattern as module


def generate(kind="domain", value="example.org", **metadata):
    attribute = {"type": kind, "value": value, **metadata}
    result = module.handler(json.dumps({"attribute": attribute}))
    assert "error" not in result, result
    output = result["results"]["Attribute"][0]
    assert output["type"] == "stix2-pattern"
    assert output["to_ids"] is True
    assert not run_validator(output["value"], stix_version="2.1")
    return output["value"]


def test_discovery():
    assert module.handler() is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.introspection()["output"] == ["stix2-pattern"]
    assert module.version()["module-type"] == ["expansion", "hover"]


@pytest.mark.parametrize(
    "kind,length,algorithm",
    [("md5", 32, "MD5"), ("sha1", 40, "SHA-1"), ("sha256", 64, "SHA-256"), ("imphash", 32, "IMPHASH")],
)
def test_hash_mappings(kind, length, algorithm):
    pattern = generate(kind, "a" * length)
    comparison = Pattern(pattern).inspect().comparisons["file"]
    assert comparison == [(["hashes", algorithm], "=", "'" + "a" * length + "'")]


def test_composite_is_one_conjunction():
    pattern = generate("filename|sha256", "example.exe|" + "a" * 64)
    comparisons = Pattern(pattern).inspect().comparisons["file"]
    assert comparisons == [(["name"], "=", "'example.exe'"), (["hashes", "SHA-256"], "=", "'" + "a" * 64 + "'")]
    assert " AND " in pattern and " OR " not in pattern


@pytest.mark.parametrize("direction", ["src", "dst"])
@pytest.mark.parametrize("address,version", [("192.0.2.1", "ipv4-addr"), ("2001:db8::1", "ipv6-addr")])
def test_ip_direction_and_port_are_preserved(direction, address, version):
    comparisons = Pattern(generate(f"ip-{direction}|port", f"{address}|443")).inspect().comparisons["network-traffic"]
    assert ([f"{direction}_ref", "type"], "=", f"'{version}'") in comparisons
    assert ([f"{direction}_ref", "value"], "=", f"'{address}'") in comparisons
    assert ([f"{direction}_port"], "=", "'443'") in comparisons


@pytest.mark.parametrize(
    "kind,value",
    [
        ("domain", "example.org"),
        ("hostname", "host.example.org"),
        ("domain|ip", "example.org|192.0.2.1"),
        ("hostname|port", "host.example.org|443"),
        ("url", "https://example.org/path"),
        ("email-src", "source@example.org"),
        ("email-dst", "dest@example.org"),
        ("email-subject", "Subject"),
        ("mutex", "example-mutex"),
        ("regkey", r"HKLM\Software\Example"),
        ("regkey|value", r"HKLM\Software\Example|data"),
        ("AS", "AS64512"),
        ("mac-address", "00:11:22:33:44:55"),
        ("port", "443"),
        ("size-in-bytes", "42"),
        ("x509-fingerprint-sha256", "a" * 64),
        ("malware-sample", "example.exe|" + "a" * 32),
    ],
)
def test_other_misp_stix_mappings(kind, value):
    generate(kind, value)


def test_literal_cannot_inject_a_comparison():
    value = r"C:\O'Brien\file.exe' OR file:name = 'other"
    pattern = generate("filename", value)
    comparisons = Pattern(pattern).inspect().comparisons
    assert list(comparisons) == ["file"]
    assert len(comparisons["file"]) == 1
    literal = comparisons["file"][0][2][1:-1]
    assert literal.replace("\\'", "'").replace("\\\\", "\\") == value


def test_legacy_request_and_explicit_non_ids_generation():
    result = module.handler(json.dumps({"domain": "example.org", "attribute_uuid": "source"}))
    assert result["results"]["Attribute"][0]["value"] == generate(to_ids=False)


@pytest.mark.parametrize(
    "kind,value",
    [
        ("sha256", "invalid"),
        ("filename|sha256", "missing hash"),
        ("domain|ip", "example.org"),
        ("ip-src|port", "192.0.2.1|65536"),
        ("ip-dst", "invalid"),
        ("port", "65536"),
        ("yara", "rule x { condition: true }"),
        ("domain", None),
        ("domain", ""),
    ],
)
def test_invalid_or_lossy_values_return_error(kind, value):
    result = module.handler(json.dumps({"attribute": {"type": kind, "value": value}}))
    assert "error" in result and "results" not in result


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"attribute": None},
        {"attribute": []},
        {"domain": "example.org", "sha256": "a" * 64},
        {"attribute": {"type": [], "value": "value"}},
    ],
)
def test_bad_request(payload):
    assert "error" in module.handler(json.dumps(payload))


def test_deleted_and_malformed_json():
    assert "error" in module.handler(
        json.dumps({"attribute": {"type": "domain", "value": "example.org", "deleted": "1"}})
    )
    assert "error" in module.handler("{")
    assert generate() == "[domain-name:value = 'example.org']"


class TestSTIX2PatternHTTP(AsyncHTTPTestCase):
    def get_app(self):
        handlers = {"stix2_pattern": module, "type:stix2_pattern": "expansion"}
        self.handlers_patch = patch.object(server, "MODULES_HANDLERS", handlers)
        self.handlers_patch.start()
        self.addCleanup(self.handlers_patch.stop)
        return Application([(r"/query", server.QueryModule), (r"/modules", server.ListModules)])

    def test_discovery_and_generation(self):
        discovery = json.loads(self.fetch("/modules").body)
        assert discovery[0]["name"] == "stix2_pattern"
        response = self.fetch(
            "/query", method="POST", body=json.dumps({"module": "stix2_pattern", "domain": "example.org"})
        )
        assert response.code == 200
        result = json.loads(response.body)
        assert result["results"]["Attribute"][0]["value"] == "[domain-name:value = 'example.org']"
