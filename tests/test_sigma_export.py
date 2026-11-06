import base64
import copy
import io
import json
import re
import zipfile
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker
from pymisp import MISPEvent, MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.modules.export_mod import sigma_export as module

STORED = """title: Existing Linux Rule
id: 5e668309-198b-4a4a-af88-231e067dd2b8
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/example
  condition: selection
"""
SCHEMA = json.loads((Path(__file__).parent / "test_files/sigma_detection_rule_schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def attribute(kind="domain", value="example.org", **metadata):
    return {"type": kind, "value": value, "to_ids": True, "uuid": "attribute-1", **metadata}


def event(attributes=None, **metadata):
    return {"uuid": "event-1", "Attribute": attributes if attributes is not None else [attribute()], **metadata}


def run(data=None, **config):
    result = module.handler(json.dumps({"data": event() if data is None else data, "config": config}))
    assert "error" not in result, result
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(result["data"], validate=True))) as archive:
        assert archive.testzip() is None
        files = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(files.pop("manifest.json"))
    assert result["summary"] == manifest["summary"]
    return files, manifest, result


def one_rule(kind="domain", value="example.org"):
    files, manifest, result = run(event([attribute(kind, value)]), mode="indicators")
    assert len(files) == 1
    rule = yaml.safe_load(next(iter(files.values())))
    VALIDATOR.validate(rule)
    return rule, manifest, result


def test_discovery_and_false_handler():
    assert module.handler(False) is False
    setup = module.introspection()
    assert setup["inputSource"] == ["event", "event-collection"]
    assert setup["outputFileExtension"] == "zip"
    assert setup["responseType"] == "application/zip"
    assert module.version()["module-type"] == ["export"]
    assert module.version()["config"] == ["mode", "include_non_ids"]


def test_default_preserves_stored_rules_even_without_ids_flag():
    original = STORED + "\n---\n" + STORED.replace("Existing Linux Rule", "Second Rule")
    files, manifest, result = run(event([attribute("sigma", original, to_ids=False), attribute()]))
    assert list(files.values()) == [original.encode()]
    assert manifest["mode"] == "rules"
    assert result["summary"]["stored_rules"] == 1
    assert result["summary"]["generated_rules"] == 0
    assert result["summary"]["skipped"] == {"excluded by mode": 1}


def test_stored_rule_contents_are_not_parsed_or_executed():
    contents = "!!python/object/apply:os.system ['must never execute']\n"
    with patch.object(module.yaml, "safe_load", side_effect=AssertionError("Stored rules must remain opaque")):
        files, _, _ = run(event([attribute("sigma", contents)]))
    assert next(iter(files.values())) == contents.encode()


@pytest.mark.parametrize("shape", ["bare", "standard", "legacy"])
def test_event_envelopes_and_sigma_objects(shape):
    obj = {"name": "sigma", "uuid": "object-1", "Attribute": [attribute("sigma", STORED, to_ids=False)]}
    bare = event([], Object=[obj], info="example")
    data = bare if shape == "bare" else {"Event": bare}
    if shape == "legacy":
        data = {"Event": {"uuid": "event-1", "info": "example"}, "Object": [obj], "Attribute": []}
    files, manifest, _ = run(data)
    assert next(iter(files.values())) == STORED.encode()
    assert next(iter(manifest["sources"].values())) == [
        {"event": "event-1", "object": "object-1", "attribute": "attribute-1", "misp_type": "sigma"}
    ]


def test_real_pymisp_event_and_sigma_object():
    misp_event = MISPEvent()
    misp_event.info = "Export test"
    obj = MISPObject("sigma")
    obj.add_attribute("sigma", STORED, to_ids=False)
    misp_event.add_object(obj)
    payload = json.loads(misp_event.to_json())
    files, _, _ = run(payload)
    assert next(iter(files.values())) == payload["Object"][0]["Attribute"][0]["value"].encode()


SAMPLES = [
    ("md5", "a" * 32),
    ("sha1", "b" * 40),
    ("sha256", "c" * 64),
    ("imphash", "d" * 32),
    ("filename", "example.exe"),
    ("filename", r"C:\Program Files\example.exe"),
    ("filename|md5", "example.exe|" + "a" * 32),
    ("filename|sha1", "example.exe|" + "b" * 40),
    ("filename|sha256", "example.exe|" + "c" * 64),
    ("filename|imphash", "example.dll|" + "d" * 32),
    ("malware-sample", "example.exe|" + "a" * 32),
    ("domain", "Example.ORG."),
    ("hostname", "host.example.org"),
    ("domain", "café.example"),
    ("ip-src", "192.0.2.1"),
    ("ip-dst", "2001:db8::1"),
    ("ip-src", "192.0.2.0/24"),
    ("ip-dst", "2001:db8::/32"),
    ("ip-src|port", "192.0.2.1|443"),
    ("ip-dst|port", "2001:db8::1|0443"),
]


@pytest.mark.parametrize("kind,value", SAMPLES)
def test_generated_rules_validate_against_upstream_sigma_schema(kind, value):
    rule, _, _ = one_rule(kind, value)
    assert UUID(rule["id"]).version == 5
    assert rule["status"] == "experimental"
    assert rule["logsource"]["product"] == "windows"
    assert rule["detection"]["condition"] == "selection"


def test_compound_hash_and_port_matches_are_conjunctions():
    rule, _, _ = one_rule("filename|sha256", "example.exe|" + "A" * 64)
    selection = rule["detection"]["selection"]
    assert set(selection) == {"Image|endswith", "Hashes|contains"}
    assert selection["Hashes|contains"] == "SHA256=" + "a" * 64
    rule, _, _ = one_rule("ip-dst|port", "192.0.2.1|443")
    assert rule["detection"]["selection"] == {"DestinationIp": "192.0.2.1", "DestinationPort": 443}


def test_domain_hostname_and_direction_semantics():
    rule, _, _ = one_rule("domain", "Example.ORG.")
    assert rule["logsource"]["category"] == "dns_query"
    assert rule["detection"]["selection"]["QueryName"] == [
        "example.org",
        "example.org.",
        "*.example.org",
        "*.example.org.",
    ]
    rule, _, _ = one_rule("hostname", "Example.ORG")
    assert rule["detection"]["selection"]["QueryName"] == ["example.org", "example.org."]
    rule, _, _ = one_rule("ip-src", "192.0.2.42/24")
    assert rule["detection"]["selection"] == {"SourceIp|cidr": "192.0.2.0/24"}


def test_sigma_wildcards_are_escaped_independently_of_yaml_quoting():
    rule, _, _ = one_rule("filename", r"C:\test\literal*?.exe")
    assert rule["detection"]["selection"]["Image"] == r"C:\\test\\literal\*\?.exe"


def test_both_mode_keeps_log_sources_separate():
    attrs = [
        attribute("sigma", STORED, to_ids=False),
        attribute("domain", "example.org"),
        attribute("sha256", "a" * 64),
        attribute("ip-dst", "192.0.2.1"),
    ]
    files, manifest, _ = run(event(attrs), mode="both")
    assert len(files) == 4
    categories = {yaml.safe_load(data)["logsource"]["category"] for data in files.values()}
    assert categories == {"process_creation", "dns_query", "network_connection"}
    assert manifest["summary"]["stored_rules"] == 1
    assert manifest["summary"]["generated_rules"] == 3


def test_duplicates_keep_all_sources_and_output_is_deterministic():
    attrs = [attribute("domain", "EXAMPLE.ORG", uuid="a"), attribute("domain", "example.org.", uuid="b")]
    data = [event(attrs), event([attribute("domain", "example.org", uuid="c")], uuid="event-2")]
    original = copy.deepcopy(data)
    files, manifest, result = run(data, mode="indicators")
    assert len(files) == 1
    assert len(next(iter(manifest["sources"].values()))) == 3
    reversed_data = list(reversed(data))
    reversed_data[1] = event(list(reversed(attrs)))
    _, _, reordered = run(reversed_data, mode="indicators")
    assert result["data"] == reordered["data"]
    assert data == original


@pytest.mark.parametrize("flag", [True, 1, "1", "true"])
def test_deleted_events_objects_and_attributes_are_excluded(flag):
    kept = attribute("sigma", STORED)
    data = [
        event([kept], deleted=flag),
        event([dict(kept, deleted=flag)]),
        event([], Object=[{"deleted": flag, "Attribute": [kept]}]),
        event([kept]),
    ]
    files, _, _ = run(data)
    assert len(files) == 1


@pytest.mark.parametrize("flag", [False, 0, "0", "false", None])
def test_non_ids_indicators_are_opt_in(flag):
    data = event([attribute(to_ids=flag), attribute("sigma", STORED, to_ids=False)])
    files, _, _ = run(data, mode="both")
    assert len(files) == 1
    files, _, _ = run(data, mode="both", include_non_ids=True)
    assert len(files) == 2


@pytest.mark.parametrize(
    "kind,value",
    [
        ("sha256", "short"),
        ("ip-dst", "not an IP"),
        ("ip-dst|port", "192.0.2.1|65536"),
        ("ip-src", "fe80::1%eth0"),
        ("domain", "*.example.org"),
        ("domain", "example.org\ncondition: true"),
        ("filename|md5", "missing separator"),
        ("filename", "/usr/bin/example"),
        ("filename", "\n"),
        ("sha256", None),
    ],
)
def test_malformed_indicators_are_reported_without_broadening_rules(kind, value):
    result = module.handler(json.dumps({"data": event([attribute(kind, value)]), "config": {"mode": "indicators"}}))
    assert "error" in result and "data" not in result
    assert result["summary"]["skipped"] == {"malformed indicator": 1}


def test_unknown_and_cross_log_source_composites_are_not_silently_split():
    _, _, result = run(
        event(
            [
                attribute("sigma", STORED),
                attribute("domain|ip", "example.org|192.0.2.1"),
                attribute("url", "https://example.org"),
            ]
        ),
        mode="both",
    )
    assert result["summary"]["skipped"] == {"unsupported type": 2}
    assert result["warnings"]


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"data": None},
        {"data": [1]},
        {"data": {"Event": []}},
        {"data": {"Attribute": {}}},
        {"data": {"Object": [None]}},
    ],
)
def test_invalid_requests_return_errors(payload):
    assert "error" in module.handler(json.dumps(payload))


@pytest.mark.parametrize(
    "config", [[], {"mode": "unknown"}, {"mode": False}, {"mode": []}, {"include_non_ids": "invalid"}]
)
def test_invalid_options_return_errors(config):
    assert "error" in module.handler(json.dumps({"data": event(), "config": config}))


def test_invalid_json_and_empty_selection():
    assert "error" in module.handler("{")
    assert "error" in module.handler(json.dumps({"data": event([])}))


def test_rule_and_total_limits_return_errors_instead_of_truncating(monkeypatch):
    monkeypatch.setattr(module, "MAX_RULE_BYTES", 8)
    assert "limit" in module.handler(json.dumps({"data": event([attribute("sigma", STORED)])}))["error"]
    monkeypatch.setattr(module, "MAX_RULE_BYTES", 1024 * 1024)
    monkeypatch.setattr(module, "MAX_RULES", 1)
    data = event([attribute("sigma", STORED), attribute("sigma", STORED + "\n")])
    assert "split the input" in module.handler(json.dumps({"data": data}))["error"]
    monkeypatch.setattr(module, "MAX_RULES", 1000)
    monkeypatch.setattr(module, "MAX_TOTAL_BYTES", 1)
    assert "split the input" in module.handler(json.dumps({"data": data}))["error"]


def test_archive_member_names_are_derived_not_taken_from_rule_titles():
    files, _, _ = run(event([attribute("sigma", STORED.replace("Existing Linux Rule", "../../outside"))]))
    assert all(re.fullmatch(r"rules/stored_[0-9a-f]{64}\.yml", name) for name in files)


class TestSigmaExportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        handlers = {"sigma_export": module, "type:sigma_export": "export_mod"}
        self.handlers_patch = patch.object(server, "MODULES_HANDLERS", handlers)
        self.handlers_patch.start()
        self.addCleanup(self.handlers_patch.stop)
        return Application([(r"/modules", server.ListModules), (r"/query", server.QueryModule)])

    def test_discovery_and_generated_download(self):
        discovered = json.loads(self.fetch("/modules").body)[0]
        assert discovered["type"] == "export_mod"
        assert discovered["mispattributes"]["outputFileExtension"] == "zip"
        body = {"module": "sigma_export", "data": [event()], "config": {"mode": "indicators"}}
        response = self.fetch("/query", method="POST", body=json.dumps(body))
        assert response.code == 200
        result = json.loads(response.body)
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(result["data"]))) as archive:
            files = [name for name in archive.namelist() if name.endswith(".yml")]
            assert len(files) == 1
            VALIDATOR.validate(yaml.safe_load(archive.read(files[0])))
