import base64
import io
import json
import re
import zipfile

import pytest
import yara

from misp_modules.modules.export_mod import yara_export


def _event(attributes, **metadata):
    return {
        "Event": {"id": "1", "info": "Test event", "date": "2026-10-27", "uuid": "uuid", **metadata},
        "Orgc": {"name": "ORG"},
        "Attribute": attributes,
    }


def _attribute(kind, value, **fields):
    return {"type": kind, "value": value, "to_ids": True, **fields}


def _stored(source, **fields):
    return _attribute("yara", source, **fields)


def _request(data, mode=None):
    query = {"data": data}
    if mode is not None:
        query["config"] = {"mode": mode}
    return yara_export.handler(json.dumps(query))


def _unpack(result):
    assert "error" not in result, result
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(result["data"]))) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        sources = {
            namespace: archive.read(entry["path"]).decode("utf-8")
            for namespace, entry in manifest["collections"].items()
        }
        assert set(archive.namelist()) == {"manifest.json"} | {
            entry["path"] for entry in manifest["collections"].values()
        }
    return sources, manifest, yara.compile(sources=sources, includes=False)


def test_stored_collection_preserves_references_and_source():
    source = (
        "// Keep “smart quotes” and Rule unchanged.\r\n"
        'private rule helper { strings: $a = "helper" condition: $a }\n'
        'rule consumer : tag { meta: note = "helper" condition: helper }\n'
        "rule dependent { condition: consumer }\n"
    )
    sources, manifest, rules = _unpack(_request([_event([_stored(source, to_ids=False, uuid="rule-uuid")])]))
    assert list(sources.values()) == [source]
    assert {match.rule for match in rules.match(data=b"helper")} == {"consumer", "dependent"}
    assert not rules.match(data=b"other")
    entry = next(iter(manifest["collections"].values()))
    assert entry["sources"][0]["attribute"] == "rule-uuid"
    assert manifest["summary"]["stored_collections"] == 1


def test_colliding_names_and_global_rules_are_isolated():
    first = "global rule gate { condition: false }\nrule same { condition: true }"
    second = "rule same { condition: true }"
    sources, _, rules = _unpack(_request([_event([_stored(first), _stored(second)])]))
    assert len(sources) == 2
    matches = rules.match(data=b"")
    assert len(matches) == 1
    assert sources[matches[0].namespace] == second


def test_invalid_collection_is_excluded_as_a_whole_with_diagnostics():
    invalid = "private rule helper { condition: true }\nrule broken { condition: missing }"
    valid = "rule good { condition: true }"
    result = _request([_event([_stored(invalid, uuid="bad"), _stored(valid, uuid="good")])])
    sources, manifest, _ = _unpack(result)
    assert list(sources.values()) == [valid]
    assert result["summary"]["skipped"] == {"invalid stored collection": 1}
    assert result["exclusions"] == manifest["exclusions"]
    assert result["exclusions"][0]["source"]["attribute"] == "bad"
    assert "missing" in result["exclusions"][0]["diagnostic"]
    assert result["warnings"]


@pytest.mark.parametrize(
    "source", ["", 'import "pe"', "Rule invalid { condition: true }", "rule valid { condition: true }\x00truncated"]
)
def test_invalid_or_empty_stored_rules_never_return_an_empty_archive(source):
    result = _request([_event([_stored(source)])])
    assert "error" in result and "data" not in result
    assert result["summary"]["excluded_attributes"] == 1
    assert result["exclusions"][0]["reason"] == "invalid stored collection"


def test_filesystem_includes_are_disabled(tmp_path):
    included = tmp_path / "included.yara"
    included.write_text("rule from_disk { condition: true }")
    result = _request([_event([_stored(f'include "{included}"')])])
    assert "data" not in result
    assert "includes are disabled" in result["exclusions"][0]["diagnostic"]


def test_same_collection_is_deduplicated_with_all_provenance():
    source = "rule same { condition: true }"
    sources, manifest, _ = _unpack(
        _request([_event([_stored(source, uuid="one")]), _event([_stored(source, uuid="two")], id="2", uuid="event2")])
    )
    assert len(sources) == 1
    refs = next(iter(manifest["collections"].values()))["sources"]
    assert {ref["attribute"] for ref in refs} == {"one", "two"}
    assert {ref["event"] for ref in refs} == {"uuid", "event2"}


def test_indicators_require_explicit_opt_in():
    result = _request([_event([_attribute("filename", "evil.exe")])])
    assert "data" not in result
    assert result["summary"]["generated_rules"] == 0
    assert result["summary"]["skipped"] == {"excluded by mode": 1}


@pytest.mark.parametrize("mode,stored,generated", [("rules", 1, 0), ("indicators", 0, 1), ("both", 1, 1)])
def test_modes_separate_stored_rules_and_ioc_generation(mode, stored, generated):
    _, _, rules = _unpack(
        _request([_event([_stored("rule existing { condition: true }"), _attribute("domain", "example.org")])], mode)
    )
    assert len(list(rules)) == stored + generated


def test_generated_strings_and_metadata_are_escaped_without_changing_bytes():
    value = 'C:\\folder\\file"\\' + "\n\r\t\x00\x01\x1f\x7f café 雪"
    info = 'Title "quoted"\\path\nrule injected { condition: true }\x01 café'
    event = _event([_attribute("filename", value)], info=info, id="12/\N{SNOWMAN}")
    event["Orgc"]["name"] = 'Org"\\\nname'
    sources, _, rules = _unpack(_request([event], "indicators"))
    assert len(list(rules)) == 1
    assert not rules.match(data=b"unrelated")
    matches = rules.match(data=b"prefix" + value.encode("utf-8") + b"suffix")
    assert len(matches) == 1
    assert matches[0].meta["description"] == info
    assert matches[0].meta["author"] == 'MISP - Org"\\\nname'
    source = next(iter(sources.values()))
    assert "\\x00" in source and "\\x0a" in source and "\\xc3\\xa9" in source


def test_filename_and_domain_are_case_sensitive_substring_content_matches(tmp_path):
    result = _request([_event([_attribute("filename", "evil.exe"), _attribute("domain", "example.org")])], "indicators")
    _, manifest, rules = _unpack(result)
    path = tmp_path / "evil.exe"
    path.write_bytes(b"unrelated content")
    assert not rules.match(filepath=str(path))
    assert rules.match(data=b"not-evil.exe.backup")
    assert rules.match(data=b"notexample.org.invalid")
    assert not rules.match(data=b"EXAMPLE.ORG EVIL.EXE")
    assert "file's name" in manifest["match_semantics"]
    assert any("case-sensitively" in warning for warning in result["warnings"])


def test_composites_report_omitted_hashes_and_ports():
    attributes = [
        _attribute("filename|md5", "evil.exe|d41d8cd98f00b204e9800998ecf8427e"),
        _attribute("ip-dst|port", "192.0.2.1|443"),
        _attribute("malware-sample", "sample.bin|d41d8cd98f00b204e9800998ecf8427e"),
        _attribute("domain|ip", "example.org|192.0.2.2"),
    ]
    result = _request([_event(attributes)], "indicators")
    _, manifest, rules = _unpack(result)
    for value in (b"evil.exe", b"sample.bin", b"example.org", b"192.0.2.1", b"192.0.2.2"):
        assert rules.match(data=value)
    assert not rules.match(data=b"d41d8cd98f00b204e9800998ecf8427e")
    assert not rules.match(data=b"443")
    assert [entry["omitted_components"] for entry in result["reductions"]] == [["md5"], ["port"], ["md5"]]
    assert manifest["reductions"] == result["reductions"]


@pytest.mark.parametrize("to_ids", [False, "false", 0, "0", None])
def test_non_ids_indicators_are_excluded(to_ids):
    result = _request([_event([_attribute("filename", "evil.exe", to_ids=to_ids)])], "indicators")
    assert "data" not in result
    assert result["summary"]["skipped"] == {"non-IDS": 1}


def test_malformed_composites_and_unsupported_types_are_reported():
    result = _request(
        [
            _event(
                [
                    _attribute("filename|md5", "no-separator"),
                    _attribute("domain|ip", "domain|"),
                    _attribute("sha256", "a" * 64),
                    _attribute("filename", ""),
                ]
            )
        ],
        "indicators",
    )
    assert "data" not in result
    assert result["summary"]["skipped"] == {"invalid indicator": 3, "unsupported type": 1}
    assert all(entry["diagnostic"] for entry in result["exclusions"] if entry["reason"] == "invalid indicator")


@pytest.mark.parametrize("shape", ["legacy", "standard", "bare"])
def test_event_shapes_and_object_attributes(shape):
    event = _event([_stored("rule top { condition: true }")])
    event["Object"] = [{"uuid": "object", "Attribute": [_stored("rule object_rule { condition: true }")]}]
    if shape == "standard":
        event["Event"].update({key: value for key, value in event.items() if key != "Event"})
        event = {"Event": event["Event"]}
    elif shape == "bare":
        metadata = event.pop("Event")
        event.update(metadata)
    sources, manifest, _ = _unpack(_request(event))
    assert len(sources) == 2
    refs = [entry["sources"][0] for entry in manifest["collections"].values()]
    assert any(".Object[0].Attribute[0]" in ref["location"] for ref in refs)


@pytest.mark.parametrize("as_list", [False, True])
@pytest.mark.parametrize(
    "attribute_level,object_level",
    [
        ("inner", "inner"),
        ("outer", "outer"),
        ("inner", "outer"),
        ("outer", "inner"),
        ("bare", "bare"),
    ],
)
def test_source_locations_resolve_to_original_input(as_list, attribute_level, object_level):
    included = _stored("rule included { condition: true }", uuid="included")
    excluded = _stored("rule excluded { condition: missing }", uuid="excluded")
    object_attribute = _stored("rule object_rule { condition: true }", uuid="object-attribute")
    inner = {"id": "1", "Attribute": [included, excluded], "Object": [{"Attribute": [object_attribute]}]}
    if attribute_level == "bare":
        event = inner
    else:
        event = {"Event": inner}
        for key, level in [("Attribute", attribute_level), ("Object", object_level)]:
            if level == "outer":
                event[key] = inner.pop(key)
                # A shadowed collection must not supply either records or their locations.
                inner[key] = [{"type": "yara", "value": "invalid shadowed collection"}]
    data = [event] if as_list else event
    _, manifest, _ = _unpack(_request(data))
    prefix = "data[0]" if as_list else "data"
    attribute_prefix = prefix + (".Event" if attribute_level == "inner" else "")
    object_prefix = prefix + (".Event" if object_level == "inner" else "")
    refs = [ref for entry in manifest["collections"].values() for ref in entry["sources"]]
    refs.extend(entry["source"] for entry in manifest["exclusions"])
    locations = {ref["attribute"]: ref["location"] for ref in refs}
    assert locations == {
        "included": attribute_prefix + ".Attribute[0]",
        "excluded": attribute_prefix + ".Attribute[1]",
        "object-attribute": object_prefix + ".Object[0].Attribute[0]",
    }
    for ref in refs:
        record = {"data": data}
        for key, index in re.findall(r"([A-Za-z]+)(?:\[(\d+)\])?", ref["location"]):
            record = record[key]
            if index:
                record = record[int(index)]
        assert record["uuid"] == ref["attribute"]


@pytest.mark.parametrize("mode", ["indicators", "both"])
@pytest.mark.parametrize("value", ["a" * 8191, "é" * 4096, "\x00" * 8192], ids=["ascii", "utf8", "escaped"])
def test_oversized_ioc_is_excluded_without_losing_valid_collections(mode, value):
    result = _request(
        [
            _event(
                [
                    _stored("rule stored { condition: true }"),
                    _attribute("filename", "valid.bin"),
                    _attribute("email-header", value, uuid="oversized"),
                ]
            )
        ],
        mode,
    )
    _, manifest, rules = _unpack(result)
    assert {match.rule for match in rules.match(data=b"valid.bin")} == (
        {"MISP_ioc", "stored"} if mode == "both" else {"MISP_ioc"}
    )
    exclusion = next(entry for entry in result["exclusions"] if entry["source"]["attribute"] == "oversized")
    assert exclusion["reason"] == "invalid indicator"
    assert "8190" in exclusion["diagnostic"]
    assert result["summary"]["skipped"]["invalid indicator"] == 1
    assert manifest["exclusions"] == result["exclusions"]


@pytest.mark.parametrize("char", ["a", "é", "\x00"], ids=["ascii", "utf8", "escaped"])
def test_ioc_at_literal_byte_limit_remains_exportable(char):
    value = char * (8190 // len(char.encode("utf-8")))
    _, _, rules = _unpack(_request([_event([_attribute("pattern-in-file", value)])], "indicators"))
    assert rules.match(data=value.encode("utf-8"))


def test_oversized_composite_is_excluded_as_a_whole():
    result = _request(
        [
            _event(
                [
                    _attribute("filename", "valid.bin"),
                    _attribute("domain|ip", "example.org|" + "a" * 8192),
                ]
            )
        ],
        "indicators",
    )
    _, _, rules = _unpack(result)
    assert rules.match(data=b"valid.bin")
    assert not rules.match(data=b"example.org")
    assert result["summary"]["skipped"] == {"invalid indicator": 1}


def test_deleted_events_objects_and_attributes_are_reported():
    event = _event([_stored("rule attr_deleted { condition: true }", deleted="1")])
    event["Object"] = [{"deleted": True, "Attribute": [_stored("rule obj_deleted { condition: true }")]}]
    deleted_event = _event([_stored("rule event_deleted { condition: true }")], deleted=True)
    result = _request([event, deleted_event])
    assert "data" not in result
    assert result["summary"]["skipped"] == {"deleted": 3}


def test_complete_output_is_compiled_and_failure_returns_no_download(monkeypatch):
    compile_yara = yara.compile
    calls = []

    def compile_output(**kwargs):
        calls.append(kwargs)
        if "sources" in kwargs:
            raise yara.SyntaxError("combined output failed")
        return compile_yara(**kwargs)

    monkeypatch.setattr(yara_export.yara, "compile", compile_output)
    result = _request(
        [_event([_stored("rule stored { condition: true }"), _attribute("filename", "evil.exe")])], "both"
    )
    assert "data" not in result
    assert "Complete YARA output failed to compile" in result["error"]
    assert len(calls[-1]["sources"]) == 2
    assert {key.split("_", 1)[0] for key in calls[-1]["sources"]} == {"stored", "generated"}
    assert all(call["includes"] is False for call in calls)


def test_archive_is_reproducible_and_matches_introspection():
    query = [_event([_stored("rule test { condition: true }")])]
    assert _request(query)["data"] == _request(query)["data"]
    setup = yara_export.introspection()
    assert setup["outputFileExtension"] == "zip"
    assert setup["responseType"] == "application/zip"
    assert "mode" in setup["userConfig"]
    assert "mode" in yara_export.version()["config"]


def test_imports_and_generated_object_strings_compile_together():
    event = _event([_stored('import "hash"\nrule digest { condition: hash.md5(0, filesize) != "" }')])
    event["Object"] = [{"Attribute": [_attribute("filename", "example.bin", to_ids="true")]}]
    _, manifest, rules = _unpack(_request([event], "both"))
    assert {match.rule for match in rules.match(data=b"example.bin")} == {"digest", "MISP_ioc"}
    assert manifest["summary"]["stored_collections"] == 1
    assert manifest["summary"]["generated_rules"] == 1


@pytest.mark.parametrize(
    "query",
    [
        "not-json",
        "[]",
        '{"data": null}',
        '{"data": [], "config": "wrong"}',
        '{"data": [], "config": []}',
        '{"data": [], "config": {"mode": "wrong"}}',
        '{"data": [], "config": {"mode": []}}',
    ],
)
def test_invalid_requests_return_errors(query):
    assert "error" in yara_export.handler(query)
    assert yara_export.handler() is False
