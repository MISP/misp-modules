import base64
import copy
import hashlib
import json
import socket
from pathlib import Path

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.import_mod import volatility3_import as module

FIXTURES = Path(__file__).parent / "fixtures/volatility3"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())


def request(raw, config=None, **kwargs):
    return json.dumps({"data": base64.b64encode(raw).decode(), "config": config, **kwargs})


def imported(filename="pslist.json", raw=None, config=None):
    raw = (FIXTURES / filename).read_bytes() if raw is None else raw
    config = MANIFEST[filename] if config is None else config
    result = module.handler(request(raw, config, filename=filename))
    assert "error" not in result, result
    return result


def objects(result, name="volatility3-result"):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def fields(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def refs(obj, relationship):
    return [r["referenced_uuid"] for r in obj.get("ObjectReference", []) if r["relationship_type"] == relationship]


def rows(filename="pslist.json"):
    return json.loads((FIXTURES / filename).read_text())


@pytest.mark.parametrize("filename", sorted(MANIFEST))
def test_native_renderers_preserve_source_image_plugin_and_rows(filename):
    result = imported(filename)
    data = (FIXTURES / filename).read_bytes()
    context = MANIFEST[filename]
    results = objects(result)
    assert result["summary"]["rows"] == len(results) == 2
    files = objects(result, "file")
    assert len(files) == 2
    source = next(f for f in files if "attachment" in fields(f))
    image = next(f for f in files if "attachment" not in fields(f))
    assert fields(source)["sha256"] == hashlib.sha256(data).hexdigest()
    assert fields(image)["sha256"] == context["image_sha256"] != fields(source)["sha256"]
    assert (
        base64.b64decode(next(a["data"] for a in source["Attribute"] if a["object_relation"] == "attachment")) == data
    )
    assert refs(image, "derived-from") == [source["uuid"]]
    assert set(refs(source, "derived-from")) == {r["uuid"] for r in results}
    for record in results:
        values = fields(record)
        assert values["plugin"] == context["plugin"]
        assert values["volatility-version"] == "2.28.2"
        assert values["image-sha256"] == context["image_sha256"]
        assert values["review-status"] == "unreviewed"
        assert values["source-sha256"] == fields(source)["sha256"]
        if "plugin_version" in context:
            assert values["plugin-version"] == context["plugin_version"]
        assert "__children" not in json.loads(values["raw-result"])
    assert len(objects(result, "process")) == (0 if filename.startswith("yarascan.") else 2)
    assert len(objects(result, "network-socket")) == (2 if filename.startswith(("netscan.", "netstat.")) else 0)
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])


def test_integer_offsets_above_float_precision_and_process_birth_times_are_lossless():
    result = imported()
    value = fields(objects(result)[0])
    assert value["offset-virtual"] == "0xffff800000001000"
    assert json.loads(value["raw-result"])["Offset(V)"] == 0xFFFF800000001000
    assert value["process-created"] == value["process-created-raw"] == "2026-10-10T12:00:00.123456+00:00"
    assert fields(objects(result, "process")[0])["creation-time"] == value["process-created"]
    physical = fields(objects(imported("psscan.json"))[0])
    assert physical["offset-physical"] == "0x12345000" and "offset-virtual" not in physical


def test_tree_hierarchy_links_only_explicit_consistent_process_ancestry():
    result = imported("pstree.json")
    records, processes = objects(result), objects(result, "process")
    assert [fields(r)["row-path"] for r in records] == ["1", "1.1"]
    assert refs(records[0], "contains") == [records[1]["uuid"]]
    assert refs(processes[0], "parent-of") == [processes[1]["uuid"]]
    assert refs(records[0], "describes") == [processes[0]["uuid"]]
    assert not any(refs(obj, "parent-of") for obj in objects(imported(), "process"))


@pytest.mark.parametrize("change", [{"PPID": 999}, {"PID": 4}, {"CreateTime": "2020-01-01T00:00:00Z"}])
def test_pid_reuse_and_inconsistent_ancestry_do_not_create_process_parent_links(change):
    data = rows("pstree.json")
    data[0]["__children"][0].update(change)
    result = imported("pstree.json", raw=json.dumps(data).encode())
    assert not any(refs(p, "parent-of") for p in objects(result, "process"))
    assert refs(objects(result)[0], "contains")
    assert any("ancestry conflicts" in warning for warning in result["warnings"])


def test_duplicate_pids_remain_distinct_observations_and_image_scope_changes_identity():
    data = rows()
    data[1]["PID"] = data[0]["PID"]
    raw = json.dumps(data).encode()
    first = imported(raw=raw)
    assert len({p["uuid"] for p in objects(first, "process")}) == 2
    context = {**MANIFEST["pslist.json"], "image_sha256": "b" * 64}
    second = imported(raw=raw, config=context)
    assert {p["uuid"] for p in objects(first, "process")}.isdisjoint({p["uuid"] for p in objects(second, "process")})


def test_command_line_preserves_windows_quoting_without_inventing_creation_time():
    result = imported("cmdline.json")
    process = fields(objects(result, "process")[0])
    assert process["command-line"] == rows("cmdline.json")[0]["Args"]
    assert "creation-time" not in process and "image" not in process


def test_network_ipv4_ipv6_wildcards_and_creation_are_not_packet_observations():
    result = imported("netscan.json")
    first, second = map(fields, objects(result, "network-socket"))
    assert first["ip-src"] == "10.0.0.5" and first["ip-dst"] == "203.0.113.5"
    assert first["dst-port"] == "443" and first["protocol"] == "tcp"
    assert first["state"] == "ESTABLISHED" and first["address-family"] == "AF_INET"
    assert second["ip-src"] == "::" and "ip-dst" not in second
    assert second["dst-port"] == "0" and second["address-family"] == "AF_INET6"
    assert all("first-packet-seen" not in f for f in [first, second])
    assert fields(objects(result)[0])["network-created"].endswith(".123456+00:00")


def test_corrupt_network_fields_keep_raw_context_without_false_process_or_endpoints():
    data = rows("netscan.json")[:1]
    data[0].update(PID=-1, Proto="unknown", LocalAddr="garbage", ForeignAddr="*", LocalPort=999999, ForeignPort=-1)
    result = imported("netscan.json", raw=json.dumps(data).encode())
    assert not objects(result, "process") and not objects(result, "network-socket")
    assert json.loads(fields(objects(result)[0])["raw-result"])["PID"] == -1
    assert result["warnings"]


@pytest.mark.parametrize("filename", ["malfind.json", "vadyarascan.json", "yarascan.json"])
def test_memory_suspicion_and_yara_matches_do_not_become_malicious_verdicts_or_rule_bodies(filename):
    data = rows(filename)
    data[0].update(verdict="malicious", **{"review-status": "confirmed-malicious"})
    result = imported(filename, raw=json.dumps(data).encode())
    value = fields(objects(result)[0])
    assert value["review-status"] == "unreviewed" and "verdict" not in value
    assert json.loads(value["raw-result"])["verdict"] == "malicious"
    assert not objects(result, "yara") and not objects(result, "threat-hunt-finding")
    if filename.startswith("malfind"):
        assert value["memory-start"] == "0x1000" and value["memory-end"] == "0x1fff"
        assert value["memory-protection"] == "PAGE_EXECUTE_READWRITE" and value["vad-tag"] == "VadS"
    else:
        assert value["rule-name"] == "ExampleRule" and value["yara-component"] == "$example"
        assert value["match-data"].startswith("4d 5a 90 00") and value["offset"] == "0x1234"
    if filename.startswith("yarascan."):
        assert value["layer-name"] == "synthetic" and "process-id" not in value
    if filename.startswith("vadyarascan"):
        assert value["process-created"].endswith(".123456+00:00")


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-10T12:00:00",
        "2026-10-10T12:00:00-00:00",
        "2026-10-10T12:00:00.1234567Z",
        1791633600,
        True,
        {"raw": "unknown"},
    ],
)
def test_unknown_timezones_and_precision_are_retained_without_normalizing(value):
    data = rows()[:1]
    data[0]["CreateTime"] = value
    result = imported(raw=json.dumps(data).encode())
    record = fields(objects(result)[0])
    assert "process-created" not in record and "process-created-raw" in record
    assert "creation-time" not in fields(objects(result, "process")[0])
    assert json.loads(record["raw-result"])["CreateTime"] == value
    assert result["warnings"]


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, "0x0"),
        (2**64 - 1, "0xffffffffffffffff"),
        ("0xABC", "0xabc"),
        (-1, None),
        (2**64, None),
        (1.5, None),
        (True, None),
    ],
)
def test_offsets_preserve_zero_and_exact_unsigned_addresses_without_guessing(value, expected):
    data = rows()[:1]
    data[0]["Offset(V)"] = value
    result = imported(raw=json.dumps(data).encode())
    record = fields(objects(result)[0])
    assert record.get("offset-virtual") == expected
    assert json.loads(record["raw-result"])["Offset(V)"] == value


def test_metadata_envelope_without_config_preserves_provenance_and_accepts_same_aliases():
    data = {"metadata": MANIFEST["pslist.json"], "results": rows()}
    first = imported(raw=json.dumps(data).encode(), config={})
    assert fields(objects(first)[0])["image-sha256"] == MANIFEST["pslist.json"]["image_sha256"]
    second = imported(raw=json.dumps(data).encode(), config={"plugin": "windows.pslist"})
    assert first == second


@pytest.mark.parametrize(
    "field,value", [("plugin", "windows.psscan"), ("image_sha256", "0" * 64), ("plugin_version", "different")]
)
def test_conflicting_envelope_context_is_rejected(field, value):
    data = {"metadata": MANIFEST["pslist.json"], "results": rows()}
    result = module.handler(request(json.dumps(data).encode(), {field: value}))
    assert "Conflicting" in result["error"] and "results" not in result


def test_missing_image_and_version_information_is_reported_and_never_derived_from_json():
    result = imported(config={"plugin": "windows.pslist"})
    assert len(objects(result, "file")) == 1
    value = fields(objects(result)[0])
    assert not {"image-sha256", "volatility-version", "plugin-version"}.intersection(value)
    assert len(result["warnings"]) == 3


def test_memory_image_hash_only_uses_existing_file_template_without_fabricating_a_name():
    context = {"plugin": "windows.pslist", "image_sha256": "a" * 64}
    result = imported(config=context)
    image = next(obj for obj in objects(result, "file") if fields(obj)["sha256"] == "a" * 64)
    assert "filename" not in fields(image)
    validated = MISPObject("file", strict=True)
    validated.from_dict(**copy.deepcopy(image))
    assert validated.to_json(strict=True)


def test_jsonl_with_unicode_line_separators_is_not_split_inside_commands():
    data = rows("cmdline.json")
    data[0]["Args"] = "example\u2028line\u0085separator"
    raw = ("\n".join(json.dumps(row, ensure_ascii=False) for row in data) + "\n").encode()
    result = imported("cmdline.jsonl", raw=raw)
    assert fields(objects(result, "process")[0])["command-line"] == data[0]["Args"]


@pytest.mark.parametrize(
    "raw,config",
    [
        (b"[]", {"plugin": "windows.pslist"}),
        (b'{"PID":1,"PID":2}', {"plugin": "windows.pslist"}),
        (b'{"PID":NaN}', {"plugin": "windows.pslist"}),
        (b"{}", {"plugin": "windows.pslist"}),
        (b'[{"PID":1}]', {"plugin": "windows.pslist"}),
        (b'{"results":[],"metadata":[]}', {}),
    ],
)
def test_invalid_inputs_return_atomic_errors(raw, config):
    result = module.handler(request(raw, config))
    assert "error" in result and "results" not in result


@pytest.mark.parametrize(
    "config,expected",
    [
        ({"plugin": "pslist"}, "Unsupported plugin"),
        ({"plugin": "linux.pslist.PsList"}, "Unsupported plugin"),
        ({"plugin": "windows.pslist", "format": False}, "format must be"),
        ({"plugin": "windows.pslist", "image_sha256": "bad"}, "64 hexadecimal digits"),
        ({"plugin": "windows.pslist", "image_name": "/"}, "image_name requires"),
        ({"plugin": "windows.pslist", "image_name": ".."}, "image_name requires"),
        ({"plugin": "windows.pslist", "plugin_version": []}, "plugin_version must be"),
        ([], "config must be"),
        ({}, "plugin must be"),
    ],
)
def test_invalid_configuration_is_rejected_with_otherwise_valid_native_rows(config, expected):
    result = module.handler(request((FIXTURES / "pslist.json").read_bytes(), config))
    assert expected in result["error"] and "results" not in result


def test_legacy_malfind_plugin_and_image_reference_without_hash_are_preserved():
    result = imported("malfind.json", config={"plugin": "windows.malfind", "image_name": "case/memory.raw"})
    assert fields(objects(result)[0])["plugin"] == "windows.malfind.Malfind"
    image = next(obj for obj in objects(result, "file") if "attachment" not in fields(obj))
    assert fields(image) == {"filename": "memory.raw"}
    assert any("image_sha256" in warning for warning in result["warnings"])


def test_explicit_json_does_not_silently_accept_jsonl_and_bad_children_are_atomic():
    raw = (FIXTURES / "pslist.jsonl").read_bytes()
    assert "error" in module.handler(request(raw, {"plugin": "windows.pslist", "format": "json"}))
    for child in [None, {}, "bad", [None], [{}]]:
        data = rows()
        data[1]["__children"] = child
        result = module.handler(request(json.dumps(data).encode(), MANIFEST["pslist.json"]))
        assert "error" in result and "results" not in result


def test_row_hierarchy_and_payload_limits_are_enforced(monkeypatch):
    context = MANIFEST["pslist.json"]
    assert "error" in module.handler(request(json.dumps(rows()[:1] * 1001).encode(), context))
    data = rows()[:1]
    data[0]["__children"] = rows()[:1] * 1000
    assert "error" in module.handler(request(json.dumps(data).encode(), context))
    nested = copy.deepcopy(rows()[0])
    for _ in range(33):
        nested = {**rows()[0], "__children": [nested]}
    assert "error" in module.handler(request(json.dumps([nested]).encode(), context))
    monkeypatch.setattr(module, "MAX_ROW", 50)
    assert "error" in module.handler(request((FIXTURES / "pslist.json").read_bytes(), context))
    monkeypatch.setattr(module, "MAX_INPUT", 1)
    assert "error" in module.handler(request(b"[]", context))


def test_bad_requests_filename_sanitization_and_bom():
    for q in ["null", "[]", "{}", json.dumps({"data": "%%%"}), request(b"\xff")]:
        assert "error" in module.handler(q)
    raw = b"\xef\xbb\xbf" + (FIXTURES / "pslist.json").read_bytes()
    result = module.handler(request(raw, MANIFEST["pslist.json"], filename="C:\\uploads\\processes.json"))
    source = next(obj for obj in objects(result, "file") if "attachment" in fields(obj))
    assert fields(source)["filename"] == "processes.json"


def test_templates_validate_repeatable_identity_and_no_network_or_image_access(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Importer must not access the network")

    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(socket.socket, "connect", fail)
    context = {**MANIFEST["pslist.json"], "image_name": "/nonexistent/memory/image.raw"}
    first = imported(config=context)
    assert first == imported(config=context)
    for name in ["pslist.json", "netscan.json", "malfind.json", "vadyarascan.json", "yarascan.json"]:
        for obj in imported(name)["results"]["Object"]:
            custom = {"misp_objects_template_custom": module._template()} if obj["name"] == "volatility3-result" else {}
            validated = MISPObject(obj["name"], strict=True, **custom)
            validated.from_dict(**copy.deepcopy(obj))
            assert validated.to_json(strict=True)


class TestVolatility3HTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"volatility3_import": module, "type:volatility3_import": "import_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_import_and_errors(self):
        modules = json.loads(self.fetch("/modules").body)
        assert modules[0]["name"] == "volatility3_import"
        assert modules[0]["mispattributes"]["format"] == "misp_standard"
        assert module.handler() is False
        response = self.fetch(
            "/query",
            method="POST",
            body=request((FIXTURES / "pstree.json").read_bytes(), MANIFEST["pstree.json"], module="volatility3_import"),
        )
        assert response.code == 200 and len(objects(json.loads(response.body))) == 2
        response = self.fetch("/query", method="POST", body=json.dumps({"module": "volatility3_import", "data": "%%%"}))
        assert response.code == 200 and "error" in json.loads(response.body)
