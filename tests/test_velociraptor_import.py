"""Velociraptor artifact mappings, evidence fidelity, identity and HTTP contract."""

import base64
import copy
import csv
import hashlib
import json
import socket
from io import StringIO
from pathlib import Path

import pytest
from pymisp import MISPEvent, MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.import_mod import velociraptor_import as module

FIXTURE = Path(__file__).parent / "fixtures/velociraptor/results.jsonl"


def request(raw, config=None, **kwargs):
    return json.dumps({"data": base64.b64encode(raw).decode(), "config": config, **kwargs})


def imported(rows=None, raw=None, artifact="Windows.System.Pslist", **config):
    if raw is None:
        raw = json.dumps(rows if rows is not None else {"Pid": 12, "Name": "sample.exe"}).encode()
    result = module.handler(request(raw, config={"artifact": artifact, **config}))
    assert "error" not in result, result
    return result


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def fields(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def references(obj, relation):
    return [r["referenced_uuid"] for r in obj.get("ObjectReference", []) if r["relationship_type"] == relation]


def test_mixed_artifacts_original_bytes_and_relationships():
    raw = FIXTURE.read_bytes()
    result = imported(raw=raw, artifact="", server_id="dfir.example", collected_at="2026-11-15T11:00:00+01:00")
    source = result["results"]["Object"][0]
    values = fields(source)
    assert values["sha256"] == hashlib.sha256(raw).hexdigest()
    attachment = next(a for a in source["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == raw
    records = objects(result, "velociraptor-result")
    assert len(records) == 5
    assert [fields(r)["row-number"] for r in records] == ["1", "2", "3", "4", "5"]
    for record in records:
        values = fields(record)
        assert values["source-format"] == "jsonl"
        assert values["source-sha256"] == hashlib.sha256(raw).hexdigest()
        assert values["server-id"] == "dfir.example"
        assert values["collected-at"] == "2026-11-15T10:00:00+00:00"
        assert source["uuid"] not in references(record, "derived-from")
    assert references(source, "derived-from") == [record["uuid"] for record in records]
    assert fields(records[0])["client-id"] == "C.alpha"
    assert fields(records[0])["flow-id"] == "F.alpha"
    assert fields(records[1])["hunt-id"] == "H.test"
    assert fields(records[1])["hostname"] == "host-b.example"
    assert len(objects(result, "process")) == 3  # Two pslist rows plus netstat's row-local process.
    assert len(objects(result, "windows-service")) == 1
    assert len(objects(result, "network-socket")) == 1
    services = fields(objects(result, "windows-service")[0])
    assert services["name"] == "ExampleSvc"
    assert services["image-path"] == '"C:\\Program Files\\Example\\svc.exe" --service'
    processes = objects(result, "process")
    binary = references(processes[0], "executes")[0]
    files = {f["uuid"]: f for f in objects(result, "file")}
    assert fields(files[binary])["sha256"] == "a" * 64
    assert fields(files[binary])["fullpath"] == "C:\\Temp\\sample.exe"
    assert fields(processes[0])["creation-time"] == "2026-11-15T09:00:00.123456+00:00"
    assert fields(processes[0])["parent-pid"] == "4"
    # PIDs on different hosts remain distinct, and no parent relation is inferred from a PID alone.
    assert processes[0]["uuid"] != processes[1]["uuid"]
    assert references(processes[0], "child-of") == []
    socket_obj = objects(result, "network-socket")[0]
    assert fields(socket_obj)["ip-dst"] == "2001:db8::20"
    assert fields(socket_obj)["dst-port"] == "443"
    assert fields(socket_obj)["state"] == "ESTAB"
    assert "first-packet-seen" not in fields(socket_obj)
    known = {obj["uuid"] for obj in result["results"]["Object"]}
    assert all(
        ref["referenced_uuid"] in known for obj in result["results"]["Object"] for ref in obj.get("ObjectReference", [])
    )
    for obj in result["results"]["Object"]:
        assert all(a["to_ids"] is False for a in obj["Attribute"])
        if obj["name"] == "velociraptor-result":
            assert all(a["disable_correlation"] is True for a in obj["Attribute"])


def test_provenance_edges_follow_catalogue_source_to_derived_target():
    raw = FIXTURE.read_bytes() + b'{"_Source":"Custom.Unknown","Pid":100}\n'
    result = imported(raw=raw, artifact="")
    source = result["results"]["Object"][0]
    records = objects(result, "velociraptor-result")
    expected = {(source["uuid"], record["uuid"]) for record in records}
    for record in records:
        expected.update((record["uuid"], target) for target in references(record, "describes"))
    actual = {
        (obj["uuid"], target) for obj in result["results"]["Object"] for target in references(obj, "derived-from")
    }
    assert actual == expected
    assert not any((target, original) in actual for original, target in actual)
    assert len(records) == 6
    assert references(records[-1], "describes") == []


def test_pymisp_roundtrip_and_bundled_template():
    result = imported(raw=FIXTURE.read_bytes(), artifact="")
    event = MISPEvent()
    event.from_dict(info="Velociraptor", **copy.deepcopy(result["results"]))
    for obj in event.objects:
        if obj.name == "velociraptor-result":
            obj._definition = module._template()
        assert obj._validate()
    assert json.loads(event.to_json())["Object"]
    template = module._template()
    obj = MISPObject("velociraptor-result", strict=True, misp_objects_template_custom=template)
    for field, value in {"artifact": "Custom.Test", "row": "{}", "row-number": 1, "source-sha256": "a" * 64}.items():
        obj.add_attribute(field, value=value)
    assert obj._validate()


@pytest.mark.parametrize("format_", ["json", "jsonl", "csv"])
def test_input_formats_nested_hash_cells_and_multiline_csv(format_):
    row = {
        "Pid": 12,
        "Name": "quoted.exe",
        "CommandLine": 'cmd /c "a,b"\nsecond line',
        "Exe": "C:\\quoted.exe",
        "Hash": {"MD5": "a" * 32},
    }
    if format_ == "json":
        raw = json.dumps([row]).encode()
    elif format_ == "jsonl":
        raw = ("\n" + json.dumps(row) + "\n\n").encode()
    else:
        stream = StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow({**row, "Hash": json.dumps(row["Hash"])})
        raw = stream.getvalue().encode()
    result = imported(raw=raw, format=format_)
    assert fields(objects(result, "process")[0])["command-line"] == row["CommandLine"]
    assert fields(objects(result, "file")[1])["md5"] == "a" * 32
    assert fields(objects(result, "velociraptor-result")[0])["source-format"] == format_


def test_explicit_json_does_not_fall_back_to_jsonl():
    raw = b'{"Pid":1}\n{"Pid":2}\n'
    result = module.handler(request(raw, {"artifact": "Windows.System.Pslist", "format": "json"}))
    assert "error" in result
    assert "results" not in result


@pytest.mark.parametrize("format_", ["auto", "jsonl"])
def test_jsonl_accepted_when_auto_detected_or_explicit(format_):
    result = imported(raw=b'{"Pid":1}\n{"Pid":2}\n', format=format_)
    records = objects(result, "velociraptor-result")
    assert len(records) == 2
    assert all(fields(record)["source-format"] == "jsonl" for record in records)


@pytest.mark.parametrize("rows", [{"Pid": 1}, [{"Pid": 1}, {"Pid": 2}]])
def test_explicit_json_accepts_complete_pretty_printed_documents(rows):
    result = imported(raw=json.dumps(rows, indent=2).encode(), format="json")
    records = objects(result, "velociraptor-result")
    assert len(records) == (len(rows) if isinstance(rows, list) else 1)
    assert all(fields(record)["source-format"] == "json" for record in records)


def test_filefinder_times_hashes_and_zero_size():
    row = {
        "OSPath": "C:\\Temp\\empty.txt",
        "Size": 0,
        "IsDir": False,
        "BTime": "2026-11-15T09:00:00Z",
        "MTime": "2026-11-15T09:01:00Z",
        "ATime": "2026-11-15T09:02:00Z",
        "CTime": "2026-11-15T09:03:00Z",
        "Hash": {"SHA256": "b" * 64},
        "Data": {"mft": 42},
        "Upload": {"Path": "uploads/empty.txt"},
    }
    result = imported(row, artifact="Windows.Search.FileFinder")
    file = fields(objects(result, "file")[1])
    assert file["size-in-bytes"] == "0"
    assert file["creation-time"] == "2026-11-15T09:00:00+00:00"
    assert file["modification-time"] == "2026-11-15T09:01:00+00:00"
    assert file["access-time"] == "2026-11-15T09:02:00+00:00"
    saved = json.loads(fields(objects(result, "velociraptor-result")[0])["row"])
    assert saved == row
    assert "attachment" not in file  # Upload paths are evidence references, never fetched.


@pytest.mark.parametrize("value", [True, "true", "True", "Y", "1"])
def test_directories_are_preserved_without_file_mapping(value):
    result = imported({"OSPath": "C:\\Windows", "IsDir": value}, artifact="Windows.Search.FileFinder")
    assert len(objects(result, "file")) == 1  # Source export only.
    assert result["warnings"]


def test_unknown_artifact_is_retained_without_guessing_fields(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No network access is allowed")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    row = {"Pid": 3, "URL": "https://example.invalid/private", "Custom": {"a": [1, True]}}
    result = imported(row, artifact="Custom.Example")
    assert objects(result, "process") == []
    assert json.loads(fields(objects(result, "velociraptor-result")[0])["row"]) == row
    assert "Unsupported artifact" in result["warnings"][0]


def test_repeat_import_objects_attributes_and_references_are_deterministic():
    raw = FIXTURE.read_bytes()
    first = imported(raw=raw, artifact="")
    assert first == imported(raw=raw, artifact="")
    second = imported(raw=raw, artifact="", server_id="another-deployment")
    assert objects(first, "velociraptor-result")[0]["uuid"] != objects(second, "velociraptor-result")[0]["uuid"]


def test_duplicate_occurrences_stay_separate():
    result = imported([{"Pid": 12}, {"Pid": 12}])
    process = objects(result, "process")
    assert len(process) == 2
    assert process[0]["uuid"] != process[1]["uuid"]


@pytest.mark.parametrize("row", [{"Username": "LAB\\analyst"}, {"Ppid": 4}, {"Pid": "not-a-pid"}])
def test_projected_process_without_required_fields_remains_raw(row):
    result = imported(row)
    assert objects(result, "process") == []
    assert json.loads(fields(objects(result, "velociraptor-result")[0])["row"]) == row
    assert result["warnings"]


def test_bad_socket_does_not_lose_valid_process_context():
    result = imported({"Pid": 0, "Laddr": "invalid", "Lport": -1}, artifact="Windows.Network.NetstatEnriched/Netstat")
    assert fields(objects(result, "process")[0])["pid"] == "0"
    assert objects(result, "network-socket") == []


@pytest.mark.parametrize("display", ["a" * 257, "invalid/name"])
def test_invalid_service_display_retained_without_losing_service(display):
    result = imported({"Name": "ExampleSvc", "DisplayName": display}, artifact="Windows.System.Services")
    assert fields(objects(result, "windows-service")[0]) == {"name": "ExampleSvc"}
    assert result["warnings"]


@pytest.mark.parametrize("offset", ["+00:99", "+24:00", "-00:00"])
def test_invalid_or_unknown_timezone_offsets_are_not_normalized(offset):
    result = imported({"Pid": 1, "CreateTime": "2026-11-15T10:00:00" + offset})
    assert "creation-time" not in fields(objects(result, "process")[0])
    assert result["warnings"]


@pytest.mark.parametrize(
    "time", ["2026-11-15", "2026-11-15T09:00:00", "2026-11-15T09:00:00.123456789Z", 1794733200, "0000-00-00T00:00:00Z"]
)
def test_ambiguous_or_high_precision_times_preserved_without_truncation(time):
    result = imported({"Pid": 12, "CreateTime": time})
    assert "creation-time" not in fields(objects(result, "process")[0])
    assert json.loads(fields(objects(result, "velociraptor-result")[0])["row"])["CreateTime"] == time
    assert any("CreateTime" in warning for warning in result["warnings"])


def test_bad_optional_values_do_not_drop_evidence():
    result = imported(
        {
            "Pid": 12,
            "Laddr": "invalid",
            "Raddr": "2001:db8::1",
            "Lport": "wrong",
            "Rport": 443,
            "Path": "C:\\x.exe",
            "Hash": {"SHA256": "invalid"},
        },
        artifact="Windows.Network.NetstatEnriched/Netstat",
    )
    network = fields(objects(result, "network-socket")[0])
    assert "ip-src" not in network and "src-port" not in network
    assert network["ip-dst"] == "2001:db8::1"
    assert len(result["warnings"]) == 3
    result = imported({"Hash": {"SHA256": "bad"}}, artifact="Windows.Search.FileFinder")
    assert len(objects(result, "file")) == 1


def test_native_ipv6_and_listening_socket_zero_fields():
    result = imported(
        {"Laddr": "::", "Lport": 0, "Raddr": "0.0.0.0", "Rport": 0, "Status": "LISTEN"},
        artifact="Windows.Network.NetstatEnriched/Netstat",
    )
    network = fields(objects(result, "network-socket")[0])
    assert network["src-port"] == network["dst-port"] == "0"
    assert network["ip-src"] == "::"


def test_per_row_metadata_overrides_defaults_without_host_merging():
    result = imported(
        [{"Pid": 1, "ClientId": "C.one", "Fqdn": "one"}, {"Pid": 1, "ClientId": "C.two", "Fqdn": "two"}],
        client_id="C.fallback",
        hostname="fallback",
    )
    records = objects(result, "velociraptor-result")
    assert [fields(r)["client-id"] for r in records] == ["C.one", "C.two"]
    assert [fields(r)["hostname"] for r in records] == ["one", "two"]


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b"{}",
        b"null",
        b"[1]",
        b"[{}]",
        b'{"Pid":1,"Pid":2}',
        b'{"Pid":NaN}',
        b'{"Pid":1}\nnot json',
        b'[{"Pid":1},]',
        b"Name,Name\na,b\n",
        b"Name,Pid\na,1,extra\n",
        b"Name,Pid\na\n",
        b'Name\n"unterminated',
        b"\xff",
        rb'{"Name":"\ud800"}',
    ],
)
def test_invalid_exports_reject_atomically(raw):
    result = module.handler(request(raw, {"artifact": "Windows.System.Pslist"}))
    assert "error" in result, result
    assert "results" not in result


@pytest.mark.parametrize("q", ["{", "null", "[]", "{}", '{"data":123}', '{"data":"%%%"}'])
def test_bad_request_envelopes(q):
    assert "error" in module.handler(q)


@pytest.mark.parametrize(
    "config", [[], False, {"artifact": []}, {"format": "xml"}, {"collected_at": "2026-11-15"}, {"client_id": 12}]
)
def test_invalid_configuration(config):
    assert "error" in module.handler(request(b'{"Pid":1}', config))


def test_missing_and_conflicting_metadata():
    for row, config in [
        ({"Pid": 1}, {}),
        ({"Pid": 1, "Artifact": "Custom.A", "_Source": "Custom.B"}, {}),
        ({"Pid": 1, "ClientId": "C.a", "_ClientId": "C.b"}, {"artifact": "Windows.System.Pslist"}),
    ]:
        assert "error" in module.handler(request(json.dumps(row).encode(), config))


def test_limits_and_no_partial_success(monkeypatch):
    monkeypatch.setattr(module, "MAX_ROWS", 1)
    for raw, format_ in [(b'[{"Pid":1},{"Pid":2}]', "json"), (b'{"Pid":1}\n{"Pid":2}', "jsonl"), (b"Pid\n1\n2", "csv")]:
        result = module.handler(request(raw, {"artifact": "Windows.System.Pslist", "format": format_}))
        assert "error" in result and "results" not in result
    monkeypatch.setattr(module, "MAX_ROW", 10)
    assert "error" in module.handler(request(b'{"Name":"long name.exe"}', {"artifact": "Windows.System.Pslist"}))
    monkeypatch.setattr(module, "MAX_INPUT", 3)
    assert "error" in module.handler(request(b'{"Pid":1}', {"artifact": "Windows.System.Pslist"}))


def test_depth_limit():
    raw = b'{"Pid":1,"nested":' + b"[" * 33 + b"0" + b"]" * 33 + b"}"
    assert "error" in module.handler(request(raw, {"artifact": "Windows.System.Pslist"}))


def test_bom_and_filename_basename():
    result = module.handler(
        request(b'\xef\xbb\xbf{"Pid":1}', {"artifact": "Windows.System.Pslist"}, filename="C:\\uploads\\results.json")
    )
    assert "error" not in result
    assert fields(objects(result, "file")[0])["filename"] == "results.json"


class TestVelociraptorHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"velociraptor_import": module, "type:velociraptor_import": "import_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        modules = json.loads(self.fetch("/modules").body)
        assert modules[0]["name"] == "velociraptor_import"
        assert modules[0]["mispattributes"]["format"] == "misp_standard"
        assert module.handler() is False
        body = request(FIXTURE.read_bytes(), {}, module="velociraptor_import")
        response = self.fetch("/query", method="POST", body=body)
        assert response.code == 200
        assert len(objects(json.loads(response.body), "velociraptor-result")) == 5
        response = self.fetch(
            "/query", method="POST", body=json.dumps({"module": "velociraptor_import", "data": "%%%"})
        )
        assert response.code == 200 and "error" in json.loads(response.body)
