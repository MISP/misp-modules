import base64
import hashlib
import io
import json
import subprocess
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
from pymisp import MISPEvent, MISPObject

from misp_modules.modules.expansion import manalyze as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SAMPLE = b"MZ" + b"\x00" * 100
REPORT = {
    "Summary": {"Compilation Date": "2017-Nov-16 22:05:22"},
    "Sections": {".text": {"Entropy": 6.6}},
    "Plugins": {
        "authenticode": {"level": 0, "summary": "Signed", "plugin_output": {"info_0": "Trusted"}},
        "imports": {
            "level": 2,
            "summary": "Suspicious imports",
            "plugin_output": {"Creates processes": ["CreateProcessA"]},
        },
        "compilers": {"level": 1, "plugin_output": {"info_0": "MSVC"}},
        "peid": {"level": 3, "summary": "Packed"},
    },
}


def query(content=SAMPLE, kind="attachment", value=None, config=None):
    if value is None:
        value = "program.exe" + ("|" + hashlib.md5(SAMPLE).hexdigest() if kind == "malware-sample" else "")
    return json.dumps(
        {
            "attribute": {
                "type": kind,
                "value": value,
                "uuid": UUID,
                "data": base64.b64encode(content).decode(),
                "to_ids": False,
                "comment": "source metadata",
            },
            "config": config,
        }
    )


def run_report(report=REPORT, raw=None, returncode=0):
    def run(args, **kwargs):
        sample = Path(args[-1])
        assert sample.read_bytes() == SAMPLE
        kwargs["stdout"].write(raw if raw is not None else json.dumps({str(sample): report}).encode())
        return subprocess.CompletedProcess(args, returncode)

    return run


def attributes(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def test_discovery():
    assert module.handler() is False
    assert module.introspection() == {"input": ["attachment", "malware-sample"], "format": "misp_standard"}
    assert module.version()["config"] == module.moduleconfig
    assert module.version()["module-type"] == ["expansion"]


def test_full_report_and_independent_verdicts():
    with patch.object(module.subprocess, "run", side_effect=run_report()) as run:
        result = module.handler(query())
    objects = result["results"]["Object"]
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == UUID and source["comment"] == "source metadata"
    assert base64.b64decode(source["data"]) == SAMPLE
    file_object, annotation = objects[:2]
    assert attributes(file_object)["filename"] == "program.exe"
    assert attributes(file_object)["size-in-bytes"] == str(len(SAMPLE))
    assert attributes(file_object)["sha256"] == hashlib.sha256(SAMPLE).hexdigest()
    report_attribute = next(a for a in annotation["Attribute"] if a["object_relation"] == "attachment")
    assert json.loads(base64.b64decode(report_attribute["data"])) == REPORT
    assert "misp-manalyze-" not in base64.b64decode(report_attribute["data"]).decode()
    verdicts = {attributes(o)["module"]: attributes(o)["result"] for o in objects[2:]}
    assert verdicts == {"authenticode": "benign", "imports": "suspicious", "compilers": "unknown", "peid": "malicious"}
    assert file_object["ObjectReference"][0]["referenced_uuid"] == UUID
    for obj in objects[1:]:
        assert any(ref["referenced_uuid"] == file_object["uuid"] for ref in obj["ObjectReference"])
    assert all(a["to_ids"] is False for obj in objects for a in obj["Attribute"])
    for obj in objects:
        # Validate against PyMISP's shipped templates and required relations.
        parsed = MISPObject(obj["name"], strict=True)
        parsed.from_dict(**obj)
        parsed.to_json(strict=True)
    event = MISPEvent()
    event.from_dict(info="Manalyze enrichment", **result["results"])
    args, kwargs = run.call_args
    command = args[0]
    assert command[0] == "manalyze"
    assert "--output=json" in command and "--dump=all" in command and "--hashes" in command
    assert "virustotal" not in command[4] and "all" not in command[4]
    assert kwargs["timeout"] == 60 and kwargs.get("shell", False) is False
    assert not Path(command[-1]).exists()


def test_malware_sample_zip_with_misp_filename_metadata():
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        archive.writestr("digest", SAMPLE)
        archive.writestr("digest.filename.txt", "program.exe")
    with patch.object(module.subprocess, "run", side_effect=run_report()):
        result = module.handler(
            query(content.getvalue(), kind="malware-sample", value="program.exe|" + hashlib.md5(SAMPLE).hexdigest())
        )
    assert attributes(result["results"]["Object"][0])["filename"] == "program.exe"


def test_encrypted_misp_zip():
    # The repository's encrypted EICAR fixture exercises password handling;
    # it must be rejected as a non-PE after extraction, before invoking Manalyze.
    with patch.object(module.subprocess, "run") as run:
        with zipfile.ZipFile("tests/infected.zip") as archive:
            digest = hashlib.md5(archive.read(archive.namelist()[0], pwd=b"infected")).hexdigest()
        result = module.handler(
            query(Path("tests/infected.zip").read_bytes(), kind="malware-sample", value="eicar|" + digest)
        )
    assert "MZ header" in result["error"]
    run.assert_not_called()


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_requests(raw):
    with patch.object(module.subprocess, "run") as run:
        assert "error" in module.handler(raw)
    run.assert_not_called()


@pytest.mark.parametrize(
    "key,value", [("type", "md5"), ("value", ""), ("uuid", None), ("data", "%%%"), ("data", ""), ("data", 42)]
)
def test_invalid_attribute(key, value):
    request = json.loads(query())
    request["attribute"][key] = value
    with patch.object(module.subprocess, "run") as run:
        assert "error" in module.handler(json.dumps(request))
    run.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [
        {"timeout": "0"},
        {"timeout": "301"},
        {"timeout": True},
        {"max_size_mb": "101"},
        {"binary": []},
        {"binary": "\x00"},
        [1],
    ],
)
def test_invalid_configuration(config):
    with patch.object(module.subprocess, "run") as run:
        assert "error" in module.handler(query(config=config))
    run.assert_not_called()


def test_custom_executable_is_one_argument():
    with patch.object(module.subprocess, "run", side_effect=run_report()) as run:
        assert "results" in module.handler(query(config={"binary": "/opt/manalyze install/manalyze", "timeout": "12"}))
    assert run.call_args.args[0][0] == "/opt/manalyze install/manalyze"
    assert run.call_args.kwargs["timeout"] == 12


@pytest.mark.parametrize(
    "failure,message",
    [
        (FileNotFoundError(), "not found"),
        (PermissionError(), "unable to run"),
        (subprocess.TimeoutExpired("manalyze", 60), "timed out"),
    ],
)
def test_process_failures_cleanup(failure, message):
    with patch.object(module.subprocess, "run", side_effect=failure) as run:
        result = module.handler(query())
    assert message in result["error"]
    assert not Path(run.call_args.args[0][-1]).parent.exists()


@pytest.mark.parametrize("raw", [b"{}", b"[]", b"not json", b"\xff", b'{"wrong-path": {"Summary": {}}}'])
def test_invalid_output(raw):
    with patch.object(module.subprocess, "run", side_effect=run_report(raw=raw)):
        assert "error" in module.handler(query())


@pytest.mark.parametrize(
    "report",
    [
        None,
        {},
        {"Summary": [], "Plugins": {}},
        {"Summary": {}, "Plugins": []},
        {"Summary": {}, "Plugins": {"x": {"level": True}}},
        {"Summary": {}, "Plugins": {"x": {"level": 4}}},
        {"Summary": {}, "Plugins": {"x": {"level": 2, "summary": []}}},
    ],
)
def test_invalid_report(report):
    with patch.object(module.subprocess, "run", side_effect=run_report(report)):
        assert "error" in module.handler(query())


def test_no_plugins_is_valid():
    with patch.object(module.subprocess, "run", side_effect=run_report({"Summary": {}})):
        result = module.handler(query())
    assert [o["name"] for o in result["results"]["Object"]] == ["file", "annotation"]


def test_nonzero_exit():
    with patch.object(module.subprocess, "run", side_effect=run_report(returncode=1)):
        assert "failed" in module.handler(query())["error"]


def test_report_size_limit():
    with patch.object(module, "MAX_REPORT_BYTES", 10), patch.object(module.subprocess, "run", side_effect=run_report()):
        assert "20 MiB" in module.handler(query())["error"]


def test_input_size_limit():
    with patch.object(module.subprocess, "run") as run:
        assert "max_size_mb" in module.handler(query(b"MZ" + b"a" * (1024 * 1024), config={"max_size_mb": 1}))["error"]
    run.assert_not_called()


def test_zip_expansion_size_limit():
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("sample", b"MZ" + b"a" * (1024 * 1024))
    with patch.object(module.subprocess, "run") as run:
        result = module.handler(query(content.getvalue(), kind="malware-sample", config={"max_size_mb": 1}))
    assert "max_size_mb" in result["error"]
    run.assert_not_called()


@pytest.mark.parametrize("members", [[], [("one", SAMPLE), ("two", SAMPLE)]])
def test_ambiguous_zip(members):
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        for name, data in members:
            archive.writestr(name, data)
    with patch.object(module.subprocess, "run") as run:
        assert "exactly one" in module.handler(query(content.getvalue(), kind="malware-sample"))["error"]
    run.assert_not_called()


def test_bad_zip():
    with patch.object(module.subprocess, "run") as run:
        assert "ZIP" in module.handler(query(b"bad zip", kind="malware-sample"))["error"]
    run.assert_not_called()


def test_malware_sample_hash_mismatch():
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        archive.writestr("sample", SAMPLE)
    with patch.object(module.subprocess, "run") as run:
        result = module.handler(query(content.getvalue(), kind="malware-sample", value="sample.exe|" + "0" * 32))
    assert "MD5 does not match" in result["error"]
    run.assert_not_called()


@pytest.mark.parametrize("value", ["sample.exe", "sample.exe|bad", "|" + "0" * 32])
def test_malware_sample_invalid_value(value):
    with patch.object(module.subprocess, "run") as run:
        assert "filename|md5" in module.handler(query(kind="malware-sample", value=value))["error"]
    run.assert_not_called()
