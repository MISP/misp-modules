import base64
import copy
import io
import json
import stat
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.modules.import_mod import cuckooimport as module
from misp_modules.modules.import_mod.cuckooimport import CuckooParser


def _parser():
    parser = CuckooParser({})
    parser.report = {}
    return parser


def test_add_http_without_network_section():
    """A report without a "network" section must not raise."""
    assert _parser().add_http() is False


def test_add_network_without_network_section():
    parser = _parser()
    assert parser.add_network("tcp") is False
    assert parser.add_network("udp") is False


def test_add_dns_without_network_section():
    assert _parser().add_dns() is False


@pytest.fixture
def cape_report():
    return json.loads((Path(__file__).parent / "fixtures" / "cape_report.json").read_text())


def request(content, config=None):
    return json.dumps({"data": base64.b64encode(content).decode(), "config": {} if config is None else config})


def import_report(report, config=None):
    return module.handler(request(json.dumps(report).encode(), config))


def objects(result, name):
    assert "error" not in result, result
    return [obj for obj in result["results"].get("Object", []) if obj["name"] == name]


def values(obj, relation):
    return [attr["value"] for attr in obj["Attribute"] if attr["object_relation"] == relation]


def archive_bytes(files, kind="zip", symlink=None):
    output = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(output, "w") as archive:
            for path, data in files.items():
                # ZIPs from non-Unix systems may omit the file type bits.
                info = zipfile.ZipInfo(path)
                info.create_system = 0
                archive.writestr(info, data)
            if symlink:
                info = zipfile.ZipInfo(symlink)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, "elsewhere.json")
    else:
        with tarfile.open(fileobj=output, mode="w:bz2") as archive:
            for path, data in files.items():
                info = tarfile.TarInfo(path)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            if symlink:
                info = tarfile.TarInfo(symlink)
                info.type = tarfile.SYMTYPE
                info.linkname = "elsewhere.json"
                archive.addfile(info)
    return output.getvalue()


def test_cape_json_imports_current_fields_without_bundled_binaries(cape_report):
    result = import_report(cape_report)
    sandbox = objects(result, "sandbox-report")[0]
    assert values(sandbox, "on-premise-sandbox") == ["cape"]
    assert float(values(sandbox, "score")[0]) == 7.5
    assert "2026-11-01 12:00:00" in values(sandbox, "raw-report")[0]

    sample, dropped = objects(result, "file")
    assert values(sample, "filename") == ["sample.exe"]
    assert values(sample, "sha256") == ["a" * 64]
    assert values(dropped, "filename") == ["payload.dll"]
    assert values(dropped, "sha256") == ["b" * 64]
    assert values(dropped, "fullpath") == [r"C:\Users\analyst\AppData\payload.dll"]
    assert all(attr["category"] == "Artifacts dropped" for attr in dropped["Attribute"] if attr["type"] == "sha256")
    assert not any(
        "data" in attr or attr["type"] == "malware-sample" for obj in (sample, dropped) for attr in obj["Attribute"]
    )

    parent, child = objects(result, "process")
    assert values(parent, "name") == ["sample.exe"]
    assert values(parent, "command-line") == [r"C:\sample.exe --test"]
    assert values(child, "parent-pid") == ["100"]
    assert child["ObjectReference"][0]["referenced_uuid"] == parent["uuid"]
    assert dropped["ObjectReference"][0]["referenced_uuid"] == child["uuid"]
    assert objects(result, "dns-record") and objects(result, "http-request")
    tcp, udp = objects(result, "network-connection")
    assert not values(tcp, "first-packet-seen")
    assert not values(udp, "first-packet-seen")
    assert tcp["comment"] == "First packet observed 1.5 seconds after capture start"
    assert udp["comment"] == "First packet observed 2 seconds after capture start"

    signature = objects(result, "sb-signature")[0]
    assert values(signature, "software") == ["CAPE"]
    assert "long-value-preserved-without-truncation-123456789" in values(signature, "signature")[0]
    assert "T1059" in values(signature, "signature")[0]
    assert json.loads(values(objects(result, "annotation")[0], "text")[0]) == cape_report["CAPE"]["configs"][0]


@pytest.mark.parametrize("kind", ["zip", "bz2"])
@pytest.mark.parametrize("report_path", ["reports/report.json", "report.json"])
def test_cape_report_archives_retain_imports(cape_report, kind, report_path):
    result = module.handler(request(archive_bytes({report_path: json.dumps(cape_report).encode()}, kind)))
    assert len(objects(result, "file")) == 2
    assert len(objects(result, "process")) == 2
    assert objects(result, "sb-signature")


@pytest.mark.parametrize("kind", ["zip", "bz2"])
def test_archives_preserve_real_binaries_and_screenshots(cape_report, kind):
    data = archive_bytes(
        {
            "reports/report.json": json.dumps(cape_report).encode(),
            "binary": b"harmless sample content",
            "files/payload": b"harmless dropped content",
            "shots/0001.jpg": b"screenshot content",
        },
        kind,
    )
    result = module.handler(request(data))
    assert all(values(obj, "malware-sample") for obj in objects(result, "file"))
    screenshots = [obj for obj in objects(result, "sandbox-report") if values(obj, "sandbox-file")]
    assert values(screenshots[0], "sandbox-file") == ["0001.jpg"]
    attachment = next(a for a in screenshots[0]["Attribute"] if a["object_relation"] == "sandbox-file")
    assert base64.b64decode(attachment["data"]) == b"screenshot content"


def test_cuckoo_fields_and_marks_remain_supported():
    report = {
        "info": {"score": 0, "duration": 30, "machine": {"started_on": "2020-01-01", "name": "vm", "label": "vm"}},
        "target": {"category": "url", "url": "https://example.org"},
        "behavior": {"processtree": [{"pid": 10, "ppid": 0, "process_name": "browser", "command_line": "browser"}]},
        "signatures": [
            {
                "description": "Legacy signature",
                "marks": [{"type": "ioc", "ioc": "example.org", "pid": 10}],
                "ttp": {"T1059": {"short": "Command and Scripting Interpreter"}},
            }
        ],
    }
    original = copy.deepcopy(report)
    result = import_report(report)
    assert values(objects(result, "sandbox-report")[0], "on-premise-sandbox") == ["cuckoo"]
    assert float(values(objects(result, "sandbox-report")[0], "score")[0]) == 0
    assert values(objects(result, "url")[0], "url") == ["https://example.org"]
    process = objects(result, "process")[0]
    assert values(process, "parent-pid") == ["0"]
    assert process["ObjectReference"][0]["relationship_type"] == "triggers"
    signature = objects(result, "sb-signature")[0]
    assert "example.org" in values(signature, "signature")[0]
    assert "T1059" in signature["Attribute"][-1]["Tag"][0]["name"]
    parser = CuckooParser({})
    parser.report = original
    parser.add_signatures()
    assert parser.report == report


@pytest.mark.parametrize("machine", [None, "vm-name", {}])
def test_optional_cape_machine_and_score(cape_report, machine):
    cape_report["info"]["machine"] = machine
    cape_report.pop("malscore")
    result = import_report(cape_report)
    assert objects(result, "sandbox-report")


def test_static_analysis_and_zero_malscore(cape_report):
    cape_report["target"]["category"] = "static"
    cape_report["malscore"] = 0
    result = import_report(cape_report)
    assert values(objects(result, "file")[0], "sha256") == ["a" * 64]
    assert float(values(objects(result, "sandbox-report")[0], "score")[0]) == 0


def test_standalone_report_does_not_fabricate_screenshot_attachments(cape_report):
    cape_report["screenshots"] = [{"path": "/analysis/42/shots/0001.jpg"}]
    result = import_report(cape_report)
    assert len(objects(result, "sandbox-report")) == 1
    assert not values(objects(result, "sandbox-report")[0], "sandbox-file")


def test_user_options_can_disable_sections(cape_report):
    config = {key: "0" for key in CuckooParser.options}
    config["DNS"] = "1"
    result = import_report(cape_report, config)
    assert [obj["name"] for obj in result["results"]["Object"]] == ["dns-record"]


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"data": 42}'])
def test_invalid_envelope_returns_actionable_error(raw):
    assert "error" in module.handler(raw)


@pytest.mark.parametrize("content", [b"", b"not JSON", b"[]", b"null", b"{}", b'{"unrelated": 1}', b'{"network": []}'])
def test_invalid_reports_return_actionable_errors(content):
    assert "error" in module.handler(request(content))


def test_invalid_base64_and_config():
    assert "base64" in module.handler(json.dumps({"data": "!!!"}))["error"]
    assert "configuration" in module.handler(request(b'{"network": {}}', [1]))["error"]
    assert "DNS" in module.handler(request(b'{"network": {}}', {"DNS": "invalid"}))["error"]
    assert module.handler(False) is False


@pytest.mark.parametrize("kind", ["zip", "bz2"])
def test_missing_report_and_symlinks_are_rejected(kind):
    data = archive_bytes({"elsewhere.json": b'{"network": {}}'}, kind, symlink="reports/report.json")
    assert "regular file" in module.handler(request(data))["error"]


def test_invalid_nested_report_returns_diagnostic(cape_report):
    cape_report["behavior"]["processtree"] = ["invalid process"]
    assert "report structure" in import_report(cape_report)["error"]


def test_archive_streams_are_closed(cape_report):
    parser = CuckooParser({})
    parser.read_archive(base64.b64encode(archive_bytes({"reports/report.json": json.dumps(cape_report).encode()})))
    stream = parser.files["reports/report.json"]
    assert not stream.closed
    parser.close()
    assert stream.closed


@pytest.mark.parametrize("payload", [b"not JSON", b'{"behavior": {"processtree": ["invalid"]}}'])
def test_handler_closes_archive_streams_on_failure(payload, monkeypatch):
    streams = []
    original_close = CuckooParser.close

    def close(parser):
        streams.extend(parser.files.values())
        original_close(parser)

    monkeypatch.setattr(CuckooParser, "close", close)
    result = module.handler(request(archive_bytes({"reports/report.json": payload})))
    assert "error" in result
    assert streams and all(stream.closed for stream in streams)


def test_truncated_bzip2_returns_archive_error():
    assert "archive" in module.handler(request(b"BZh9truncated"))["error"]


class TestCuckooImportAPI(AsyncHTTPTestCase):
    def get_app(self):
        handlers = {"cuckooimport": module, "type:cuckooimport": "import_mod"}
        self.handlers_patch = patch.object(server, "MODULES_HANDLERS", handlers)
        self.handlers_patch.start()
        self.addCleanup(self.handlers_patch.stop)
        return Application([(r"/modules", server.ListModules), (r"/query", server.QueryModule)])

    def test_raw_cape_report_through_query_endpoint(self):
        report = (Path(__file__).parent / "fixtures" / "cape_report.json").read_bytes()
        body = json.loads(request(report))
        body["module"] = "cuckooimport"
        response = self.fetch("/query", method="POST", body=json.dumps(body))
        assert response.code == 200
        result = json.loads(response.body)
        assert objects(result, "file") and objects(result, "process")
        discovered = json.loads(self.fetch("/modules").body)[0]
        assert discovered["type"] == "import_mod"
        assert "CAPE configurations" in discovered["mispattributes"]["userConfig"]

    def test_bad_upload_returns_input_error_instead_of_generic_server_failure(self):
        body = {"module": "cuckooimport", "data": "invalid base64", "config": {}}
        response = self.fetch("/query", method="POST", body=json.dumps(body))
        assert response.code == 200
        result = json.loads(response.body)
        assert "base64" in result["error"]
        assert "Something went wrong" not in result["error"]
