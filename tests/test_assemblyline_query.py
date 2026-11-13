import io
import json
import logging
from unittest.mock import Mock, call, mock_open

import pytest

from misp_modules.modules.expansion import assemblyline_query as module

API_URL = "https://assemblyline.example"
SID = "test-submission-id"
FILE_HASH = "a" * 64


@pytest.fixture
def report():
    return {
        "classification": "TLP:AMBER",
        "file_infos": {FILE_HASH: {"classification": "UNCLASSIFIED", "sha256": FILE_HASH}},
        "file_tree": {FILE_HASH: {"score": 1, "name": ["sample.exe"], "children": {}}},
        "results": {
            FILE_HASH + ".service": {
                "result": {
                    "tags": [
                        {
                            "type": "NET_DOMAIN_NAME",
                            "value": "malware.example",
                            "classification": "TLP:AMBER",
                            "context": "Network connection",
                        }
                    ]
                }
            }
        },
    }


@pytest.fixture
def parser(report):
    parser = module.AssemblyLineParser()
    parser._parse_report(report)
    return parser


@pytest.fixture
def client(monkeypatch, report):
    client = Mock()
    client.get_json.side_effect = lambda path: {"completed": True} if "is_completed" in path else report
    monkeypatch.setattr(module, "AssemblyLineAPI", Mock(return_value=client))
    return client


@pytest.fixture
def request_body():
    return {
        "module": "assemblyline_query",
        "attribute": {
            "type": "link",
            "value": f"{API_URL}/submission/detail/{SID}",
            "uuid": "f6061c52-57d8-46fd-8c4d-043565d27b40",
        },
        "config": {"apiurl": API_URL, "user_id": "test-user", "apikey": "test-api-key", "password": "test-password"},
    }


@pytest.fixture
def debug_file(monkeypatch):
    # Intercept the original module-local open call without affecting PyMISP's
    # object template reads or ever creating the old file in the real /tmp.
    file_open = mock_open()
    monkeypatch.setattr(module, "open", file_open, raising=False)
    return file_open


def test_discovery():
    assert module.handler() is False
    assert "debug" in module.version()["config"]


@pytest.mark.parametrize("debug", [False, True])
def test_never_writes_a_debug_file(parser, debug_file, debug):
    parser.debug = debug
    assert "results" in parser.finalize_results()
    debug_file.assert_not_called()


def test_debug_preserves_enrichment_and_logs_the_parsed_event(parser, caplog):
    caplog.set_level(logging.DEBUG, logger=module.LOGGER.name)
    expected = parser.finalize_results()
    assert not caplog.records
    parser.debug = True
    actual = parser.finalize_results()
    assert actual == expected
    result = actual["results"]
    assert result["Attribute"][0]["value"] == "malware.example"
    assert result["Attribute"][0]["Tag"][0]["name"] == "tlp:amber"
    assert result["Object"][0]["name"] == "file"
    assert {attribute["object_relation"]: attribute["value"] for attribute in result["Object"][0]["Attribute"]} == {
        "sha256": FILE_HASH,
        "filename": "sample.exe",
    }
    assert result["Tag"][0]["name"] == "tlp:amber"
    (record,) = caplog.records
    assert record.name == "misp-modules.assemblyline_query"
    assert record.levelno == logging.DEBUG
    event = json.loads(record.getMessage().removeprefix("Parsed AssemblyLine event: "))
    assert {key: event[key] for key in result} == result


@pytest.mark.parametrize("flag", [True, 1, "true", "TRUE", "  Yes ", "on", "1"])
def test_handler_enables_debug_explicitly(client, request_body, debug_file, caplog, flag):
    caplog.set_level(logging.DEBUG, logger=module.LOGGER.name)
    request_body["config"]["debug"] = flag
    result = module.handler(json.dumps(request_body))
    assert "results" in result
    assert "Parsed AssemblyLine event:" in caplog.text
    assert "malware.example" in caplog.text and "tlp:amber" in caplog.text
    for credential in ("test-user", "test-api-key", "test-password"):
        assert credential not in caplog.text
    client.authenticate.assert_called_once_with(user="test-user", apikey="test-api-key")
    assert client.get_json.call_args_list == [
        call(f"/api/v4/submission/is_completed/{SID}/"),
        call(f"/api/v4/submission/full/{SID}/"),
    ]
    debug_file.assert_not_called()


@pytest.mark.parametrize("flag", [None, False, 0, "false", "FALSE", "0", "off", "no", "", "unexpected", [], {}])
def test_handler_debug_defaults_to_off(client, request_body, debug_file, caplog, flag):
    caplog.set_level(logging.DEBUG, logger=module.LOGGER.name)
    request_body["config"]["debug"] = flag
    assert "results" in module.handler(json.dumps(request_body))
    assert not caplog.records
    debug_file.assert_not_called()


def test_debug_does_not_persist_between_queries(client, request_body, caplog):
    caplog.set_level(logging.DEBUG, logger=module.LOGGER.name)
    request_body["config"]["debug"] = True
    assert "results" in module.handler(json.dumps(request_body))
    assert caplog.records
    caplog.clear()
    del request_body["config"]["debug"]
    assert "results" in module.handler(json.dumps(request_body))
    assert not caplog.records


def test_debug_works_with_service_logger_at_info(client, request_body, monkeypatch):
    stream = io.StringIO()
    service_logger = logging.getLogger("misp-modules")
    monkeypatch.setattr(service_logger, "handlers", [logging.StreamHandler(stream)])
    monkeypatch.setattr(service_logger, "level", logging.INFO)
    monkeypatch.setattr(service_logger, "propagate", False)
    request_body["config"]["debug"] = True
    assert "results" in module.handler(json.dumps(request_body))
    assert "Parsed AssemblyLine event:" in stream.getvalue()


@pytest.mark.parametrize("verifyssl,expected", [(None, True), ("false", False), ("true", True)])
def test_debug_does_not_change_ssl_verification(client, request_body, verifyssl, expected):
    request_body["config"].update(debug=True, verifyssl=verifyssl)
    assert "results" in module.handler(json.dumps(request_body))
    module.AssemblyLineAPI.assert_called_once_with(API_URL, verify=expected)


def test_parser_error_is_preserved_without_dumping(parser, debug_file, caplog):
    caplog.set_level(logging.DEBUG, logger=module.LOGGER.name)
    parser.debug = True
    parser.results = {"error": "Submission unavailable"}
    assert parser.finalize_results() == {"error": "Submission unavailable"}
    assert not caplog.records
    debug_file.assert_not_called()


def test_incomplete_submission_is_preserved(client, request_body, debug_file, caplog):
    caplog.set_level(logging.DEBUG, logger=module.LOGGER.name)
    client.get_json.side_effect = None
    client.get_json.return_value = {"completed": False}
    request_body["config"]["debug"] = True
    assert module.handler(json.dumps(request_body)) == {
        "error": "Submission not completed on AssemblyLine yet, please retry later."
    }
    assert not caplog.records
    debug_file.assert_not_called()


def test_empty_enrichment_is_preserved(debug_file):
    assert module.AssemblyLineParser().finalize_results() == {
        "error": "AssemblyLine query completed but no enrichment data was returned."
    }
    debug_file.assert_not_called()
