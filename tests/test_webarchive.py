import json
from copy import deepcopy
from datetime import datetime, timezone
from importlib import resources
from unittest.mock import Mock

import pytest
import requests
from pymisp import MISPObject

from misp_modules.modules.expansion import webarchive

SOURCE_UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
URL = "https://example.com/report?a=1&b=2"
ARCHIVE = "http://web.archive.org/web/20130919044612/https://example.com/report?a=1&b=2"
SNAPSHOT = {"available": True, "url": ARCHIVE, "timestamp": "20130919044612", "status": "200"}


@pytest.fixture
def get(monkeypatch):
    response = Mock()
    response.json.return_value = {"archived_snapshots": {"closest": deepcopy(SNAPSHOT)}}
    get = Mock(return_value=response)
    monkeypatch.setattr(webarchive.requests, "get", get)
    return get


def _run(value=URL, attribute_type="url", **extra):
    request = {"attribute": {"type": attribute_type, "value": value, "uuid": SOURCE_UUID}}
    request.update(extra)
    return webarchive.handler(json.dumps(request))


def test_archive_object_and_original_attribute(get):
    attribute = {"type": "url", "value": URL, "uuid": SOURCE_UUID, "comment": "Original context", "to_ids": True}
    result = _run(attribute=attribute)
    assert result["results"]["Attribute"][0].items() >= attribute.items()
    obj = result["results"]["Object"][0]
    assert obj["name"] == "page-capture"
    values = {a["object_relation"]: a["value"] for a in obj["Attribute"]}
    assert values["url"] == URL
    assert values["archive"] == ARCHIVE
    assert datetime.fromisoformat(values["capture-date"]) == datetime(2013, 9, 19, 4, 46, 12, tzinfo=timezone.utc)
    assert all(a["to_ids"] is False for a in obj["Attribute"])
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in obj["ObjectReference"]] == [
        (SOURCE_UUID, "related-to")
    ]
    template = json.loads(
        resources.files("misp_modules").joinpath("data", "page-capture", "definition.json").read_text()
    )
    strict_obj = MISPObject("page-capture", strict=True, misp_objects_template_custom=template)
    strict_obj.from_dict(**obj)
    strict_obj._validate()
    get.assert_called_once_with(webarchive.AVAILABILITY_URL, params={"url": URL}, timeout=15)


@pytest.mark.parametrize(
    "attribute_type,value,expected",
    [
        ("link", URL, URL),
        ("url", "https://example.com/é#fragment", "https://example.com/é#fragment"),
        ("domain", "example.com", "http://example.com/"),
        ("hostname", "www.example.com.", "http://www.example.com/"),
        ("domain", "bücher.example", "http://xn--bcher-kva.example/"),
    ],
)
def test_supported_inputs(get, attribute_type, value, expected):
    assert "results" in _run(value, attribute_type)
    assert get.call_args.kwargs["params"] == {"url": expected}


@pytest.mark.parametrize("timestamp", ["2", "20060101", "20060101000000"])
def test_historical_lookup(get, timestamp):
    assert "results" in _run(config={"timestamp": timestamp})
    assert get.call_args.kwargs["params"] == {"url": URL, "timestamp": timestamp}


@pytest.mark.parametrize("config", [None, {}, {"timestamp": ""}])
def test_empty_configuration_queries_latest(get, config):
    assert "results" in _run(config=config)
    assert get.call_args.kwargs["params"] == {"url": URL}


@pytest.mark.parametrize(
    "snapshots",
    [{}, {"closest": {}}, {"closest": dict(SNAPSHOT, available=False)}, {"closest": dict(SNAPSHOT, status="404")}],
)
def test_no_accessible_snapshot_creates_no_object(get, snapshots):
    get.return_value.json.return_value = {"archived_snapshots": snapshots}
    result = _run()
    assert "No accessible archive" in result["error"]
    assert "results" not in result


@pytest.mark.parametrize(
    "payload",
    [None, [], {}, {"archived_snapshots": []}, {"archived_snapshots": {"closest": []}}],
)
def test_invalid_api_responses(get, payload):
    get.return_value.json.return_value = payload
    assert "error" in _run()


@pytest.mark.parametrize(
    "changes",
    [
        {"url": None},
        {"url": "https://example.com/not-an-archive"},
        {"url": "https://web.archive.org.evil.example/web/20130919044612/example.com"},
        {"timestamp": None},
        {"timestamp": "20130919"},
        {"timestamp": "20130230000000"},
    ],
)
def test_invalid_snapshot_metadata(get, changes):
    get.return_value.json.return_value = {"archived_snapshots": {"closest": dict(SNAPSHOT, **changes)}}
    assert "error" in _run()


@pytest.mark.parametrize("failure", [requests.Timeout("timed out"), requests.ConnectionError("offline")])
def test_network_errors(get, failure):
    get.side_effect = failure
    assert "Wayback Machine request failed" in _run()["error"]


@pytest.mark.parametrize("status", [429, 500, 503])
def test_http_errors_are_not_reported_as_missing_archives(get, status):
    get.return_value.raise_for_status.side_effect = requests.HTTPError(str(status))
    assert "Wayback Machine request failed" in _run()["error"]
    get.return_value.json.assert_not_called()


def test_non_json_response(get):
    get.return_value.json.side_effect = requests.exceptions.JSONDecodeError("Invalid JSON", "<html>", 0)
    assert "error" in _run()


@pytest.mark.parametrize(
    "value,attribute_type",
    [
        (None, "url"),
        ("", "link"),
        ("example.com", "url"),
        ("ftp://example.com", "url"),
        ("https:///path", "url"),
        ("https://example.com/\n", "url"),
        ("http://example.com:bad/", "url"),
        ("bad host", "domain"),
        ("example.com/path", "hostname"),
        ("https://example.com", "domain"),
    ],
)
def test_invalid_values_do_not_query(get, value, attribute_type):
    assert "error" in _run(value, attribute_type)
    get.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [[], "bad", {"timestamp": 2006}, {"timestamp": "2006-01-01"}, {"timestamp": "1" * 15}, {"timestamp": "２００６"}],
)
def test_invalid_config_does_not_query(get, config):
    assert "error" in _run(config=config)
    get.assert_not_called()


@pytest.mark.parametrize("query", ["{", "null", "[]", "{}", '{"attribute": []}', '{"attribute": {"type": "url"}}'])
def test_invalid_requests(get, query):
    assert "error" in webarchive.handler(query)
    get.assert_not_called()


@pytest.mark.parametrize(
    "attribute",
    [
        {"type": "ip-dst", "value": "1.1.1.1", "uuid": SOURCE_UUID},
        {"type": "url", "value": URL, "uuid": "invalid"},
        {"type": "url", "value": URL, "uuid": None},
    ],
)
def test_unsupported_type_or_invalid_uuid(get, attribute):
    assert "error" in _run(attribute=attribute)
    get.assert_not_called()


def test_metadata():
    assert webarchive.handler() is False
    assert webarchive.introspection() == {"input": ["url", "link", "domain", "hostname"], "format": "misp_standard"}
    assert webarchive.version()["module-type"] == ["expansion"]
    assert webarchive.version()["config"] == ["timestamp"]
