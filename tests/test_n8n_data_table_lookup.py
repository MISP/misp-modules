import copy
import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.expansion import n8n_data_table_lookup as module
from tests.test_n8n_client import ORIGIN, SECRET, TABLE_ID, FakeHTTP

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
ENDPOINT = "/api/v1/data-tables/" + TABLE_ID


def query(kind="domain", value="example.org", **config):
    return {
        "attribute": {"uuid": UUID, "type": kind, "value": value, "to_ids": True, "comment": "original"},
        "config": {
            "url": ORIGIN + "/api/v1",
            "api_key": SECRET,
            "data_table_id": TABLE_ID,
            "column": "indicator",
            **config,
        },
    }


def report(result):
    assert "error" not in result, result
    obj = result["results"]["Object"][0]
    assert obj["name"] == "annotation" and obj["ObjectReference"][0]["referenced_uuid"] == UUID
    assert obj["Attribute"][0]["to_ids"] is False and obj["Attribute"][0]["disable_correlation"] is True
    event = MISPEvent()
    event.from_dict(info="Synthetic n8n lookup", **result["results"])
    return json.loads(obj["Attribute"][0]["value"])


@pytest.fixture
def http():
    fake = FakeHTTP()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


@pytest.mark.parametrize(
    "kind,value",
    [
        ("domain", "faß.de"),
        ("ip-src", "2001:0db8::1"),
        ("sha256", "A" * 64),
        ("url", "https://example.org/Case?q=One"),
        ("text", 'quote"&filter=all'),
        ("vulnerability", "CVE-2026-12345"),
    ],
)
def test_literal_public_api_filter_preserves_source_and_non_ids_results(http, kind, value):
    http.replies[ENDPOINT + "/rows"] = {
        "data": [{"id": 1, "indicator": value, "active": False, "score": 0}],
        "nextCursor": None,
    }
    request = query(kind, value, limit="3")
    original = copy.deepcopy(request)
    result = module.handler(json.dumps(request))
    data = report(result)
    assert result["results"]["Attribute"] == [original["attribute"]] and request == original
    assert data["rows"][0]["active"] is False and data["rows"][0]["score"] == 0
    assert data["status"] == "found" and data["query"] == value and not data["truncated"]
    assert len(http.calls) == 2
    columns, rows = [call[0] for call in http.calls]
    assert columns.url == ORIGIN + ENDPOINT + "/columns" and rows.method == columns.method == "GET"
    assert urlsplit(rows.url).path == ENDPOINT + "/rows"
    params = parse_qs(urlsplit(rows.url).query)
    assert params["limit"] == ["3"] and params["sortBy"] == ["id:asc"]
    assert json.loads(params["filter"][0]) == {
        "type": "and",
        "filters": [{"columnName": "indicator", "condition": "eq", "value": value}],
    }
    assert rows.headers["X-N8N-API-KEY"] == SECRET and "Authorization" not in rows.headers


def test_empty_page_is_no_match_not_a_benign_verdict(http):
    http.replies[ENDPOINT + "/rows"] = {"data": [], "nextCursor": None}
    data = report(module.handler(json.dumps(query())))
    assert data["status"] == "not_found" and data["rows"] == [] and not data["truncated"]


def test_cursor_is_reported_without_following_provider_urls(http):
    http.replies[ENDPOINT + "/rows"] = {
        "data": [{"id": 1, "indicator": "example.org"}],
        "nextCursor": "https://unexpected.example/collect",
    }
    result = module.handler(json.dumps(query()))
    assert report(result)["truncated"] and result["warnings"] and len(http.calls) == 2


def test_self_hosted_deployment_subpath_is_preserved(http):
    result = module.handler(json.dumps(query(url=ORIGIN + "/automation/api/v1/")))
    assert report(result)["status"] == "found"
    assert all(call.url.startswith(ORIGIN + "/automation/api/v1/data-tables/") for call, _ in http.calls)


@pytest.mark.parametrize(
    "columns",
    [
        {"data": []},
        [],
        [None],
        [{"name": "indicator", "type": "number", "dataTableId": TABLE_ID}],
        [{"name": "indicator", "type": "string", "dataTableId": "other"}],
        [{"name": "other", "type": "string", "dataTableId": TABLE_ID}],
        [{"name": "indicator", "type": "string", "dataTableId": TABLE_ID}] * 2,
    ],
)
def test_column_identity_and_string_type_are_checked_before_query(http, columns):
    http.replies[ENDPOINT + "/columns"] = columns
    assert "error" in module.handler(json.dumps(query())) and len(http.calls) == 1


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"data": [], "nextCursor": False},
        {"data": []},
        {"data": [], "nextCursor": "more"},
        {"data": [{"id": 1, "indicator": "unrelated"}], "nextCursor": None},
        {"data": [{"id": True, "indicator": "example.org"}], "nextCursor": None},
        {"data": [{"id": 1, "indicator": False}], "nextCursor": None},
        {"data": [{"id": 1}], "nextCursor": None},
        {"data": [{"id": 1, "indicator": "example.org"}] * 2, "nextCursor": None},
        {"data": [{"id": 1, "indicator": "example.org"}], "nextCursor": ""},
        {"data": "bad", "nextCursor": None},
    ],
)
def test_invalid_mismatched_and_incomplete_pages_are_errors(http, body):
    http.replies[ENDPOINT + "/rows"] = body
    assert "error" in module.handler(json.dumps(query())) and len(http.calls) == 2


def test_provider_cannot_exceed_requested_limit(http):
    http.replies[ENDPOINT + "/rows"] = {
        "data": [{"id": 1, "indicator": "example.org"}, {"id": 2, "indicator": "example.org"}],
        "nextCursor": None,
    }
    assert "error" in module.handler(json.dumps(query(limit="1")))


@pytest.mark.parametrize("suffix", ["/columns", "/rows"])
@pytest.mark.parametrize("status", [401, 403, 404, 429])
def test_access_and_api_errors_are_never_no_match(http, suffix, status):
    http.replies[ENDPOINT + suffix] = (status, {"error": SECRET})
    result = module.handler(json.dumps(query()))
    assert "error" in result and str(status) in result["error"] and SECRET not in json.dumps(result)


@pytest.mark.parametrize(
    "config",
    [
        {"data_table_id": "../other"},
        {"data_table_id": True},
        {"data_table_id": "short"},
        {"column": "id"},
        {"column": "createdAt"},
        {"column": "indicator OR 1=1"},
        {"url": ORIGIN},
        {"api_key": ""},
        {"limit": True},
        {"limit": 101},
        {"timeout": 0},
    ],
)
def test_invalid_configuration_makes_no_api_call(http, config):
    assert "error" in module.handler(json.dumps(query(**config))) and not http.calls


@pytest.mark.parametrize(
    "field,value",
    [("uuid", "bad"), ("type", "attachment"), ("value", ""), ("value", []), ("value", "x" * 4097), ("value", "\ud800")],
)
def test_invalid_source_makes_no_api_call(http, field, value):
    request = query()
    request["attribute"][field] = value
    assert "error" in module.handler(json.dumps(request)) and not http.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(http, raw):
    assert "error" in module.handler(raw) and not http.calls


def test_discovery_contract():
    assert module.handler(False) is False and module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig


class TestN8nLookupHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"n8n_data_table_lookup": module, "type:n8n_data_table_lookup": "expansion"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "n8n_data_table_lookup"
        fake = FakeHTTP()
        with patch.object(
            requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
        ):
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": "n8n_data_table_lookup", **query()}),
            )
        assert response.code == 200 and report(json.loads(response.body))["status"] == "found"
