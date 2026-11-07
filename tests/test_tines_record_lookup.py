import copy
import json
from unittest.mock import patch

import pytest
import requests
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.expansion import tines_record_lookup as module
from tests.test_tines_client import CONFIG, FakeAPI

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"


def query(kind="domain", value="example.org", **config):
    return {
        "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "original"},
        "config": {**CONFIG, "record_type_id": "42", "field_id": "101", **config},
    }


def report(result):
    assert "error" not in result, result
    obj = result["results"]["Object"][0]
    assert obj["name"] == "annotation" and obj["ObjectReference"][0]["referenced_uuid"] == UUID
    assert obj["Attribute"][0]["to_ids"] is False and obj["Attribute"][0]["disable_correlation"] is True
    event = MISPEvent()
    event.from_dict(info="Synthetic Tines result", **result["results"])
    return json.loads(obj["Attribute"][0]["value"])


@pytest.fixture
def api():
    fake = FakeAPI()
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
        ("text", 'quote" AND field=x'),
        ("vulnerability", "CVE-2026-12345"),
    ],
)
def test_literal_v2_filter_source_preservation_and_artifact_handles(api, kind, value):
    request = query(kind, value, limit="3", test_mode="true")
    original = copy.deepcopy(request)
    result = module.handler(json.dumps(request))
    data = report(result)
    assert result["results"]["Attribute"] == [original["attribute"]] and request == original
    prepared = api.calls[0][0]
    assert prepared.url == CONFIG["url"] + "/api/v2/records/search"
    assert json.loads(prepared.body) == {
        "record_type_id": 42,
        "filter": {"field_id": 101, "operator": "EQUAL", "value": value},
        "include_total": True,
        "limit": 3,
        "test_mode": True,
    }
    assert data["query"] == value and data["status"] == "found" and data["total"] == 1
    assert data["records"][0]["fields"]["enabled"] is False
    assert data["records"][0]["fields"]["payload"]["expandable"] is True and len(api.calls) == 1


def response(rows=None, **updates):
    return {
        "data": [] if rows is None else rows,
        "field_ids": {"indicator": 101},
        "page": {"total": len(rows or [])},
        "applied": {"filter": {"field_id": 101, "operator": "EQUAL", "value": "example.org"}},
        **updates,
    }


def row():
    return {"id": 555, "fields": {"indicator": "example.org"}, "relationships": {"record_type": {"id": 42}}}


def test_empty_result_is_not_a_benign_verdict(api):
    api.replies["/api/v2/records/search"] = response()
    data = report(module.handler(json.dumps(query())))
    assert data["status"] == "not_found" and data["total"] == 0 and data["records"] == [] and not data["truncated"]


def test_cursor_is_reported_without_following_it(api):
    api.replies["/api/v2/records/search"] = response(
        [row()], page={"total": 2, "next_page_token": "https://unexpected.example/collect"}
    )
    result = module.handler(json.dumps(query()))
    assert report(result)["truncated"] and result["warnings"] and len(api.calls) == 1


def test_equivalent_normalized_filter_is_accepted(api):
    body = response([row()])
    body["applied"]["filter"] = {"op": "AND", "nodes": [body["applied"]["filter"]]}
    api.replies["/api/v2/records/search"] = body
    assert report(module.handler(json.dumps(query())))["status"] == "found"


def test_boolean_filter_id_cannot_confirm_integer_identity(api):
    body = response()
    body["applied"]["filter"]["field_id"] = True
    api.replies["/api/v2/records/search"] = body
    assert "error" in module.handler(json.dumps(query(field_id=1)))


@pytest.mark.parametrize(
    "body",
    [
        response(applied=None),
        response(applied={"filter": None}),
        response(applied={"filter": {"field_id": 102, "operator": "EQUAL", "value": "example.org"}}),
        response(applied={"filter": {"field_id": 101, "operator": "CONTAINS", "value": "example.org"}}),
        response([row()], field_ids={}),
        response([row()], field_ids={"indicator": True}),
        response(data=None),
        response([row()], page={}),
        response(page={"total": 1}),
        response([row()], page={"total": False}),
        response([row()], page={"total": 1, "next_page_token": 2}),
        response(page={"total": 0, "next_page_token": "more"}),
        response([row(), row()]),
        response([{**row(), "id": True}]),
        response([{**row(), "relationships": {"record_type": {"id": 43}}}]),
        response([{**row(), "fields": None}]),
    ],
)
def test_malformed_mismatched_and_incomplete_responses_are_errors(api, body):
    api.replies["/api/v2/records/search"] = body
    assert "error" in module.handler(json.dumps(query()))


@pytest.mark.parametrize(
    "config",
    [
        {"record_type_id": None},
        {"field_id": 0},
        {"field_id": True},
        {"limit": 101},
        {"limit": 0},
        {"test_mode": "invalid"},
    ],
)
def test_invalid_query_configuration_makes_no_request(api, config):
    assert "error" in module.handler(json.dumps(query(**config))) and not api.calls


@pytest.mark.parametrize(
    "field,value", [("type", "attachment"), ("uuid", "bad"), ("value", []), ("value", ""), ("value", "\ud800")]
)
def test_invalid_attribute_makes_no_request(api, field, value):
    request = query()
    request["attribute"][field] = value
    assert "error" in module.handler(json.dumps(request)) and not api.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(api, raw):
    assert "error" in module.handler(raw) and not api.calls


def test_discovery_contract():
    assert module.handler(False) is False and module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig


class TestTinesLookupHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"tines_record_lookup": module, "type:tines_record_lookup": "expansion"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "tines_record_lookup"
        fake = FakeAPI()
        with patch.object(
            requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
        ):
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": "tines_record_lookup", **query()}),
            )
        assert response.code == 200 and report(json.loads(response.body))["status"] == "found"
