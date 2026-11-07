import copy
import json
from unittest.mock import patch

import pytest
import requests
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.expansion import shuffle_datastore_lookup as module
from tests.test_shuffle_client import CONFIG, DATASTORE_SECRET, EXECUTION_ID, EXECUTION_SECRET, ORG_ID, FakeAPI

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"


def query(kind="domain", value="example.org", **config):
    return {
        "attribute": {"uuid": UUID, "type": kind, "value": value, "to_ids": True, "comment": "original"},
        "config": {**CONFIG, "category": "misp", **config},
    }


def report(result):
    assert "error" not in result, result
    obj = result["results"]["Object"][0]
    assert obj["name"] == "annotation" and obj["ObjectReference"][0]["referenced_uuid"] == UUID
    assert obj["Attribute"][0]["to_ids"] is False and obj["Attribute"][0]["disable_correlation"] is True
    event = MISPEvent()
    event.from_dict(info="Synthetic Shuffle lookup", **copy.deepcopy(result["results"]))
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
        ("text", 'quote"&key=other'),
        ("vulnerability", "CVE-2026-12345"),
    ],
)
def test_literal_key_prefix_source_preservation_and_safe_metadata(api, kind, value):
    request = query(kind, value, key_prefix="misp:")
    original = copy.deepcopy(request)
    result = module.handler(json.dumps(request))
    data = report(result)
    assert request == original and result["results"]["Attribute"] == [original["attribute"]]
    assert data["key"] == "misp:" + value and data["org_id"] == ORG_ID and data["status"] == "found"
    assert data["record"]["value"]["active"] is False and data["record"]["value"]["score"] == 0
    assert data["record"]["changed"] is False and data["record"]["encrypted"] is False
    assert json.loads(api.calls[0][0].body) == {"org_id": ORG_ID, "key": "misp:" + value, "category": "misp"}
    assert len(api.calls) == 1
    for secret in (DATASTORE_SECRET, EXECUTION_SECRET, EXECUTION_ID, CONFIG["api_key"]):
        assert secret not in json.dumps(result)


@pytest.mark.parametrize("value", [False, 0, None, "", "1234", [], {"active": False, "count": 0}])
def test_native_record_values_are_preserved_without_interpretation(api, value):
    api.replies["get_cache"] = {"success": True, "key": "example.org", "category": "misp", "value": value}
    assert report(module.handler(json.dumps(query())))["record"]["value"] == value


@pytest.mark.parametrize("requested,returned", [("", ""), ("default", ""), ("", "default"), ("default", "default")])
def test_default_category_alias(api, requested, returned):
    api.replies["get_cache"] = {"success": True, "key": "example.org", "category": returned, "value": "value"}
    assert report(module.handler(json.dumps(query(category=requested))))["category"] == ""


@pytest.mark.parametrize(
    "body",
    [
        {"success": True, "key": "other.example", "category": "misp", "value": "value"},
        {"success": True, "key": "example.org", "category": "different", "value": "value"},
        {"success": True, "key": "example.org", "value": "value"},
        {"success": True, "key": "example.org", "category": "misp"},
        {"success": True, "key": "example.org", "category": "misp", "value": "value", "org_id": UUID},
        {"success": False, "reason": "Failed authentication or key doesn't exist"},
    ],
)
def test_fallback_mismatch_missing_or_inaccessible_records_are_errors(api, body):
    api.replies["get_cache"] = body
    assert "error" in module.handler(json.dumps(query()))


def test_echoed_matching_organization_is_accepted(api):
    api.replies["get_cache"] = {
        "success": True,
        "key": "example.org",
        "category": "misp",
        "value": "value",
        "org_id": ORG_ID,
    }
    assert report(module.handler(json.dumps(query())))["status"] == "found"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429])
def test_missing_and_permission_http_errors_never_mean_no_match(api, status):
    api.replies["get_cache"] = (status, {"success": False, "reason": "Failed authentication or key doesn't exist"})
    result = module.handler(json.dumps(query()))
    assert "error" in result and str(status) in result["error"] and len(api.calls) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("uuid", "bad"),
        ("type", "attachment"),
        ("value", ""),
        ("value", []),
        ("value", "x" * 1025),
        ("value", "\ud800"),
        ("value", " example.org"),
        ("value", "example.org\n"),
    ],
)
def test_invalid_source_makes_no_request(api, field, value):
    request = query()
    request["attribute"][field] = value
    assert "error" in module.handler(json.dumps(request)) and not api.calls


@pytest.mark.parametrize(
    "config",
    [
        {"category": None},
        {"category": "bad\n"},
        {"category": "x" * 129},
        {"key_prefix": []},
        {"key_prefix": "x" * 129},
        {"org_id": "bad"},
        {"timeout": 0},
    ],
)
def test_invalid_config_makes_no_request(api, config):
    assert "error" in module.handler(json.dumps(query(**config))) and not api.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(api, raw):
    assert "error" in module.handler(raw) and not api.calls


def test_discovery_contract():
    assert module.handler(False) is False and module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig


class TestShuffleLookupHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {"shuffle_datastore_lookup": module, "type:shuffle_datastore_lookup": "expansion"}
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "shuffle_datastore_lookup"
        fake = FakeAPI()
        with patch.object(
            requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
        ):
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": "shuffle_datastore_lookup", **query()}),
            )
        assert response.code == 200 and report(json.loads(response.body))["status"] == "found"
