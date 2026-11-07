import copy
import json
from unittest.mock import patch

import pytest
import requests
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.expansion import torq_observable_lookup as module
from tests.test_torq_client import CONFIG, FakeAPI

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
PATH = "/public/v1alpha/observables/query"


def query(kind="domain", value="example.org", **config):
    return {
        "attribute": {"uuid": UUID, "type": kind, "value": value, "to_ids": True, "comment": "original"},
        "config": {**CONFIG, **config},
    }


def report(result):
    assert "error" not in result, result
    obj = result["results"]["Object"][0]
    assert obj["name"] == "annotation" and obj["ObjectReference"][0]["referenced_uuid"] == UUID
    assert obj["Attribute"][0]["to_ids"] is False and obj["Attribute"][0]["disable_correlation"] is True
    event = MISPEvent()
    event.from_dict(info="Synthetic Torq lookup", **copy.deepcopy(result["results"]))
    return json.loads(obj["Attribute"][0]["value"])


@pytest.fixture
def api():
    fake = FakeAPI()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


@pytest.mark.parametrize(
    "kind,value,normalized",
    [
        ("domain", "Faß.DE.", "xn--fa-hia.de"),
        ("hostname", "HOST", "host"),
        ("ip-src", "2001:0db8::1", "2001:db8::1"),
        ("ip-dst", "192.0.2.1", "192.0.2.1"),
        ("md5", "A" * 32, "a" * 32),
        ("sha1", "B" * 40, "b" * 40),
        ("sha256", "C" * 64, "c" * 64),
        ("email-src", "User@example.org", "User@example.org"),
        ("url", "https://example.org/Case?q=One", "https://example.org/Case?q=One"),
        ("filename", 'quote".exe', 'quote".exe'),
    ],
)
def test_documented_type_filter_normalization_source_preservation_and_intelligence(api, kind, value, normalized):
    request = query(kind, value, limit="3")
    original = copy.deepcopy(request)
    result = module.handler(json.dumps(request))
    data = report(result)
    assert request == original and result["results"]["Attribute"] == [original["attribute"]]
    body = json.loads(api.calls[1][0].body)
    assert body == {
        "filter": {"types": [{"id": module.TYPE_MAP[kind][0]}], "search": normalized},
        "page_size": 3,
        "order": "desc",
        "order_by": "last_seen",
    }
    assert data["query"] == normalized and data["status"] == "found" and not data["truncated"]
    assert data["matches"][0]["enrichment"]["known"] is False
    assert (
        data["matches"][0]["associated_cases_count"] == 0
        and data["matches"][0]["threat_intel"]["detection"]["detected_count"] == 0
    )
    assert len(api.calls) == 2


def row(value="example.org", **updates):
    return {"id": 28, "type": {"id": "TYPE_ID_HOSTNAME"}, "value": {"hostname": value}, **updates}


@pytest.mark.parametrize("cursor", [None, "", "opaque-token"])
def test_broad_search_never_promotes_partial_matches_or_claims_complete_absence(api, cursor):
    api.replies[PATH] = {"observables": [row("sub.example.org")], "next_page_token": cursor}
    result = module.handler(json.dumps(query()))
    data = report(result)
    assert data["matches"] == [] and data["discarded"] == 1
    assert data["status"] == ("inconclusive" if cursor else "not_found") and data["truncated"] == bool(cursor)
    assert bool(result.get("warnings")) == bool(cursor)


def test_empty_result_is_not_a_benign_verdict(api):
    api.replies[PATH] = {"observables": []}
    data = report(module.handler(json.dumps(query())))
    assert data["status"] == "not_found" and data["candidates"] == 0


def test_truncated_exact_match_and_provider_urls_are_not_followed(api):
    api.replies[PATH] = {
        "observables": [row(enrichment={"href": "https://unexpected.example/artifact"})],
        "next_page_token": "https://unexpected.example/page",
    }
    result = module.handler(json.dumps(query()))
    assert (
        report(result)["status"] == "found"
        and report(result)["truncated"]
        and result["warnings"]
        and len(api.calls) == 2
    )


def test_deleted_observable_is_not_current_evidence(api):
    api.replies[PATH] = {"observables": [row(deleted_at="2026-01-01T00:00:00Z")]}
    assert report(module.handler(json.dumps(query())))["matches"] == []


@pytest.mark.parametrize(
    "kind,value,type_id,field,returned",
    [
        ("ip-src", "2001:db8::1", "TYPE_ID_IP_ADDRESS", "ip", "2001:0DB8:0:0:0:0:0:1"),
        ("sha256", "a" * 64, "TYPE_ID_FILE_HASH", "file_hash", "A" * 64),
        ("domain", "faß.de", "TYPE_ID_HOSTNAME", "hostname", "FAß.DE."),
    ],
)
def test_equivalent_typed_values_are_verified_locally(api, kind, value, type_id, field, returned):
    api.replies[PATH] = {"observables": [{"id": 28, "type": {"id": type_id}, "value": {field: returned}}]}
    assert report(module.handler(json.dumps(query(kind, value))))["status"] == "found"


def test_idna2008_does_not_conflate_sharp_s_with_ss(api):
    api.replies[PATH] = {"observables": [row("fass.de")]}
    assert report(module.handler(json.dumps(query("domain", "faß.de"))))["matches"] == []


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"observables": None},
        {"observables": [None]},
        {"observables": [row(id=True)]},
        {"observables": [row(), row()]},
        {"observables": [row(type={})]},
        {"observables": [row(value={})]},
        {"observables": [row(value={"hostname": False})]},
        {"observables": [], "next_page_token": True},
        {"observables": [], "next_page_token": "more"},
    ],
)
def test_malformed_mismatched_and_incomplete_pages_are_errors(api, body):
    api.replies[PATH] = body
    assert "error" in module.handler(json.dumps(query()))


def test_excess_result_count_is_rejected(api):
    api.replies[PATH] = {"observables": [row(), row(id=29)]}
    assert "error" in module.handler(json.dumps(query(limit="1")))


@pytest.mark.parametrize(
    "kind,value",
    [
        ("sha512", "a" * 128),
        ("md5", "bad"),
        ("ip-src", "192.0.2.1/24"),
        ("ip-src", "fe80::1%eth0"),
        ("domain", "bad domain"),
        ("domain", ""),
        ("url", "\ud800"),
        ("filename", []),
    ],
)
def test_invalid_observable_makes_no_request(api, kind, value):
    assert "error" in module.handler(json.dumps(query(kind, value))) and not api.calls


@pytest.mark.parametrize(
    "config", [{"limit": 0}, {"limit": 101}, {"timeout": True}, {"region": "invalid"}, {"client_secret": ""}]
)
def test_invalid_configuration_makes_no_request(api, config):
    assert "error" in module.handler(json.dumps(query(**config))) and not api.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(api, raw):
    assert "error" in module.handler(raw) and not api.calls


def test_discovery_contract():
    assert module.handler(False) is False and module.introspection()["format"] == "misp_standard"
    assert module.version()["config"] == module.moduleconfig


class TestTorqLookupHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"torq_observable_lookup": module, "type:torq_observable_lookup": "expansion"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "torq_observable_lookup"
        fake = FakeAPI()
        with patch.object(
            requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
        ):
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": "torq_observable_lookup", **query()}),
            )
        assert response.code == 200 and report(json.loads(response.body))["status"] == "found"
