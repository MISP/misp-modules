import copy
import json
from unittest.mock import patch

import pytest
import requests
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.expansion import cortex_xsoar_indicator_lookup as module
from tests.test_cortex_xsoar_client import CONFIG, FakeAPI

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"


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
    event.from_dict(info="Synthetic XSOAR lookup", **copy.deepcopy(result["results"]))
    return json.loads(obj["Attribute"][0]["value"])


@pytest.fixture
def api():
    fake = FakeAPI()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


@pytest.mark.parametrize(
    "kind,value,normalized,native",
    [
        ("domain", "Faß.DE.", "xn--fa-hia.de", "Domain"),
        ("ip-src", "2001:0db8::1", "2001:db8::1", "IPv6"),
        ("ip-dst", "192.0.2.1", "192.0.2.1", "IP"),
        ("md5", "A" * 32, "a" * 32, "File"),
        ("sha1", "B" * 40, "b" * 40, "File"),
        ("sha256", "C" * 64, "c" * 64, "File"),
        ("sha512", "D" * 128, "d" * 128, "File"),
        ("url", "https://example.org/Case?q=One", "https://example.org/Case?q=One", "URL"),
        ("email-src", "User@example.org", "User@example.org", "Email"),
        ("vulnerability", "cve-2026-12345", "CVE-2026-12345", "CVE"),
    ],
)
def test_native_identity_normalization_and_source_preservation(api, kind, value, normalized, native):
    api.rows = [
        {
            "id": "indicator-1",
            "value": normalized,
            "indicator_type": native,
            "score": 0,
            "isDetectable": False,
            "expirationStatus": "active",
            "CustomFields": {"known": False},
        }
    ]
    request = query(kind, value, limit="3")
    original = copy.deepcopy(request)
    result = module.handler(json.dumps(request))
    data = report(result)
    assert request == original and result["results"]["Attribute"] == [original["attribute"]]
    assert data["query"] == normalized and data["status"] == "found" and not data["truncated"]
    assert data["matches"][0]["score"] == 0 and data["matches"][0]["isDetectable"] is False
    assert data["matches"][0]["CustomFields"]["known"] is False and len(api.calls) == 1
    body = json.loads(api.calls[0][0].body)
    assert body["size"] == 3 and set(body) == {"query", "size"}
    assert "page" not in body and "request_data" not in body


def test_value_and_type_query_matches_documented_field_names(api):
    assert report(module.handler(json.dumps(query())))["status"] == "found"
    assert json.loads(api.calls[0][0].body) == {"query": 'value:"example.org" AND type:"Domain"', "size": 20}


def test_query_metacharacters_are_escaped_and_cannot_add_clauses(api):
    value = 'https://example.org/" OR *:*'
    api.rows = [{"id": "indicator-1", "value": value, "indicator_type": "URL"}]
    assert report(module.handler(json.dumps(query("url", value))))["status"] == "found"
    assert json.loads(api.calls[0][0].body)["query"] == r'value:"https\:\/\/example.org\/\" OR \*\:\*" AND type:"URL"'


@pytest.mark.parametrize(
    "kind,digest", [("md5", "a" * 32), ("sha1", "b" * 40), ("sha256", "c" * 64), ("sha512", "d" * 128)]
)
def test_merged_file_hash_fields_are_searched_and_verified(api, kind, digest):
    api.rows = [{"id": "file-1", "value": "f" * 64, "indicator_type": "File", "CustomFields": {kind: digest.upper()}}]
    data = report(module.handler(json.dumps(query(kind, digest))))
    assert data["status"] == "found" and data["matches"][0]["matched_fields"] == ["CustomFields." + kind]
    search = json.loads(api.calls[0][0].body)["query"]
    assert " OR " + kind + ':"' + digest + '"' in search


def test_legacy_file_type_is_supported(api):
    api.rows = [{"id": "file-1", "value": "a" * 32, "indicator_type": "File MD5"}]
    assert report(module.handler(json.dumps(query("md5", "a" * 32))))["status"] == "found"


def test_same_hash_in_unrelated_custom_field_does_not_match(api):
    api.rows = [{"id": "file-1", "value": "f" * 64, "indicator_type": "File", "CustomFields": {"comment": "a" * 32}}]
    assert report(module.handler(json.dumps(query("md5", "a" * 32))))["matches"] == []


@pytest.mark.parametrize("total,expected", [(1, "not_found"), (2, "inconclusive")])
def test_broad_candidates_and_truncation_are_not_false_matches_or_absence(api, total, expected):
    api.replies["search"] = {
        "iocObjects": [{"id": "x", "value": "sub.example.org", "indicator_type": "Domain"}],
        "total": total,
    }
    result = module.handler(json.dumps(query()))
    data = report(result)
    assert data["status"] == expected and data["discarded"] == 1 and bool(result.get("warnings")) == (total == 2)


@pytest.mark.parametrize("rows", [[], None])
def test_complete_empty_result_with_go_nulls_is_supported(api, rows):
    api.replies["search"] = {"iocObjects": rows, "total": 0, "accountErrors": None}
    assert report(module.handler(json.dumps(query())))["status"] == "not_found"


def test_expired_indicator_metadata_remains_visible_without_promoting_ids(api):
    api.rows[0]["expirationStatus"] = "expired"
    assert report(module.handler(json.dumps(query())))["matches"][0]["expirationStatus"] == "expired"


def test_multi_account_ids_are_scoped_to_the_account(api):
    api.rows = [{**api.rows[0], "account": "tenant-a"}, {**api.rows[0], "account": "tenant-b"}]
    assert report(module.handler(json.dumps(query())))["returned"] == 2


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"total": 0},
        {"iocObjects": None, "total": 1},
        {"iocObjects": [], "total": True},
        {"iocObjects": [], "total": 0, "accountErrors": ["denied"]},
        {"iocObjects": [], "total": 0, "accountErrors": {}},
        {"iocObjects": [None], "total": 1},
        {"iocObjects": [{"id": True}], "total": 1},
        {"iocObjects": [{"id": "x", "value": "a"}], "total": 1},
    ],
)
def test_malformed_or_partial_account_responses_are_errors(api, body):
    api.replies["search"] = body
    assert "error" in module.handler(json.dumps(query()))


def test_duplicate_and_excess_candidates_are_errors(api):
    api.rows *= 2
    assert "error" in module.handler(json.dumps(query()))
    api.rows[1] = {**api.rows[1], "id": "different"}
    assert "error" in module.handler(json.dumps(query(limit="1")))


@pytest.mark.parametrize(
    "kind,value",
    [
        ("md5", "bad"),
        ("ip-src", "192.0.2.1/24"),
        ("ip-src", "fe80::1%eth0"),
        ("domain", "bad domain"),
        ("url", "\ud800"),
        ("url", "x\n"),
        ("vulnerability", "not-a-CVE"),
        ("text", "example.org"),
    ],
)
def test_invalid_indicator_makes_no_request(api, kind, value):
    assert "error" in module.handler(json.dumps(query(kind, value))) and not api.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(api, raw):
    assert "error" in module.handler(raw) and not api.calls


def test_discovery_contract():
    assert module.handler(False) is False and module.introspection()["format"] == "misp_standard"


class TestXsoarLookupHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {"cortex_xsoar_indicator_lookup": module, "type:cortex_xsoar_indicator_lookup": "expansion"}
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "cortex_xsoar_indicator_lookup"
        fake = FakeAPI()
        with patch.object(
            requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
        ):
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": "cortex_xsoar_indicator_lookup", **query()}),
            )
        assert response.code == 200 and report(json.loads(response.body))["status"] == "found"
