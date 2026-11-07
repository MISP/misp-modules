import json
from unittest.mock import patch

import pytest
import requests
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.expansion import cortex_xdr_ioc_lookup as module
from tests.test_cortex_xdr_client import CONFIG, DIGEST, FakeAPI

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"


def query(kind="sha256", value=DIGEST, **config):
    return {
        "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "original"},
        "config": {**CONFIG, **config},
    }


def report(result):
    assert "error" not in result, result
    obj = result["results"]["Object"][0]
    assert obj["name"] == "annotation" and obj["ObjectReference"][0]["referenced_uuid"] == UUID
    assert obj["Attribute"][0]["to_ids"] is False and obj["Attribute"][0]["disable_correlation"] is True
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
        ("sha256", DIGEST.upper(), DIGEST),
        ("md5", "a" * 32, "a" * 32),
        ("domain", "faß.de", "xn--fa-hia.de"),
        ("ip-dst", "2001:0db8::1", "2001:db8::1"),
    ],
)
def test_lookup_preserves_source_and_native_indicator_metadata(api, kind, value, normalized):
    request = query(kind, value)
    result = module.handler(json.dumps(request))
    data = report(result)
    assert result["results"]["Attribute"] == [request["attribute"]]
    assert data["indicator"] == normalized and data["status"] == "found" and data["returned"] == 1
    assert data["rules"][0]["rule_id"] == 99 and data["rules"][0]["expiration_date"] == 0
    assert not data["truncated"]
    event = MISPEvent()
    event.from_dict(info="Synthetic XDR lookup", **result["results"])
    assert len(event.objects) == 1 and len(api.calls) == 1


def test_empty_lookup_is_not_found_not_a_benign_verdict(api):
    api.rows = []
    data = report(module.handler(json.dumps(query())))
    assert data["status"] == "not_found" and data["rules"] == []
    assert "reputation" not in data


def test_non_expiring_rule_is_retained_in_lookup_result(api):
    api.rows = [{"rule_id": 1, "type": "hash", "indicator": DIGEST, "expiration_date": -1}]
    result = module.handler(json.dumps(query()))
    assert report(result)["rules"][0]["expiration_date"] == -1
    assert report(result)["status"] == "found"


def test_limit_warning_and_metadata_whitelist(api):
    api.rows = [
        {"rule_id": 1, "type": "hash", "indicator": DIGEST, "comment": "provider context", "debug": CONFIG["api_key"]}
    ]
    result = module.handler(json.dumps(query(limit=1)))
    assert report(result)["truncated"] and result["warnings"]
    assert CONFIG["api_key"] not in json.dumps(result)


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(api, raw):
    assert "error" in module.handler(raw) and not api.calls


@pytest.mark.parametrize(
    "field,value", [("type", "sha1"), ("type", "url"), ("uuid", "bad"), ("value", []), ("value", "bad")]
)
def test_invalid_attribute_prevents_network(api, field, value):
    request = query()
    request["attribute"][field] = value
    assert "error" in module.handler(json.dumps(request)) and not api.calls


def test_discovery():
    assert module.handler(False) is False
    assert module.version()["config"] == module.moduleconfig
    assert module.introspection()["format"] == "misp_standard"


class TestXdrLookupHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"cortex_xdr_ioc_lookup": module, "type:cortex_xdr_ioc_lookup": "expansion"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "cortex_xdr_ioc_lookup"
        fake = FakeAPI()
        with patch.object(
            requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
        ):
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": "cortex_xdr_ioc_lookup", **query()}),
            )
        assert response.code == 200 and report(json.loads(response.body))["status"] == "found"
