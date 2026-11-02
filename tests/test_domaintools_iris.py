import json
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.lib import domaintools_iris as shared
from misp_modules.modules.expansion import domaintools_iris_enrich as enrich
from misp_modules.modules.expansion import domaintools_iris_investigate as investigate
from misp_modules.modules.expansion import domaintools_iris_pivot as pivot

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-api-secret"


def query(kind="domain", value="example.com", **config):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source"},
            "config": {"username": "analyst", "api_key": SECRET, **config},
        }
    )


def reply(rows=None, status=200, **metadata):
    return Mock(status_code=status, json=Mock(return_value={"response": {"results": rows or [], **metadata}}))


def sample():
    return {
        "domain": "example.com",
        "active": False,
        "domain_risk": {"risk_score": 0, "components": []},
        "create_date": {"value": "2020-01-01", "count": 1000},
        "registrar": {"value": "Registrar", "count": 301},
        "registrant_contact": {"name": {"value": "Example"}, "email": [{"value": "a@example.com", "count": 2}]},
        "ip": [{"address": {"value": "192.0.2.1", "count": 2}}],
        "name_server": [{"host": {"value": "ns.example.com", "count": 3}, "ip": [{"value": "192.0.2.2"}]}],
        "mx": [{"host": {"value": "mail.example.com"}, "ip": []}],
        "ssl_info": [{"hash": {"value": "a" * 40}}],
    }


def objects(result, name):
    return [o for o in result["results"]["Object"] if o["name"] == name]


def test_enrich_maps_reference_response_and_preserves_source_and_zero():
    with patch.object(shared.requests, "post", return_value=reply([sample()])) as call:
        result = enrich.handler(query())
    assert "results" in result, result
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == UUID and source["to_ids"] is True and source["comment"] == "source"
    assert call.call_args.args[0] == "https://api.domaintools.com/v1/iris-enrich/"
    assert call.call_args.kwargs["data"] == {"api_username": "analyst", "api_key": SECRET, "domain": "example.com"}
    assert call.call_args.kwargs["timeout"] == (5, 30)
    assert call.call_args.kwargs["verify"] is True
    assert call.call_args.kwargs["allow_redirects"] is False
    record = json.loads(objects(result, "annotation")[0]["Attribute"][0]["value"])
    assert record["active"] is False and record["domain_risk"]["risk_score"] == 0
    assert objects(result, "whois") and len(objects(result, "domain-ip")) == 3
    for obj in result["results"]["Object"]:
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])
        assert all(a["to_ids"] is False for a in obj["Attribute"])


@pytest.mark.parametrize(
    "kind,field,value",
    [
        ("domain", "domain", "example.com"),
        ("hostname", "nameserver_host", "ns.example.com"),
        ("ip-src", "ip", "192.0.2.1"),
        ("ip-dst", "ip", "192.0.2.1"),
        ("email-src", "email", "a@example.com"),
        ("email-dst", "email", "a@example.com"),
        ("whois-registrant-email", "email", "a@example.com"),
        ("whois-registrar", "registrar", "Registrar"),
        ("whois-registrant-name", "registrant", "Example"),
        ("x509-fingerprint-sha1", "ssl_hash", "a" * 40),
    ],
)
def test_pivot_filters_match_provider_reference(kind, field, value):
    with patch.object(shared.requests, "post", return_value=reply([sample()])) as call:
        result = pivot.handler(query(kind, value))
    assert "results" in result, result
    assert call.call_args.args[0].endswith("/iris-investigate/")
    assert call.call_args.kwargs["data"][field] == value
    assert call.call_args.kwargs["data"]["page_size"] == 100


def test_guided_pivot_counts_and_certificate_mapping():
    with patch.object(shared.requests, "post", return_value=reply([sample()])):
        result = pivot.handler(query(guided_pivot_threshold=3))
    whois = objects(result, "whois")[0]
    email = next(a for a in whois["Attribute"] if a["object_relation"] == "registrant-email")
    assert "2 domains" in email["comment"]
    assert {"name": "Guided Pivot"} in email["Tag"]
    registrar = next(a for a in whois["Attribute"] if a["object_relation"] == "registrar")
    assert not registrar.get("Tag")
    assert objects(result, "x509")[0]["Attribute"][0]["value"] == "a" * 40


def test_result_limit_and_pagination_metadata():
    with patch.object(
        shared.requests,
        "post",
        return_value=reply([sample(), {"domain": "other.example"}], total_count=9, position="next-page"),
    ) as call:
        result = investigate.handler(query(results_limit=1))
    assert call.call_count == 1
    assert call.call_args.kwargs["data"]["page_size"] == 1
    assert len(objects(result, "whois")) == 1
    metadata = json.loads(objects(result, "annotation")[-1]["Attribute"][0]["value"])
    assert metadata["total_count"] == 9 and metadata["position"] == "next-page"
    assert metadata["imported_results"] == 1


@pytest.mark.parametrize("module", [enrich, investigate, pivot])
def test_discovery_and_empty_results(module):
    assert module.handler(False) is False
    assert module.version()["config"] == module.moduleconfig
    assert module.introspection()["format"] == "misp_standard"
    with patch.object(shared.requests, "post", return_value=reply()):
        result = module.handler(query())
    assert not result["results"]["Object"]


@pytest.mark.parametrize("raw", ["{", "[]", "{}", "null", '{"attribute": []}'])
def test_invalid_requests_never_call_provider(raw):
    with patch.object(shared.requests, "post") as call:
        assert "error" in enrich.handler(raw)
    call.assert_not_called()


@pytest.mark.parametrize("config", [{"api_key": ""}, {"username": ""}, {"results_limit": 0}, {"results_limit": 101}])
def test_invalid_config_never_calls_provider(config):
    with patch.object(shared.requests, "post") as call:
        assert "error" in enrich.handler(query(**config))
    call.assert_not_called()


@pytest.mark.parametrize("status", [301, 401, 403, 429, 503])
def test_http_errors_do_not_echo_credentials(status):
    with patch.object(shared.requests, "post", return_value=reply(status=status)):
        result = enrich.handler(query())
    assert str(status) in result["error"] and SECRET not in str(result)


def test_timeout_and_provider_error_are_sanitized():
    with patch.object(shared.requests, "post", side_effect=requests.Timeout(SECRET)):
        assert SECRET not in str(enrich.handler(query()))
    response = Mock(status_code=200, json=Mock(return_value={"response": {"error": {"message": SECRET}}}))
    with patch.object(shared.requests, "post", return_value=response):
        result = enrich.handler(query())
    assert "error" in result and SECRET not in str(result)


def test_non_domain_input_requires_pivot_module():
    with patch.object(shared.requests, "post") as call:
        assert "error" in investigate.handler(query("hostname", "ns.example.com"))
    call.assert_not_called()
