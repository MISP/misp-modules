import json
from pathlib import Path
from unittest.mock import patch

import dns.exception
import dns.resolver
import dns.rrset
import pytest

import misp_modules
from misp_modules.modules.expansion import spamcop

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


def _query(value="1.2.3.4", type_="ip-src", config=None):
    return json.dumps({"attribute": {"type": type_, "value": value, "uuid": UUID}, "config": config})


@pytest.mark.parametrize("type_", ["ip-src", "ip-dst"])
def test_listing_queries_reversed_ipv4_and_returns_linked_reputation(type_):
    with patch.object(spamcop.dns.resolver, "Resolver") as factory:
        resolver = factory.return_value
        resolver.resolve.return_value = dns.rrset.from_text("4.3.2.1.bl.spamcop.net.", 60, "IN", "A", "127.0.0.2")
        result = spamcop.handler(_query(type_=type_, config={"timeout": "2.5"}))

    resolver.resolve.assert_called_once_with("4.3.2.1.bl.spamcop.net", "A")
    assert resolver.timeout == resolver.lifetime == 2.5
    (attribute,) = result["results"]["Attribute"]
    assert (attribute["uuid"], attribute["type"], attribute["value"]) == (UUID, type_, "1.2.3.4")
    (obj,) = result["results"]["Object"]
    assert obj["name"] == "reputation"
    values = {a["object_relation"]: a["value"] for a in obj["Attribute"]}
    assert values["classification"] == "suspicious"
    assert values["source"] == "SpamCop"
    assert values["list-name"] == "bl.spamcop.net"
    assert values["link"] == "https://www.spamcop.net/bl.shtml?1.2.3.4"
    assert "127.0.0.2" in values["text"]
    (reference,) = obj["ObjectReference"]
    assert (reference["referenced_uuid"], reference["relationship_type"]) == (UUID, "related-to")


def test_nxdomain_reports_not_listed_without_a_benign_verdict():
    with patch.object(spamcop.dns.resolver, "Resolver") as factory:
        factory.return_value.resolve.side_effect = dns.resolver.NXDOMAIN
        result = spamcop.handler(_query())
    assert result == {"error": "1.2.3.4 is not listed on bl.spamcop.net."}


@pytest.mark.parametrize("error", [dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer])
def test_dns_failures_do_not_claim_the_ip_is_unlisted(error):
    with patch.object(spamcop.dns.resolver, "Resolver") as factory:
        factory.return_value.resolve.side_effect = error
        result = spamcop.handler(_query())
    assert result["error"].startswith("Unable to query bl.spamcop.net:")
    assert "results" not in result


def test_resolver_initialization_failure_returns_an_error():
    with patch.object(spamcop.dns.resolver, "Resolver", side_effect=dns.resolver.NoResolverConfiguration):
        result = spamcop.handler(_query())
    assert result["error"].startswith("Unable to query bl.spamcop.net:")


@pytest.mark.parametrize("codes", [[], ["127.0.0.3"], ["203.0.113.10"], ["127.0.0.2", "127.0.0.3"]])
def test_unexpected_responses_never_produce_a_listing(codes):
    with patch.object(spamcop.dns.resolver, "Resolver") as factory:
        factory.return_value.resolve.return_value = codes
        result = spamcop.handler(_query())
    assert "unexpected A response" in result["error"]
    assert "results" not in result


@pytest.mark.parametrize("value", ["", "example.com", "1.2.3.4/24", "1.2.3.4.bl.spamcop.net", "999.2.3.4", "::1", 1234])
def test_invalid_and_ipv6_inputs_do_not_query_dns(value):
    with patch.object(spamcop.dns.resolver, "Resolver") as factory:
        result = spamcop.handler(_query(value=value))
    assert "error" in result
    factory.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "null",
        "[]",
        "{}",
        '{"attribute": []}',
        '{"attribute": {"type": "ip-src", "value": "1.2.3.4"}}',
        _query(type_="domain"),
    ],
)
def test_malformed_requests_do_not_query_dns(payload):
    with patch.object(spamcop.dns.resolver, "Resolver") as factory:
        assert "error" in spamcop.handler(payload)
    factory.assert_not_called()


@pytest.mark.parametrize("timeout", ["bad", -1, 0, "nan", "inf", [], {}])
def test_invalid_timeouts_do_not_query_dns(timeout):
    with patch.object(spamcop.dns.resolver, "Resolver") as factory:
        assert "timeout" in spamcop.handler(_query(config={"timeout": timeout}))["error"]
    factory.assert_not_called()


@pytest.mark.parametrize("config", [None, {}, {"timeout": ""}])
def test_missing_and_blank_timeouts_use_the_default(config):
    with patch.object(spamcop.dns.resolver, "Resolver") as factory:
        factory.return_value.resolve.side_effect = dns.resolver.NXDOMAIN
        spamcop.handler(_query(config=config))
    assert factory.return_value.timeout == factory.return_value.lifetime == 5.0


@pytest.mark.parametrize("config", [[], "invalid", 1])
def test_invalid_config_does_not_query_dns(config):
    with patch.object(spamcop.dns.resolver, "Resolver") as factory:
        assert "config" in spamcop.handler(_query(config=config))["error"]
    factory.assert_not_called()


def test_metadata_and_module_discovery():
    assert spamcop.handler() is False
    assert spamcop.introspection() == {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
    assert spamcop.version()["config"] == ["timeout"]
    modules = misp_modules.iterate_modules(Path(misp_modules.__file__).parent / "modules")
    assert any(kind.name == "expansion" and module.name == "spamcop.py" for kind, module in modules)
