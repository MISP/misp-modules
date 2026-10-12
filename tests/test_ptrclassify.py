import json
from unittest.mock import patch

import pytest
from dns import exception, rdata, resolver, reversename

from misp_modules.modules.expansion import ptrclassify

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
MOBILE = "188.147.228.101.nat.umts.dynamic.t-mobile.pl"
AWS = "ec2-3-151-166-120.us-east-2.compute.amazonaws.com"
MOBILE_TAGS = {
    'ptrclassify:allocation="dynamic"',
    'ptrclassify:access="mobile"',
    'ptrclassify:translation="nat"',
}
AWS_TAGS = {'ptrclassify:provider="amazon-aws"', 'ptrclassify:hosting="cloud"'}


def _request(attribute_type="hostname", value=MOBILE, **fields):
    return {
        "module": "ptrclassify",
        "attribute": {"type": attribute_type, "value": value, "uuid": UUID, **fields},
        "config": {},
    }


def _run(request):
    return ptrclassify.handler(json.dumps(request))


def _attributes(result):
    assert "error" not in result, result
    return result["results"]["Attribute"]


def _source(result):
    return next(attribute for attribute in _attributes(result) if attribute["uuid"] == UUID)


def _tags(attribute):
    return {tag["name"] for tag in attribute.get("Tag", [])}


def _answer(hostname):
    return rdata.from_text("IN", "PTR", hostname + ".")


@pytest.mark.parametrize("attribute_type", ["hostname", "domain"])
def test_hostname_is_classified_locally_and_tags_the_queried_attribute(attribute_type):
    request = _request(
        attribute_type,
        MOBILE.upper() + ".",
        comment="Keep my comment",
        to_ids=True,
        Tag=[{"name": "tlp:amber"}, {"name": 'ptrclassify:access="mobile"'}],
    )
    original = json.dumps(request)
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        result = _run(request)
    dns_resolver.assert_not_called()
    source = _source(result)
    assert MOBILE_TAGS | {"tlp:amber"} <= _tags(source)
    assert source["uuid"] == UUID
    assert source["value"] == MOBILE.upper() + "."
    assert source["comment"] == "Keep my comment"
    assert source["to_ids"] is True
    assert len(source["Tag"]) == len(_tags(source))
    assert json.dumps(request) == original
    summaries = [attribute for attribute in _attributes(result) if attribute["type"] == "text"]
    assert len(summaries) == 1
    text = summaries[0]["value"]
    assert MOBILE in text
    assert 'ptrclassify:access="mobile"' in text
    assert "confidence:" in text and "evidence:" in text and "rules:" in text
    assert "Potential location:" in text and "PL" in text
    assert "not verified geolocation" in text
    assert summaries[0]["to_ids"] is False


@pytest.mark.parametrize(
    ("attribute_type", "value", "address"),
    [
        ("ip-src", "188.147.228.101", "188.147.228.101"),
        ("ip-dst", "2001:db8::1", "2001:db8::1"),
        ("domain|ip", "example.com|188.147.228.101", "188.147.228.101"),
        ("domain|ip", "example.com|2001:db8::1", "2001:db8::1"),
    ],
)
def test_ip_reverse_lookup_returns_tagged_ptr_and_preserves_source(attribute_type, value, address):
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.return_value = [_answer(MOBILE)]
        result = _run(_request(attribute_type, value))
    dns_resolver.return_value.resolve.assert_called_once_with(reversename.from_address(address), "PTR")
    assert dns_resolver.return_value.timeout == 2
    assert dns_resolver.return_value.lifetime == 5
    source = _source(result)
    assert source["value"] == value and source["type"] == attribute_type
    assert MOBILE_TAGS <= _tags(source)
    ptr = next(attribute for attribute in _attributes(result) if attribute["type"] == "hostname")
    assert ptr["value"] == MOBILE
    assert _tags(ptr) == _tags(source)
    assert ptr["uuid"] != UUID
    assert ptr["to_ids"] is False
    assert address in ptr["comment"]


def test_all_distinct_ptr_records_are_classified_and_tags_are_scoped_to_each_hostname():
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.return_value = [_answer(MOBILE), _answer(AWS), _answer(MOBILE.upper())]
        result = _run(_request("ip-src", "192.0.2.1"))
    assert MOBILE_TAGS | AWS_TAGS <= _tags(_source(result))
    ptrs = {attribute["value"]: attribute for attribute in _attributes(result) if attribute["type"] == "hostname"}
    assert set(ptrs) == {AWS, MOBILE}
    assert MOBILE_TAGS <= _tags(ptrs[MOBILE])
    assert AWS_TAGS <= _tags(ptrs[AWS])
    assert 'ptrclassify:access="mobile"' not in _tags(ptrs[AWS])
    assert 'ptrclassify:provider="amazon-aws"' not in _tags(ptrs[MOBILE])
    text = "\n".join(attribute["value"] for attribute in _attributes(result) if attribute["type"] == "text")
    assert "us-east-2" in text


@pytest.mark.parametrize("is_ip", [False, True])
def test_no_classification_match_does_not_add_taxonomy_tags(is_ip):
    request = _request("ip-src" if is_ip else "hostname", "192.0.2.1" if is_ip else "unclassified.example.com")
    request["attribute"]["Tag"] = [{"name": "tlp:green"}]
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.return_value = [_answer("unclassified.example.com")]
        result = _run(request)
    assert _tags(_source(result)) == {"tlp:green"}
    if is_ip:
        ptr = next(attribute for attribute in _attributes(result) if attribute["type"] == "hostname")
        assert not _tags(ptr)
    text = next(attribute["value"] for attribute in _attributes(result) if attribute["type"] == "text")
    assert "No classification labels matched" in text


def test_custom_nameserver_is_used():
    request = _request("ip-src", "192.0.2.1")
    request["config"]["nameserver"] = "2001:db8::53"
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.return_value = [_answer(AWS)]
        result = _run(request)
    assert dns_resolver.return_value.nameservers == ["2001:db8::53"]
    assert AWS_TAGS <= _tags(_source(result))


def test_invalid_nameserver_does_not_issue_a_dns_query():
    request = _request("ip-src", "192.0.2.1")
    request["config"]["nameserver"] = "not-a-server"
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        result = _run(request)
    assert "nameserver" in result["error"]
    dns_resolver.return_value.resolve.assert_not_called()


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (resolver.NXDOMAIN(), "No PTR record"),
        (resolver.NoAnswer(), "No PTR record"),
        (exception.Timeout(), "timed out"),
        (resolver.NoNameservers(), "lookup failed"),
    ],
)
def test_dns_failures_are_reported_without_tagged_results(failure, expected):
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.side_effect = failure
        result = _run(_request("ip-dst", "192.0.2.1"))
    assert expected in result["error"]
    assert "results" not in result


def test_empty_ptr_answer_is_reported():
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.return_value = []
        result = _run(_request("ip-dst", "192.0.2.1"))
    assert "No PTR record" in result["error"]


@pytest.mark.parametrize(
    ("attribute_type", "value"),
    [
        ("ip-src", "not-an-ip"),
        ("ip-dst", "192.0.2.0/24"),
        ("domain|ip", "example.com"),
        ("domain|ip", "|192.0.2.1"),
        ("domain|ip", "example.com|invalid"),
        ("hostname", "https://example.com/path"),
        ("hostname", "a..example.com"),
        ("hostname", "example.com.."),
        ("hostname", "x" * 64 + ".com"),
        ("hostname", "\nIN PTR example.com"),
        ("hostname", ""),
        ("hostname", None),
        ("hostname", 123),
        ("url", "https://example.com"),
    ],
)
def test_invalid_attribute_values_do_not_reach_dns(attribute_type, value):
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        result = _run(_request(attribute_type, value))
    assert "error" in result
    dns_resolver.assert_not_called()


@pytest.mark.parametrize("payload", [{}, {"attribute": {}}, {"attribute": []}, {"attribute": {"type": "hostname"}}, []])
def test_missing_or_invalid_attribute_is_reported(payload):
    assert "error" in _run(payload)


def test_invalid_configuration_is_reported():
    request = _request()
    request["config"] = "invalid"
    assert "configuration" in _run(request)["error"]


def test_invalid_json_is_reported_and_no_request_is_supported():
    assert "error" in ptrclassify.handler("{invalid")
    assert ptrclassify.handler() is False


def test_introspection_and_version_advertise_both_modes_and_configuration():
    assert ptrclassify.introspection()["format"] == "misp_standard"
    assert set(ptrclassify.version()["module-type"]) == {"expansion", "hover"}
    assert ptrclassify.version()["config"] == ["nameserver"]
