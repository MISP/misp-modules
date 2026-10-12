import json
from importlib import metadata
from unittest.mock import patch

import pytest
from dns import exception, rdata, resolver, reversename
from ptrclassify import Classification, Label, LocationCandidate
from pymisp import MISPEvent, MISPObject

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


def _objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def _values(obj, relation):
    return [attribute["value"] for attribute in obj["Attribute"] if attribute["object_relation"] == relation]


def _classification(result, hostname=MOBILE):
    return next(obj for obj in _objects(result, "ptrclassify") if _values(obj, "hostname") == [hostname])


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
    assert _attributes(result) == [source]
    assert not _objects(result, "dns-record")
    classification = _classification(result)
    assert MOBILE_TAGS <= set(_values(classification, "classification"))
    assert _values(classification, "matched") == ["1"]
    assert _values(classification, "location-country") == ["PL"]
    assert all(attribute["to_ids"] is False for attribute in classification["Attribute"])
    assert "not verified geolocation" in classification["description"]
    assert "may be located elsewhere" in " ".join(_values(classification, "location-description"))


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
    assert _attributes(result) == [source]
    dns = _objects(result, "dns-record")[0]
    assert _values(dns, "queried-domain") == [reversename.from_address(address).to_text().rstrip(".")]
    ptr = next(attribute for attribute in dns["Attribute"] if attribute["object_relation"] == "ptr-record")
    assert ptr["value"] == MOBILE
    assert ptr["type"] == "domain"
    assert _tags(ptr) == _tags(source)
    assert ptr["uuid"] != UUID
    assert ptr["to_ids"] is False
    assert _values(_classification(result), "ip") == [address]


def test_all_distinct_ptr_records_are_classified_and_tags_are_scoped_to_each_hostname():
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.return_value = [_answer(MOBILE), _answer(AWS), _answer(MOBILE.upper())]
        result = _run(_request("ip-src", "192.0.2.1"))
    assert MOBILE_TAGS | AWS_TAGS <= _tags(_source(result))
    assert len(_objects(result, "dns-record")) == 1
    dns = _objects(result, "dns-record")[0]
    ptrs = {
        attribute["value"]: attribute for attribute in dns["Attribute"] if attribute["object_relation"] == "ptr-record"
    }
    assert set(ptrs) == {AWS, MOBILE}
    assert MOBILE_TAGS <= _tags(ptrs[MOBILE])
    assert AWS_TAGS <= _tags(ptrs[AWS])
    assert 'ptrclassify:access="mobile"' not in _tags(ptrs[AWS])
    assert 'ptrclassify:provider="amazon-aws"' not in _tags(ptrs[MOBILE])
    assert len(_objects(result, "ptrclassify")) == 2
    assert _values(_classification(result, AWS), "cloud-region") == ["us-east-2"]


@pytest.mark.parametrize(
    ("attribute_type", "value", "hostname", "address"),
    [
        ("ip-src", "188.147.228.101", MOBILE, "188.147.228.101"),
        ("ip-dst", "3.151.166.120", AWS, "3.151.166.120"),
        ("domain|ip", "example.com|188.147.228.101", MOBILE, "188.147.228.101"),
    ],
)
def test_address_context_adds_ip_encoded_tags_and_embedded_ip_hint(attribute_type, value, hostname, address):
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.return_value = [_answer(hostname)]
        result = _run(_request(attribute_type, value))
    assert 'ptrclassify:naming="ip-encoded"' in _tags(_source(result))
    dns = _objects(result, "dns-record")[0]
    ptr = next(attribute for attribute in dns["Attribute"] if attribute["object_relation"] == "ptr-record")
    assert 'ptrclassify:naming="ip-encoded"' in _tags(ptr)
    classification = _classification(result, hostname)
    assert _values(classification, "embedded-ip") == [address]
    encoded_fields = {
        attribute["object_relation"]: attribute["value"]
        for attribute in classification["Attribute"]
        if attribute.get("comment") == 'ptrclassify:naming="ip-encoded"'
    }
    assert encoded_fields["rule-id"] == "naming.ip-encoded"
    assert float(encoded_fields["confidence"]) == 0.99


@pytest.mark.parametrize(
    ("attribute_type", "value"),
    [("hostname", MOBILE), ("ip-src", "192.0.2.1"), ("ip-dst", "2001:db8::1")],
)
def test_embedded_ip_is_not_inferred_without_matching_ipv4_address_context(attribute_type, value):
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.return_value = [_answer(MOBILE)]
        result = _run(_request(attribute_type, value))
    for obj in result["results"]["Object"]:
        for attribute in obj["Attribute"]:
            assert 'ptrclassify:naming="ip-encoded"' not in _tags(attribute)
    for attribute in _attributes(result):
        assert 'ptrclassify:naming="ip-encoded"' not in _tags(attribute)
    assert not _values(_classification(result), "embedded-ip")


@pytest.mark.parametrize("is_ip", [False, True])
def test_no_classification_match_does_not_add_taxonomy_tags(is_ip):
    request = _request("ip-src" if is_ip else "hostname", "192.0.2.1" if is_ip else "unclassified.example.com")
    request["attribute"]["Tag"] = [{"name": "tlp:green"}]
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.return_value = [_answer("unclassified.example.com")]
        result = _run(request)
    assert _tags(_source(result)) == {"tlp:green"}
    if is_ip:
        dns = _objects(result, "dns-record")[0]
        ptr = next(attribute for attribute in dns["Attribute"] if attribute["object_relation"] == "ptr-record")
        assert not _tags(ptr)
    classification = _classification(result, "unclassified.example.com")
    assert _values(classification, "matched") == ["0"]
    assert not _values(classification, "classification")
    assert not _values(classification, "confidence")


def test_repeated_fields_preserve_label_and_location_associations():
    classified = Classification(
        input="host.example.com",
        hostname="host.example.com",
        labels=[
            Label("access", "mobile", 0.12, ("mobile", "umts"), ("access.mobile", "isp.mobile")),
            Label("hosting", "cloud", 0.98, ("cloud",), ("hosting.cloud",)),
        ],
        locations=[
            LocationCandidate("pop1", 0.6, ".pop1.", "location.provider", city="First City", country="US"),
            LocationCandidate("us", 0.65, ".us", "location.country-code-tld", country="US"),
        ],
        hints={"cloud_region": "region-1", "conflicts": ["allocation:dynamic vs allocation:static"]},
    )
    with patch.object(ptrclassify, "_classifier") as classifier:
        classifier.return_value.classify.return_value = classified
        result = _run(_request("hostname", classified.hostname))
    assert len(_objects(result, "ptrclassify")) == 1
    obj = _classification(result, classified.hostname)
    for label in classified.labels:
        group = [attribute for attribute in obj["Attribute"] if attribute.get("comment") == label.value]
        assert [float(a["value"]) for a in group if a["object_relation"] == "confidence"] == [label.confidence]
        assert {a["value"] for a in group if a["object_relation"] == "evidence"} == set(label.evidence)
        assert {a["value"] for a in group if a["object_relation"] == "rule-id"} == set(label.rule_ids)
        assert [a["value"] for a in group if a["object_relation"] == "category"] == [label.category]
        assert [a["value"] for a in group if a["object_relation"] == "label"] == [label.label]
    for location in classified.locations:
        group = [a for a in obj["Attribute"] if a.get("comment") == f"{location.rule_id}:{location.code}"]
        assert [float(a["value"]) for a in group if a["object_relation"] == "location-confidence"] == [
            location.confidence
        ]
        assert [a["value"] for a in group if a["object_relation"] == "location-evidence"] == [location.evidence]
        assert [a["value"] for a in group if a["object_relation"] == "location-country"] == [location.country]
    assert _values(obj, "cloud-region") == ["region-1"]
    assert _values(obj, "conflict") == ["allocation:dynamic vs allocation:static"]


@pytest.mark.parametrize("attribute_type", ["hostname", "ip-src"])
def test_objects_have_valid_templates_references_and_safe_detection_flags(attribute_type):
    value = MOBILE if attribute_type == "hostname" else "188.147.228.101"
    with patch.object(ptrclassify.resolver, "Resolver") as dns_resolver:
        dns_resolver.return_value.resolve.return_value = [_answer(MOBILE)]
        result = _run(_request(attribute_type, value, to_ids=True))
    obj = _classification(result)
    assert obj["template_uuid"] == ptrclassify._object_template()["uuid"]
    assert obj["template_version"] == "1"
    assert obj["meta-category"] == "network"
    assert _values(obj, "classifier-version") == [metadata.version("ptrclassify")]
    assert _source(result)["to_ids"] is True
    assert {a["uuid"] for a in _attributes(result)} == {UUID}
    targets = {UUID} | {o["uuid"] for o in result["results"]["Object"]}
    for output in result["results"]["Object"]:
        assert all(attribute["to_ids"] is False for attribute in output["Attribute"])
        assert all(reference["referenced_uuid"] in targets for reference in output.get("ObjectReference", []))
        template = ptrclassify._object_template() if output["name"] == "ptrclassify" else None
        restored = MISPObject(output["name"], strict=True, misp_objects_template_custom=template)
        restored.from_dict(**output)
        assert restored._validate()
        assert all(a["object_relation"] in restored._definition["attributes"] for a in output["Attribute"])
    references = {(r["referenced_uuid"], r["relationship_type"]) for r in obj["ObjectReference"]}
    assert (UUID, "characterizes") in references
    if attribute_type == "ip-src":
        dns = _objects(result, "dns-record")[0]
        assert (dns["uuid"], "derived-from") in references
        assert _values(dns, "ptr-record") == [MOBILE]
        assert not _values(dns, "a-record") and not _values(dns, "aaaa-record")
        assert {(r["referenced_uuid"], r["relationship_type"]) for r in dns["ObjectReference"]} == {
            (UUID, "related-to")
        }
    else:
        assert len(references) == 1
    event = MISPEvent()
    event.from_dict(info="PTR classification enrichment", **result["results"])
    assert len(event.objects) == len(result["results"]["Object"])


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
