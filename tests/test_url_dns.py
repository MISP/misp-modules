import json
from unittest.mock import MagicMock

import dns.exception
import dns.resolver
import dns.rrset
import pytest
from pymisp import MISPObject

from misp_modules.modules.expansion import url_dns

SOURCE_UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
ORIGIN = "1.1.1.1.origin.asn.cymru.com."
ASN_NAME = "AS13335.asn.cymru.com."


@pytest.fixture
def resolver(monkeypatch):
    resolver = MagicMock()
    monkeypatch.setattr(url_dns.dns.resolver, "Resolver", lambda: resolver)
    return resolver


def _answers(resolver, records):
    def resolve(name, record_type):
        answer = records.get((name, record_type), dns.resolver.NoAnswer())
        if isinstance(answer, Exception):
            raise answer
        return dns.rrset.from_text(name, 60, "IN", record_type, *answer)

    resolver.resolve.side_effect = resolve


def _run(value="https://example.com/path", **extra):
    request = {"attribute": {"type": "url", "value": value, "uuid": SOURCE_UUID}}
    request.update(extra)
    return url_dns.handler(json.dumps(request))


def _objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def _values(obj, relation):
    return [attr["value"] for attr in obj["Attribute"] if attr["object_relation"] == relation]


def _references(obj):
    return {(ref["referenced_uuid"], ref["relationship_type"]) for ref in obj["ObjectReference"]}


def test_dual_stack_asn_and_original_url_links(resolver):
    _answers(
        resolver,
        {
            ("example.com.", "A"): ["1.1.1.1", "1.0.0.1"],
            ("example.com.", "AAAA"): ["2606:4700:4700::1111"],
            (ORIGIN, "TXT"): ['"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"'],
            ("1.0.0.1.origin.asn.cymru.com.", "TXT"): ['"13335 | 1.0.0.0/24 | AU | apnic | 2010-07-14"'],
            (ASN_NAME, "TXT"): ['"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"'],
        },
    )
    result = _run()
    endpoints = _objects(result, "ip-port")
    asns = _objects(result, "asn")
    assert len(endpoints) == 3
    assert len(asns) == 1
    assert _values(asns[0], "asn") == ["AS13335"]
    assert _values(asns[0], "description") == ["CLOUDFLARENET, US"]
    assert set(_values(asns[0], "subnet-announced")) == {"1.1.1.0/24", "1.0.0.0/24"}
    assert (SOURCE_UUID, "related-to") in _references(asns[0])
    assert result["results"]["Attribute"][0]["uuid"] == SOURCE_UUID
    assert result["results"]["Attribute"][0]["value"] == "https://example.com/path"
    for endpoint in endpoints:
        assert _values(endpoint, "dst-port") == ["443"]
        assert _values(endpoint, "protocol") == ["tcp"]
        assert _values(endpoint, "hostname") == ["example.com"]
        assert (SOURCE_UUID, "derived-from") in _references(endpoint)
        if ":" not in _values(endpoint, "ip")[0]:
            assert (asns[0]["uuid"], "belongs-to") in _references(endpoint)
        else:
            assert len(_references(endpoint)) == 1
    for obj in result["results"]["Object"]:
        strict_obj = MISPObject(obj["name"], strict=True)
        strict_obj.from_dict(**obj)
        strict_obj._validate()
        assert all(attr["to_ids"] is False for attr in obj["Attribute"])
    assert resolver.resolve.call_args_list.count(((ASN_NAME, "TXT"),)) == 1


@pytest.mark.parametrize(
    "url,port",
    [
        ("http://example.com", "80"),
        ("https://example.com", "443"),
        ("HTTP://example.com", "80"),
        ("http://example.com:8080/path", "8080"),
        ("https://user:password@example.com:8443/path?q=:9999", "8443"),
        ("ftp://example.com:21/file", "21"),
        ("custom://example.com:65535", "65535"),
        ("https://example.com/path:8443", "443"),
        ("https://example.com?port=:8443", "443"),
    ],
)
def test_port_selection(resolver, url, port):
    _answers(resolver, {("example.com.", "AAAA"): ["2001:db8::1"]})
    endpoint = _objects(_run(url), "ip-port")[0]
    assert _values(endpoint, "dst-port") == [port]


@pytest.mark.parametrize(
    "url",
    [
        "example.com/path",
        "ftp://example.com",
        "http:///path",
        "http://example.com:0",
        "http://example.com:65536",
        "http://example.com:abc",
        "http://example.com:",
        "https://[not-ipv6]/",
        "http://bad host/",
        "http://example.com/\n",
        "http://%65xample.com/",
        "http://[fe80::1%25eth0]/",
        "https://example..com/",
        "https://-example.com/",
        "https://example.com./:bad port",
        "",
        None,
        123,
    ],
)
def test_invalid_urls_do_not_query_dns(resolver, url):
    assert "error" in _run(url)
    resolver.resolve.assert_not_called()


@pytest.mark.parametrize(
    "url,ip,port", [("http://192.168.1.1", "192.168.1.1", "80"), ("https://[2001:db8::1]:8443/", "2001:db8::1", "8443")]
)
def test_ip_literal_skips_forward_dns(resolver, url, ip, port):
    result = _run(url)
    endpoint = _objects(result, "ip-port")[0]
    assert _values(endpoint, "ip") == [ip]
    assert _values(endpoint, "dst-port") == [port]
    assert not _objects(result, "asn")
    resolver.resolve.assert_not_called()


def test_public_ipv4_literal_gets_asn(resolver):
    _answers(resolver, {(ORIGIN, "TXT"): ['"13335 | 1.1.1.0/24"']})
    result = _run("https://1.1.1.1")
    assert len(_objects(result, "asn")) == 1
    assert _objects(result, "asn")[0]["comment"]
    assert all(call.args[1] == "TXT" for call in resolver.resolve.call_args_list)


def test_idna_hostname(resolver):
    _answers(resolver, {("xn--bcher-kva.example.", "AAAA"): ["2001:db8::1"]})
    endpoint = _objects(_run("https://bücher.example./"), "ip-port")[0]
    assert _values(endpoint, "hostname") == ["xn--bcher-kva.example"]


@pytest.mark.parametrize("failure", [dns.exception.Timeout(), dns.resolver.NoNameservers()])
def test_one_family_failure_preserves_other_family(resolver, failure):
    _answers(resolver, {("example.com.", "A"): failure, ("example.com.", "AAAA"): ["2001:db8::1"]})
    endpoint = _objects(_run(), "ip-port")[0]
    assert "A lookup failed" in endpoint["comment"]


@pytest.mark.parametrize("failure", [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer(), dns.exception.Timeout()])
def test_no_addresses_returns_error(resolver, failure):
    _answers(resolver, {("example.com.", "A"): failure, ("example.com.", "AAAA"): failure})
    assert "No IPv4 or IPv6 addresses" in _run()["error"]


@pytest.mark.parametrize("failure", [dns.exception.Timeout(), dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()])
def test_asn_failure_keeps_endpoint(resolver, failure):
    _answers(resolver, {("example.com.", "A"): ["1.1.1.1"], (ORIGIN, "TXT"): failure})
    result = _run()
    assert not _objects(result, "asn")
    assert "ASN lookup unavailable" in _objects(result, "ip-port")[0]["comment"]


def test_multiple_origin_asns_and_split_txt_chunks(resolver):
    _answers(resolver, {(ORIGIN, "TXT"): ['"13335 64500 | " "1.1.1.0/24 | AU | apnic | 2011-08-11"']})
    result = _run("http://1.1.1.1")
    asns = _objects(result, "asn")
    assert {_values(obj, "asn")[0] for obj in asns} == {"AS13335", "AS64500"}
    endpoint = _objects(result, "ip-port")[0]
    assert len(_references(endpoint)) == 3


def test_overlapping_prefixes_do_not_duplicate_asn_references(resolver):
    _answers(resolver, {(ORIGIN, "TXT"): ['"13335 | 1.1.1.0/24"', '"13335 | 1.1.0.0/16"']})
    result = _run("http://1.1.1.1")
    endpoint = _objects(result, "ip-port")[0]
    assert len(endpoint["ObjectReference"]) == 2
    assert len(_objects(result, "asn")) == 1
    assert set(_values(_objects(result, "asn")[0], "subnet-announced")) == {"1.1.1.0/24", "1.1.0.0/16"}


@pytest.mark.parametrize("txt", ["NA | 1.1.1.0/24", "13335 | 2.2.2.0/24", "13335 | not-a-subnet", "oops"])
def test_malformed_asn_records_keep_endpoint(resolver, txt):
    _answers(resolver, {(ORIGIN, "TXT"): [f'"{txt}"']})
    result = _run("http://1.1.1.1")
    assert not _objects(result, "asn")
    assert "ASN lookup unavailable" in _objects(result, "ip-port")[0]["comment"]


def test_private_ipv4_keeps_endpoint_without_asn_query(resolver):
    _answers(resolver, {("example.com.", "A"): ["10.0.0.1"]})
    result = _run()
    assert "not globally routable" in _objects(result, "ip-port")[0]["comment"]
    assert all(call.args[1] != "TXT" for call in resolver.resolve.call_args_list)


@pytest.mark.parametrize("address", ["224.0.0.1", "239.255.255.250"])
@pytest.mark.parametrize("literal", [True, False])
def test_multicast_ipv4_keeps_endpoint_without_asn_query(resolver, address, literal):
    _answers(resolver, {("example.com.", "A"): [address]})
    result = _run(f"https://{address}/" if literal else "https://example.com/")
    endpoint = _objects(result, "ip-port")[0]
    assert _values(endpoint, "ip") == [address]
    assert _values(endpoint, "dst-port") == ["443"]
    assert (SOURCE_UUID, "derived-from") in _references(endpoint)
    assert not _objects(result, "asn")
    assert "not globally routable" in endpoint["comment"]
    assert "ASN lookup unavailable" not in endpoint["comment"]
    assert all(call.args[1] != "TXT" for call in resolver.resolve.call_args_list)


def test_custom_nameserver_and_timeouts(resolver):
    _answers(resolver, {("example.com.", "AAAA"): ["2001:db8::1"]})
    assert "results" in _run(config={"nameserver": "9.9.9.9"})
    assert resolver.nameservers == ["9.9.9.9"]
    assert resolver.timeout == 2
    assert resolver.lifetime == 5


@pytest.mark.parametrize("config", [{"nameserver": "bad"}, "bad", ["bad"]])
def test_bad_config_returns_error(resolver, config):
    assert "error" in _run(config=config)
    resolver.resolve.assert_not_called()


@pytest.mark.parametrize("query", ["{", "null", "[]", "{}", '{"attribute": []}', '{"attribute": {"type": "url"}}'])
def test_bad_requests(query):
    assert "error" in url_dns.handler(query)


def test_unsupported_type_and_invalid_uuid(resolver):
    for attribute in (
        {"type": "domain", "value": "example.com", "uuid": SOURCE_UUID},
        {"type": "url", "value": "http://example.com", "uuid": "invalid"},
        {"type": "url", "value": "http://example.com", "uuid": None},
    ):
        assert "error" in _run(attribute=attribute)
    resolver.resolve.assert_not_called()


def test_metadata_and_no_query():
    assert url_dns.handler() is False
    assert url_dns.introspection() == {"input": ["url"], "format": "misp_standard"}
    assert url_dns.version()["config"] == ["nameserver"]
    assert url_dns.version()["module-type"] == ["expansion"]
