"""Unit tests for the onyphe and onyphe_full expansion modules.

The ONYPHE client is mocked, so these tests run offline and cover the parsing
layer only: no API key and no network access are needed.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from pyonyphe import OnypheError

from misp_modules.modules.expansion import onyphe, onyphe_full

IP_ATTRIBUTE = {
    "type": "ip-src",
    "value": "198.51.100.10",
    "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b",
}
DOMAIN_ATTRIBUTE = {
    "type": "domain",
    "value": "example.com",
    "uuid": "1f0a4a1e-2f6b-4d0c-9a2f-2d4a1b0c7e91",
}
HOSTNAME_ATTRIBUTE = {
    "type": "hostname",
    "value": "www.example.com",
    "uuid": "9c1d5f22-3b7a-4e18-8c33-6d2f5a8b4c07",
}

# Values mined from a paste go through is_routable(), and Python's ipaddress counts the RFC
# 5737 documentation ranges among the private networks -- so anything expected to survive
# that filter has to be a genuinely routable address, not 198.51.100.x or 203.0.113.x.
ROUTABLE_IP = "8.8.8.8"

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"

CERTIFICATE_DOCUMENT = {
    "serial": "0a1b2c3d4e5f",
    "fingerprint": {"md5": MD5, "sha1": SHA1, "sha256": SHA256},
    "signature": {"algorithm": "sha256WithRSAEncryption"},
    "publickey": {"algorithm": "RSA", "exponent": 65537, "length": 2048},
    "issuer": {"commonname": "Example Root CA"},
    "subject": {"commonname": "www.example.com"},
    "validity": {"notbefore": "2025-01-01T00:00:00.000Z", "notafter": "2026-01-01T00:00:00.000Z"},
}


class FakeResponse:
    """Stand-in for pyonyphe.Response: only ``results`` is consumed by the modules."""

    def __init__(self, results=None):
        self.results = results or []

    def __iter__(self):
        return iter(self.results)

    def __len__(self):
        return len(self.results)


def objects_named(results, name):
    return [o for o in results.get("Object", []) if o["name"] == name]


def relation_values(misp_object, relation):
    return [a["value"] for a in misp_object["Attribute"] if a["object_relation"] == relation]


def attributes_typed(results, attribute_type):
    return [a for a in results.get("Attribute", []) if a["type"] == attribute_type]


def attribute_values(results, attribute_type):
    return [a["value"] for a in attributes_typed(results, attribute_type)]


def query(attribute, config=None):
    return json.dumps({"module": "onyphe", "attribute": attribute, "config": config or {"apikey": "dummy"}})


# ---------------------------------------------------------------------------
# onyphe
# ---------------------------------------------------------------------------


def test_onyphe_missing_apikey_returns_error():
    result = onyphe.handler(json.dumps({"attribute": IP_ATTRIBUTE, "config": {}}))
    assert "error" in result


def test_onyphe_summary_ip_builds_domain_ip_objects():
    client = MagicMock()
    client.summary_ip.return_value = FakeResponse(
        [{"domain": ["example.com", "example.org"], "hostname": "www.example.com"}]
    )

    with patch.object(onyphe, "Onyphe", return_value=client):
        result = onyphe.handler(query(IP_ATTRIBUTE))["results"]

    client.summary_ip.assert_called_once_with("198.51.100.10")
    domain_ip = objects_named(result, "domain-ip")
    assert len(domain_ip) == 3
    domains = {v for o in domain_ip for v in relation_values(o, "domain")}
    hostnames = {v for o in domain_ip for v in relation_values(o, "hostname")}
    assert domains == {"example.com", "example.org"}
    assert hostnames == {"www.example.com"}
    assert all(relation_values(o, "ip") == ["198.51.100.10"] for o in domain_ip)


def test_onyphe_summary_ip_accepts_scalar_and_list_fields():
    """ONYPHE returns either a scalar or a list for the same field."""
    client = MagicMock()
    client.summary_ip.return_value = FakeResponse([{"domain": "example.com"}, {"domain": ["example.org"]}])

    with patch.object(onyphe, "Onyphe", return_value=client):
        result = onyphe.handler(query(IP_ATTRIBUTE))["results"]

    found = {v for o in objects_named(result, "domain-ip") for v in relation_values(o, "domain")}
    assert found == {"example.com", "example.org"}


def test_onyphe_summary_domain_without_hostname_field_does_not_raise():
    client = MagicMock()
    client.summary_domain.return_value = FakeResponse([{"domain": ["example.com"], "ip": "198.51.100.10"}])

    with patch.object(onyphe, "Onyphe", return_value=client):
        result = onyphe.handler(query(DOMAIN_ATTRIBUTE))["results"]

    assert attribute_values(result, "domain") == ["example.com", "example.com"]
    assert objects_named(result, "domain-ip")


def test_onyphe_certificate_uses_notafter_for_validity_not_after():
    client = MagicMock()
    client.summary_ip.return_value = FakeResponse([dict(CERTIFICATE_DOCUMENT)])

    with patch.object(onyphe, "Onyphe", return_value=client):
        result = onyphe.handler(query(IP_ATTRIBUTE))["results"]

    x509 = objects_named(result, "x509")[0]
    assert relation_values(x509, "x509-fingerprint-sha256") == [SHA256]
    assert relation_values(x509, "x509-fingerprint-sha1") == [SHA1]
    assert relation_values(x509, "x509-fingerprint-md5") == [MD5]
    # PyMISP normalises datetime attributes, so the trailing Z becomes an explicit offset
    assert relation_values(x509, "validity-not-before") == ["2025-01-01T00:00:00+00:00"]
    assert relation_values(x509, "validity-not-after") == ["2026-01-01T00:00:00+00:00"]
    assert relation_values(x509, "signature_algorithm") == ["SHA256_WITH_RSA_ENCRYPTION"]
    assert relation_values(x509, "issuer") == ["Example Root CA"]
    assert relation_values(x509, "subject") == ["www.example.com"]


def test_onyphe_certificate_never_uses_the_san_ip_relation_for_the_queried_value():
    """x509 `ip` is a Subject Alternative Name, not the host serving the certificate."""
    client = MagicMock()
    client.summary_ip.return_value = FakeResponse([dict(CERTIFICATE_DOCUMENT)])

    with patch.object(onyphe, "Onyphe", return_value=client):
        result = onyphe.handler(query(IP_ATTRIBUTE))["results"]

    x509 = objects_named(result, "x509")[0]
    assert relation_values(x509, "ip") == []


def test_onyphe_hostname_summary_builds_vulnerability_objects():
    client = MagicMock()
    client.summary_hostname.return_value = FakeResponse(
        [{"ip": "198.51.100.10", "cve": ["CVE-2021-44228", "CVE-2024-3094"]}]
    )

    with patch.object(onyphe, "Onyphe", return_value=client):
        result = onyphe.handler(query(HOSTNAME_ATTRIBUTE))["results"]

    vulnerabilities = objects_named(result, "vulnerability")
    assert {v for o in vulnerabilities for v in relation_values(o, "id")} == {"CVE-2021-44228", "CVE-2024-3094"}


def test_onyphe_api_error_is_reported_and_client_closed():
    client = MagicMock()
    client.summary_ip.side_effect = OnypheError("quota exceeded")

    with patch.object(onyphe, "Onyphe", return_value=client):
        result = onyphe.handler(query(IP_ATTRIBUTE))

    assert "error" in result
    assert "quota exceeded" in result["error"]
    client.close.assert_called_once()


def test_onyphe_client_is_closed_on_success():
    client = MagicMock()
    client.summary_ip.return_value = FakeResponse([])

    with patch.object(onyphe, "Onyphe", return_value=client):
        onyphe.handler(query(IP_ATTRIBUTE))

    client.close.assert_called_once()


# ---------------------------------------------------------------------------
# onyphe_full -- helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "240.0.0.1", "nope", ""],
)
def test_is_routable_rejects_non_indicators(value):
    assert onyphe_full.is_routable(value) is False


@pytest.mark.parametrize("value", [ROUTABLE_IP, "1.1.1.1", "2001:4860:4860::8888"])
def test_is_routable_accepts_public_addresses(value):
    assert onyphe_full.is_routable(value) is True


@pytest.mark.parametrize("value", ["example.com", "www.example.com", "a.b.c.example.org"])
def test_looks_like_host_accepts_names(value):
    assert onyphe_full.looks_like_host(value) is True


@pytest.mark.parametrize(
    "value",
    ["localhost", "not a host", "http://example.com/x", "user@example.com", "example.com:443", "", None, 42],
)
def test_looks_like_host_rejects_free_text(value):
    assert onyphe_full.looks_like_host(value) is False


# ---------------------------------------------------------------------------
# onyphe_full -- modules
# ---------------------------------------------------------------------------


def full_client(hits_by_category=None, failing=()):
    """Build a mocked client whose search_iter dispatches on the queried category."""
    hits_by_category = hits_by_category or {}
    client = MagicMock()
    client.queries = []

    def search_iter(query_string, **kwargs):
        client.queries.append((query_string, kwargs))
        category = query_string.split()[0].split(":", 1)[1]
        if category in failing:
            raise OnypheError(f"{category} not covered by your license")
        return iter(hits_by_category.get(category, []))

    client.search_iter.side_effect = search_iter
    return client


def test_onyphe_full_missing_apikey_returns_error():
    result = onyphe_full.handler(json.dumps({"attribute": IP_ATTRIBUTE, "config": {}}))
    assert "error" in result


def test_onyphe_full_queries_every_category_with_the_right_field():
    client = full_client()

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        onyphe_full.handler(query(DOMAIN_ATTRIBUTE))

    queried = [q for q, _ in client.queries]
    assert queried == [f"category:{c} domain:example.com" for c in onyphe_full.ASSET_CATEGORIES]
    assert "vulnscan" not in " ".join(queried)


def test_onyphe_full_queries_vulnscan_for_an_ip():
    client = full_client()

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        onyphe_full.handler(query(IP_ATTRIBUTE))

    queried = [q for q, _ in client.queries]
    assert "category:vulnscan ip:198.51.100.10" in queried


def test_onyphe_full_datascan_builds_ip_port_object():
    client = full_client(
        {
            "datascan": [
                {
                    "ip": "198.51.100.10",
                    "port": 443,
                    "transport": "tcp",
                    "protocol": "https",
                    "product": "nginx",
                    "productversion": "1.24.0",
                    "organization": "Example Hosting",
                    "asn": "AS64500",
                    "country": "FR",
                    "seen_date": "2026-07-30",
                }
            ]
        }
    )

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    ip_port = objects_named(result, "ip-port")[0]
    assert relation_values(ip_port, "ip") == ["198.51.100.10"]
    assert [str(v) for v in relation_values(ip_port, "dst-port")] == ["443"]
    assert relation_values(ip_port, "protocol") == ["tcp"]
    assert relation_values(ip_port, "AS") == ["AS64500"]
    assert relation_values(ip_port, "country-code") == ["FR"]
    assert relation_values(ip_port, "text") == ["https nginx 1.24.0 Example Hosting"]


def test_onyphe_full_datascan_without_anchor_is_skipped():
    client = full_client({"datascan": [{"organization": "Example Hosting"}]})

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    assert objects_named(result, "ip-port") == []


def test_onyphe_full_deduplicates_repeated_documents():
    hit = {"ip": "198.51.100.10", "port": 443, "transport": "tcp"}
    client = full_client({"datascan": [dict(hit), dict(hit), dict(hit)]})

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    assert len(objects_named(result, "ip-port")) == 1


def test_onyphe_full_skips_a_category_the_licence_does_not_cover():
    client = full_client(
        {"threatlist": [{"threatlist": "blocklist.de", "seen_date": "2026-07-30"}]},
        failing=("datascan", "vulnscan"),
    )

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))

    assert "error" not in result
    assert "seen 2026-07-30 on blocklist.de" in attribute_values(result["results"], "comment")


def test_onyphe_full_reports_the_skipped_categories():
    """A missing category has to be visible, otherwise a partial event reads as a clean one."""
    client = full_client(failing=("datascan", "vulnscan"))

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    reported = [a for a in attributes_typed(result, "comment") if a["value"].startswith(onyphe_full.SKIPPED_PREFIX)]
    assert len(reported) == 1
    assert "datascan" in reported[0]["value"]
    assert "vulnscan" in reported[0]["value"]
    assert reported[0]["category"] == "Other"
    assert reported[0]["to_ids"] is False


def test_onyphe_full_says_nothing_when_every_category_answers():
    client = full_client()

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    assert attribute_values(result, "comment") == []


def test_onyphe_full_pastries_builds_a_pastebin_url():
    client = full_client(
        {
            "pastries": [
                {
                    "source": "pastebin",
                    "key": "aBcD1234",
                    "domain": ["example.com"],
                    "ip": [ROUTABLE_IP],
                }
            ]
        }
    )

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    assert attribute_values(result, "url") == ["https://pastebin.com/raw/aBcD1234"]
    assert "example.com" in attribute_values(result, "domain")
    assert ROUTABLE_IP in attribute_values(result, "ip-dst")


def test_onyphe_full_pastries_are_context_and_never_flagged_for_detection():
    """A value quoted in a paste is not an observation of the queried asset."""
    client = full_client(
        {
            "pastries": [
                {
                    "source": "pastebin",
                    "key": "aBcD1234",
                    "domain": ["example.com"],
                    "hostname": ["www.example.org"],
                    "ip": [ROUTABLE_IP],
                }
            ]
        }
    )

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    mined = [a for a in result["Attribute"] if a["type"] in ("url", "domain", "hostname", "ip-dst")]
    assert mined, "the paste should still yield context attributes"
    assert all(a["to_ids"] is False for a in mined)


def test_onyphe_full_pastries_drops_addresses_that_are_not_indicators():
    """Pastes are full of configuration samples: RFC1918, loopback and friends are noise."""
    client = full_client(
        {
            "pastries": [
                {
                    "source": "pastebin",
                    "key": "aBcD1234",
                    "ip": [
                        "10.0.0.1",
                        "172.16.5.4",
                        "192.168.1.1",
                        "127.0.0.1",
                        "169.254.1.1",
                        "224.0.0.1",
                        "240.0.0.1",
                        ROUTABLE_IP,
                    ],
                }
            ]
        }
    )

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    assert attribute_values(result, "ip-dst") == [ROUTABLE_IP]


def test_onyphe_full_pastries_drops_values_that_are_not_hostnames():
    client = full_client(
        {
            "pastries": [
                {
                    "source": "pastebin",
                    "key": "aBcD1234",
                    "domain": ["localhost", "not a host", "http://example.com/x", "user@example.com"],
                }
            ]
        }
    )

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    assert attribute_values(result, "domain") == []


def test_onyphe_full_pastries_types_a_fully_qualified_name_as_hostname():
    client = full_client(
        {
            "pastries": [
                {
                    "source": "pastebin",
                    "key": "aBcD1234",
                    "domain": ["example.com"],
                    "hostname": ["www.example.com"],
                }
            ]
        }
    )

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    assert attribute_values(result, "domain") == ["example.com"]
    assert attribute_values(result, "hostname") == ["www.example.com"]


def test_onyphe_full_resolver_builds_domain_ip_objects():
    client = full_client({"resolver": [{"ip": "198.51.100.10", "domain": "example.com", "type": "A"}]})

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    domain_ip = objects_named(result, "domain-ip")[0]
    assert relation_values(domain_ip, "ip") == ["198.51.100.10"]
    assert relation_values(domain_ip, "domain") == ["example.com"]


def test_onyphe_full_resolver_types_reverse_and_forward_as_hostnames():
    client = full_client({"resolver": [{"ip": "198.51.100.10", "reverse": "mail.example.com", "type": "PTR"}]})

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    assert attribute_values(result, "hostname") == ["mail.example.com"]
    assert attribute_values(result, "domain") == []


def test_onyphe_full_vulnscan_builds_vulnerability_objects():
    client = full_client({"vulnscan": [{"ip": "198.51.100.10", "cve": ["CVE-2021-44228"]}]})

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))["results"]

    assert relation_values(objects_named(result, "vulnerability")[0], "id") == ["CVE-2021-44228"]


@pytest.mark.parametrize(
    "configured,expected",
    [
        ({"apikey": "dummy", "limit": "25"}, 25),
        ({"apikey": "dummy"}, onyphe_full.DEFAULT_LIMIT),
        ({"apikey": "dummy", "limit": "nope"}, onyphe_full.DEFAULT_LIMIT),
    ],
)
def test_onyphe_full_limit_is_passed_to_search_iter(configured, expected):
    client = full_client()

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        onyphe_full.handler(query(IP_ATTRIBUTE, config=configured))

    assert all(kwargs["max_results"] == expected for _, kwargs in client.queries)


def test_onyphe_full_client_is_closed_on_success():
    client = full_client()

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        onyphe_full.handler(query(IP_ATTRIBUTE))

    client.close.assert_called_once()
