"""Unit tests for the onyphe and onyphe_full expansion modules.

The ONYPHE client is mocked, so these tests run offline and cover the parsing
layer only: no API key and no network access are needed.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from pyonyphe import OnypheError
from pyonyphe.errors import APIError

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
    return json.dumps(
        {"module": "onyphe", "attribute": attribute, "config": config or {"apikey": "dummy", "mode": "summary"}}
    )


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
            raise APIError(f"access denied: index not allowed: {category}", status_code=400, payload={"error": 12})
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
    assert [q.split(" -fields:")[0] for q in queried] == [
        f'category:{c} domain:"example.com"' for c in onyphe_full.ASSET_CATEGORIES
    ]


def test_onyphe_full_queries_vulnscan_for_an_ip():
    client = full_client()

    with patch.object(onyphe_full, "Onyphe", return_value=client):
        onyphe_full.handler(query(IP_ATTRIBUTE))

    queried = [q for q, _ in client.queries]
    assert any(q.startswith('category:vulnscan ip:"198.51.100.10" -fields:') for q in queried)


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
    service = objects_named(result, "onyphe-service")[0]
    assert relation_values(service, "protocol") == ["https"]
    assert relation_values(service, "product") == ["nginx"]
    assert relation_values(service, "version") == ["1.24.0"]
    assert relation_values(service, "organization") == ["Example Hosting"]


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


CTISCAN_DOCUMENT = {
    "@category": "ctiscan",
    "@timestamp": "2026-10-20T12:00:00Z",
    "seen_date": "2026-10-20",
    "ip": {"dest": "192.0.2.10", "asn": "AS64500", "organization": "Example Hosting", "country": "LU"},
    "tcp": {"dest": 443},
    "services": {"port": ["22", "443", "8080"]},
    "app": {
        "protocol": "http",
        "tls": "false",
        "device": ["router"],
        "data": {"text": "HTTP/1.1 200 OK", "length": 15, "md5": MD5},
    },
    "http": {"code": 200, "url": "https://example.com/"},
    "html": {"title": {"raw": "Example", "text": "Example"}},
    "component": {
        "product": ["nginx", "OpenSSL"],
        "vendor": ["F5"],
        "version": ["1.24.0"],
        "cpe": ["cpe:/a:nginx:nginx:1.24.0"],
    },
    "cert": {
        "fingerprint": {"sha256": SHA256},
        "issuer": {"cn": ["Root CA"], "o": ["CA Inc"]},
        "subject": {"cn": ["example.com"]},
    },
    "dns": {"forward": {"hostname": ["example.com"]}, "reverse": {"hostname": "edge.example.com"}},
    "tag": ["cert::valid"],
}


def run_full(hits, attribute=IP_ATTRIBUTE, **config):
    client = full_client(hits)
    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(attribute, {"apikey": "dummy", **config}))
    return result, client


def test_layered_service_keeps_model_values_and_exact_raw_record():
    import base64

    result, _ = run_full({"ctiscan": [CTISCAN_DOCUMENT]})
    result = result["results"]
    service = objects_named(result, "onyphe-service")[0]
    assert relation_values(service, "ip") == ["192.0.2.10"]
    assert relation_values(service, "port") == ["443"]
    assert relation_values(service, "tls") == [False]
    assert relation_values(service, "product") == ["nginx", "OpenSSL"]
    assert relation_values(service, "http-status") == ["200"]
    assert relation_values(service, "response-length") == ["15"]
    assert set(relation_values(service, "hostname")) == {"example.com", "edge.example.com"}
    raw = next(a for a in service["Attribute"] if a["object_relation"] == "raw-json")
    assert json.loads(base64.b64decode(raw["data"])) == CTISCAN_DOCUMENT
    endpoint = objects_named(result, "ip-port")[0]
    assert relation_values(endpoint, "dst-port") == ["443"]  # services.port is host-wide, not this service
    cert = objects_named(result, "x509")[0]
    assert relation_values(cert, "issuer-organization") == ["CA Inc"]
    assert relation_values(cert, "ip") == []  # serving IP is not a SAN
    references = {(r["referenced_uuid"], r["relationship_type"]) for r in service["ObjectReference"]}
    assert (endpoint["uuid"], "observed-on") in references
    assert (cert["uuid"], "presents") in references
    assert all(a["to_ids"] is False for o in result["Object"] for a in o["Attribute"])


@pytest.mark.parametrize("category", ["ctiscan", "ctiurl"])
def test_cti_search_uses_ip_dest_and_projection(category):
    _, client = run_full({}, categories=category, since="7d")
    q, options = client.queries[0]
    assert q.startswith(f'category:{category} ip.dest:"198.51.100.10" -since:7d -fields:')
    assert "component" in q
    assert options == {"size": 100, "max_results": 100}


@pytest.mark.parametrize("category", ["ctiscan", "ctiurl"])
def test_hostname_layered_search_uses_dns_fields(category):
    _, client = run_full({}, HOSTNAME_ATTRIBUTE, categories=category)
    assert (
        '( ?dns.hostname:"www.example.com" ?dns.forward.hostname:"www.example.com"'
        ' ?dns.reverse.hostname:"www.example.com" )'
        in client.queries[0][0]
    )


def test_domain_layered_category_rejected_before_search():
    result, client = run_full({}, DOMAIN_ATTRIBUTE, categories="ctiscan")
    assert "use riskscan/vulnscan for domains" in result["error"]
    assert client.queries == []
    client.close.assert_called_once()


def test_oql_value_is_quoted_and_escaped():
    attribute = dict(HOSTNAME_ATTRIBUTE, value='host" category:riskscan \\')
    _, client = run_full({}, attribute, categories="datascan")
    assert "hostname:" + json.dumps(attribute["value"]) + " -fields:" in client.queries[0][0]


@pytest.mark.parametrize(
    "tag,relationship",
    [
        ("vulnerable", "affects"),
        ("notvulnerable", "related-to"),
        ("vulnerableversion", "related-to"),
        ("maybevulnerable", "related-to"),
        ("unknownvulnerable", "related-to"),
        ("notvulnerableversion", "related-to"),
    ],
)
def test_verdict_tags_are_preserved_without_false_positive_assertions(tag, relationship):
    hit = {"ip": "192.0.2.10", "port": 443, "tag": [tag], "cve": ["CVE-2021-44228"]}
    result, _ = run_full({"vulnscan": [hit]})
    service = objects_named(result["results"], "onyphe-service")[0]
    vulnerability = objects_named(result["results"], "vulnerability")[0]
    assert relation_values(service, "tag") == [tag]
    assert any(
        r["referenced_uuid"] == service["uuid"] and r["relationship_type"] == relationship
        for r in vulnerability["ObjectReference"]
    )


def test_cve_shared_by_services_keeps_all_references_and_distinct_observation_dates():
    hits = [
        {"ip": "192.0.2.10", "port": port, "seen_date": date, "cve": ["CVE-2021-44228"], "tag": ["vulnerable"]}
        for port, date in [(443, "2026-10-19"), (8443, "2026-10-20"), (443, "2026-10-20")]
    ]
    result, _ = run_full({"vulnscan": hits})
    services = objects_named(result["results"], "onyphe-service")
    assert len(services) == 3
    vulnerabilities = objects_named(result["results"], "vulnerability")
    assert len(vulnerabilities) == 1
    assert {
        r["referenced_uuid"] for r in vulnerabilities[0]["ObjectReference"] if r["relationship_type"] == "affects"
    } == {o["uuid"] for o in services}


@pytest.mark.parametrize("limit,expected", [("-5", 1), ("0", 1), ("20000", 10000), ("1", 1)])
def test_search_limits_are_clamped(limit, expected):
    _, client = run_full({}, limit=limit)
    assert all(options["max_results"] == expected for _, options in client.queries)
    assert all(options["size"] <= expected for _, options in client.queries)


@pytest.mark.parametrize(
    "config", [{"categories": "invalid"}, {"since": "7d category:foo"}, {"timeout": "nan"}, {"timeout": "-1"}]
)
def test_invalid_search_settings_do_not_call_api(config):
    result, client = run_full({}, **config)
    assert "error" in result
    assert client.queries == []


@pytest.mark.parametrize(
    "error",
    [
        APIError("unknown key", status_code=400, payload={"error": 14}),
        APIError("rate limited", status_code=429),
        OnypheError("connection failed"),
    ],
)
def test_non_subscription_errors_fail_lookup_and_close_client(error):
    client = full_client()
    client.search_iter.side_effect = error
    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe_full.handler(query(IP_ATTRIBUTE))
    assert "error" in result
    client.close.assert_called_once()


def test_empty_population_is_successful():
    result, _ = run_full({})
    assert "error" not in result
    assert result["results"].get("Object", []) == []


def test_basic_module_defaults_to_cti_search_and_keeps_summary_opt_in():
    client = full_client({"ctiscan": [CTISCAN_DOCUMENT]})
    with patch.object(onyphe_full, "Onyphe", return_value=client):
        result = onyphe.handler(query(IP_ATTRIBUTE, {"apikey": "dummy"}))
    assert objects_named(result["results"], "onyphe-service")
    assert len(client.queries) == 1
    assert client.queries[0][0].startswith("category:ctiscan ip.dest:")


def test_basic_domain_search_uses_flat_asm_categories():
    client = full_client()
    with patch.object(onyphe_full, "Onyphe", return_value=client):
        onyphe.handler(query(DOMAIN_ATTRIBUTE, {"apikey": "dummy"}))
    assert [q.split()[0] for q, _ in client.queries] == ["category:riskscan", "category:vulnscan"]
    assert all('domain:"example.com"' in q for q, _ in client.queries)


def test_sdk_search_uses_bearer_auth_and_paginates_with_rate_pacing():
    import httpx
    from pymisp import MISPObject

    requests = []

    def respond(request):
        requests.append(request)
        page = int(request.url.params["page"])
        return httpx.Response(
            200, json={"error": 0, "results": [dict(CTISCAN_DOCUMENT, seen_date=f"2026-10-{18+page}")], "max_page": 2}
        )

    sdk = onyphe_full.Onyphe(api_key="test-key")
    sdk._client.close()
    sdk._client = httpx.Client(transport=httpx.MockTransport(respond))
    with patch.object(onyphe_full, "Onyphe", return_value=sdk), patch.object(onyphe_full.time, "sleep") as sleep:
        result = onyphe_full.handler(query(IP_ATTRIBUTE, {"apikey": "test-key", "categories": "ctiscan", "limit": "2"}))
    assert len(requests) == 2
    assert requests[0].url.path == "/api/v2/search/"
    assert requests[0].headers["Authorization"].lower() == "bearer test-key"
    assert requests[0].url.params["q"].startswith("category:ctiscan ip.dest:")
    assert sleep.call_count == 1
    services = objects_named(result["results"], "onyphe-service")
    assert len(services) == 2
    for item in result["results"]["Object"]:
        options = {"misp_objects_path_custom": onyphe_full.DATA_PATH} if item["name"] == "onyphe-service" else {}
        obj = MISPObject(item["name"], strict=True, **options)
        obj.from_dict(**item)
        obj._validate()


@pytest.mark.parametrize(
    "attribute_type,value,field,categories",
    [
        ("url", "https://example.com/path?a=b", "http.url", ["ctiurl"]),
        ("cpe", "cpe:/a:nginx:nginx:1.24.0", "component.cpe", ["ctiscan", "ctiurl"]),
        ("x509-fingerprint-sha256", SHA256, "cert.fingerprint.sha256", ["ctiscan", "ctiurl"]),
    ],
)
def test_cti_pivot_inputs(attribute_type, value, field, categories):
    _, client = run_full({}, dict(IP_ATTRIBUTE, type=attribute_type, value=value))
    assert [q.split()[0] for q, _ in client.queries] == [f"category:{category}" for category in categories]
    assert all(f"{field}:{json.dumps(value)}" in q for q, _ in client.queries)


def test_array_leaves_and_duplicate_observations_validate():
    from copy import deepcopy

    from pymisp import MISPObject

    hit = deepcopy(CTISCAN_DOCUMENT)
    hit["tcp"]["dest"] = [443]
    hit["ip"]["country"] = ["LU"]
    hit["cert"]["serial"] = ["12345"]
    hit["cert"]["fingerprint"]["sha256"] = [SHA256]
    hit["cert"]["validity"] = {"notbefore": ["2026-10-20T00:00:00Z"]}
    hit.pop("@category")  # The category is known from the query; raw JSON stays exactly as returned.
    result, _ = run_full({"ctiscan": [hit, hit]})
    assert len(objects_named(result["results"], "onyphe-service")) == 1
    for item in result["results"]["Object"]:
        options = {"misp_objects_path_custom": onyphe_full.DATA_PATH} if item["name"] == "onyphe-service" else {}
        obj = MISPObject(item["name"], strict=True, **options)
        obj.from_dict(**item)
        obj._validate()
    service = objects_named(result["results"], "onyphe-service")[0]
    assert len(service["ObjectReference"]) == 3  # source attribute, endpoint, certificate
    import base64

    raw = next(a for a in service["Attribute"] if a["object_relation"] == "raw-json")
    assert json.loads(base64.b64decode(raw["data"])) == hit


@pytest.mark.parametrize("category", ["ctiscan", "ctiurl"])
@pytest.mark.parametrize("primary", ["www.example.com", ["www.example.com", "alias.example.com"]])
def test_primary_cti_hostname_is_preserved_in_service_and_endpoint(category, primary):
    hit = {"ip": {"dest": "192.0.2.10"}, "dns": {"hostname": primary}}
    result, _ = run_full({category: [hit]}, categories=category)
    expected = primary if isinstance(primary, list) else [primary]
    for name in ("onyphe-service", "ip-port"):
        assert relation_values(objects_named(result["results"], name)[0], "hostname") == expected


def test_primary_cti_hostname_is_an_anchor_and_is_deduplicated_with_dns_enrichment():
    hit = {"dns": {"hostname": "www.example.com", "forward": {"hostname": ["www.example.com"]}}}
    result, _ = run_full({"ctiscan": [hit]}, categories="ctiscan")
    for name in ("onyphe-service", "ip-port"):
        assert relation_values(objects_named(result["results"], name)[0], "hostname") == ["www.example.com"]


def test_basic_hostname_query_includes_primary_and_secondary_dns_fields():
    client = full_client()
    with patch.object(onyphe_full, "Onyphe", return_value=client):
        onyphe.handler(query(HOSTNAME_ATTRIBUTE, {"apikey": "dummy"}))
    assert len(client.queries) == 1
    for field in ("dns.hostname", "dns.forward.hostname", "dns.reverse.hostname"):
        assert f'?{field}:"www.example.com"' in client.queries[0][0]


@pytest.mark.parametrize("category", ["ctiscan", "ctiurl"])
@pytest.mark.parametrize("cves", ["CVE-2021-44228", ["CVE-2021-44228", "CVE-2024-3094"]])
def test_layered_component_cves_are_preserved_and_linked_to_each_service(category, cves):
    hits = [
        {"ip": {"dest": "192.0.2.10"}, "tcp": {"dest": port}, "component": {"cve": cves}, "cve": ["CVE-2000-0001"]}
        for port in (443, 8443)
    ]
    result, _ = run_full({category: hits}, categories=category)
    services = objects_named(result["results"], "onyphe-service")
    expected = cves if isinstance(cves, list) else [cves]
    assert len(services) == 2
    assert all(relation_values(service, "cve") == expected for service in services)
    vulnerabilities = objects_named(result["results"], "vulnerability")
    assert {cve for obj in vulnerabilities for cve in relation_values(obj, "id")} == set(expected)
    for obj in vulnerabilities:
        assert {r["referenced_uuid"] for r in obj["ObjectReference"] if r["relationship_type"] == "related-to"} >= {
            s["uuid"] for s in services
        }
        assert not any(r["relationship_type"] == "affects" for r in obj["ObjectReference"])


@pytest.mark.parametrize(
    "serial,expected",
    [
        ({"hex": "0a1b", "num": 2587}, "0a1b"),
        ({"num": 2587}, "2587"),
        ({"num": 340282366920938463463374607431768211455}, "340282366920938463463374607431768211455"),
        ({"hex": "", "num": 0}, "0"),
        ({"hex": ["0a1b"], "num": 2587}, "0a1b"),
        ({"hex": {"unexpected": "value"}, "num": 2587}, "2587"),
        ({"hex": {"unexpected": "value"}}, None),
        ({}, None),
        ("0a1b", "0a1b"),
        (["0a1b"], "0a1b"),
    ],
)
def test_certificate_serial_is_a_scalar_and_layered_serial_prefers_hex(serial, expected):
    from pymisp import MISPObject

    hit = {"ip": {"dest": "192.0.2.10"}, "cert": {"serial": serial, "fingerprint": {"sha256": SHA256}}}
    result, _ = run_full({"ctiscan": [hit]}, categories="ctiscan")
    certificate = objects_named(result["results"], "x509")[0]
    assert relation_values(certificate, "serial-number") == ([] if expected is None else [expected])
    assert all(not isinstance(a["value"], (dict, list)) for a in certificate["Attribute"])
    obj = MISPObject("x509", strict=True)
    obj.from_dict(**certificate)
    obj._validate()


@pytest.mark.parametrize("category", ["ctiscan", "ctiurl"])
@pytest.mark.parametrize("transport", ["tcp", "udp", None])
@pytest.mark.parametrize("tcp", [{"dest": 53}, {}])
def test_layered_app_transport_is_preserved_without_inference(category, transport, tcp):
    hit = {"ip": {"dest": "192.0.2.10"}, "tcp": tcp, "app": {"transport": transport}}
    result, _ = run_full({category: [hit]}, categories=category)
    expected = [transport] if transport is not None else []
    assert relation_values(objects_named(result["results"], "onyphe-service")[0], "transport") == expected
    assert relation_values(objects_named(result["results"], "ip-port")[0], "protocol") == expected
