import json
from unittest.mock import patch

from misp_modules.modules.expansion import netapi

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"

# Answers of the live API on 2026-10-26, trimmed to the fields the module reads.
CHECK_LISTED_NOW = {
    "value": "000359.xyz",
    "type": "domain",
    "listed_now": True,
    "listed_ever": True,
    "matched_value": "000359.xyz",
    "first_seen": "2023-02-25",
    "last_seen": "2026-10-26 01:05:27 UTC",
    "block_reason": "blackbook",
    "registrar": {"id": 1599, "name": "Alibaba Cloud Computing Ltd.", "brand_name": "Alibaba Cloud"},
}
CHECK_VIA_REGISTERED_DOMAIN = dict(CHECK_LISTED_NOW, value="www.000359.xyz")
CHECK_LISTED_PAST = {
    "value": "0-07.ru",
    "type": "domain",
    "listed_now": False,
    "listed_ever": True,
    "matched_value": "0-07.ru",
    "first_seen": "2019-12-18",
    "last_seen": "2019-12-25 00:00:00 UTC",
    "block_reason": "suspicious",
    "registrar": None,
}
CHECK_CLEAN = {"value": "github.com", "type": "domain", "listed_now": False, "listed_ever": False}
RANK_IN_TOP_1M = {"domain": "github.com", "in_top_1m": True, "rank": 11, "snapshot_date": "2026-10-26"}
RANK_NOT_IN_TOP_1M = {"domain": "000359.xyz", "in_top_1m": False, "rank": None, "snapshot_date": "2026-10-26"}
RANK_PAST_NOT_IN_TOP_1M = dict(RANK_NOT_IN_TOP_1M, domain="0-07.ru")


class MockResponse:
    def __init__(self, payload, status_code=200, headers=None):
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        if self.payload is None:
            raise ValueError("no JSON")
        return self.payload


def _query(value, type_="domain", config=None):
    attribute = {"type": type_, "value": value, "uuid": UUID}
    return json.dumps({"module": "netapi", "attribute": attribute, "config": config or {}})


def _api(check=None, rank=None, calls=None):
    """Return a requests.get replacement dispatching on the method parameter."""

    def _get(url, params=None, headers=None, timeout=None):
        if calls is not None:
            calls.append((url, dict(params or {}), dict(headers or {})))
        method = (params or {}).get("method")
        if method == "compromised-check":
            return check if isinstance(check, MockResponse) else MockResponse(check)
        if method == "domain-rank":
            return rank if isinstance(rank, MockResponse) else MockResponse(rank)
        return MockResponse({"error": {"code": "unknown_method", "message": "Unknown method."}}, 400)

    return _get


def _texts(results):
    return [a["value"] for a in results["results"]["Attribute"] if a["type"] == "text"]


def test_listed_domain_returns_the_listing_and_the_rank():
    with patch.object(netapi.requests, "get", _api(CHECK_LISTED_NOW, RANK_NOT_IN_TOP_1M)):
        results = netapi.handler(_query("000359.xyz"))

    listing, rank = _texts(results)
    assert listing.startswith("NetAPI compromised feed: 000359.xyz is listed now")
    assert "first seen 2023-02-25" in listing
    assert "reported by blackbook" in listing
    assert "registrar Alibaba Cloud" in listing
    assert "matched entry" not in listing
    assert rank == "NetAPI Top 1M: 000359.xyz is not in the NetAPI Top 1M"


def test_hostname_listed_through_its_registered_domain_says_so():
    """
    The feed matches a hostname through its registered domain. Presenting that as a listing
    of the hostname itself would overstate what the feed knows.
    """
    with patch.object(netapi.requests, "get", _api(CHECK_VIA_REGISTERED_DOMAIN, RANK_NOT_IN_TOP_1M)):
        results = netapi.handler(_query("www.000359.xyz", "hostname"))

    assert "matched entry: 000359.xyz (the registered domain)" in _texts(results)[0]


def test_past_listing_is_not_reported_as_current():
    with patch.object(netapi.requests, "get", _api(CHECK_LISTED_PAST, RANK_PAST_NOT_IN_TOP_1M)):
        results = netapi.handler(_query("0-07.ru"))

    listing, rank = _texts(results)
    assert "listed in the past (last seen 2019-12-25), not in the current feed" in listing
    assert "reported by suspicious" in listing
    assert rank == "NetAPI Top 1M: 0-07.ru is not in the NetAPI Top 1M"


def test_a_clean_value_is_an_answer_not_an_error():
    """For a reputation lookup, never listed is a result the analyst needs to see."""
    with patch.object(netapi.requests, "get", _api(CHECK_CLEAN, RANK_IN_TOP_1M)):
        results = netapi.handler(_query("github.com"))

    listing, rank = _texts(results)
    assert listing == "NetAPI compromised feed: github.com is not listed, now or in the past"
    assert rank == "NetAPI Top 1M: github.com is ranked #11 (snapshot of 2026-10-26)"


def test_url_is_looked_up_by_its_host():
    calls = []
    with patch.object(netapi.requests, "get", _api(CHECK_CLEAN, RANK_IN_TOP_1M, calls)):
        netapi.handler(_query("HTTPS://Sub.Example.COM:8443/login?x=1", "url"))
        netapi.handler(_query("example.org/path", "url"))

    values = [params.get("value") for _, params, _ in calls if params.get("method") == "compromised-check"]
    assert values == ["sub.example.com", "example.org"]


def test_domain_side_of_domain_ip_is_looked_up():
    calls = []
    with patch.object(netapi.requests, "get", _api(CHECK_CLEAN, RANK_IN_TOP_1M, calls)):
        netapi.handler(_query("github.com|140.82.121.4", "domain|ip"))

    assert calls[0][1]["value"] == "github.com"


def test_no_token_is_sent_unless_configured():
    calls = []
    with patch.object(netapi.requests, "get", _api(CHECK_CLEAN, RANK_IN_TOP_1M, calls)):
        netapi.handler(_query("github.com"))
        netapi.handler(_query("github.com", config={"api_token": "abc123"}))

    assert "Authorization" not in calls[0][2]
    assert calls[-1][2]["Authorization"] == "Bearer abc123"


def test_rejected_value_returns_the_api_message():
    rejected = MockResponse({"error": {"code": "invalid_value", "message": "Not a valid domain name."}}, 400)
    with patch.object(netapi.requests, "get", _api(rejected)):
        results = netapi.handler(_query("not_a_host"))

    assert results == {"error": "NetAPI lookup failed: Not a valid domain name."}


def test_rate_limit_reports_when_to_retry():
    limited = MockResponse(
        {"error": {"code": "rate_limited", "message": "Too many requests."}}, 429, {"Retry-After": "42"}
    )
    with patch.object(netapi.requests, "get", _api(limited)):
        results = netapi.handler(_query("github.com"))

    assert results["error"] == "NetAPI lookup failed: Too many requests. (retry after 42 s)"


def test_unreachable_api_degrades_to_an_error_instead_of_raising():
    def _down(url, params=None, headers=None, timeout=None):
        raise netapi.requests.exceptions.ConnectionError("connection refused")

    with patch.object(netapi.requests, "get", _down):
        results = netapi.handler(_query("github.com"))

    assert results["error"].startswith("NetAPI lookup failed: the NetAPI API could not be reached")


def test_a_failed_rank_lookup_keeps_the_listing():
    """The listing was obtained; losing it because the rank call failed would hide it."""
    with patch.object(netapi.requests, "get", _api(CHECK_LISTED_NOW, MockResponse(None, 502))):
        results = netapi.handler(_query("000359.xyz"))

    listing, rank = _texts(results)
    assert "is listed now" in listing
    assert rank == "NetAPI Top 1M rank unavailable: the NetAPI API returned HTTP 502 without JSON"


def test_unsupported_type_is_refused_without_a_request():
    calls = []
    with patch.object(netapi.requests, "get", _api(CHECK_CLEAN, calls=calls)):
        md5 = netapi.handler(_query("d41d8cd98f00b204e9800998ecf8427e", "md5"))
        ip = netapi.handler(_query("1.1.1.1", "ip-dst"))

    assert md5 == ip == {"error": "Unsupported attribute type."}
    assert calls == []


def test_url_with_an_ip_host_is_refused_without_a_request():
    """NetAPI covers domain names only, so an IP host is not sent to the API."""
    calls = []
    with patch.object(netapi.requests, "get", _api(CHECK_CLEAN, calls=calls)):
        ipv4 = netapi.handler(_query("http://192.0.2.10/payload.exe", "url"))
        ipv6 = netapi.handler(_query("http://[2001:db8::1]:8080/", "url"))

    expected = {"error": "NetAPI covers domain names only. IP addresses are not looked up."}
    assert ipv4 == ipv6 == expected
    assert calls == []


def test_results_are_not_correlated_and_not_flagged_for_ids():
    with patch.object(netapi.requests, "get", _api(CHECK_LISTED_NOW, RANK_NOT_IN_TOP_1M)):
        results = netapi.handler(_query("000359.xyz"))

    for attribute in results["results"]["Attribute"]:
        assert attribute["disable_correlation"] is True
        assert attribute["to_ids"] is False
