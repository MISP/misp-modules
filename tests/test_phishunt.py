import copy
import json
from unittest.mock import patch

import pytest
import requests

from misp_modules.modules.expansion import phishunt

# Fixtures below are the verbatim JSON bodies captured from
# https://phishunt.io/api/v1/search.json?q=<q>&limit=200 on 2026-10-13.

SEARCH_SINGLE = json.loads(
    r"""{"query":"binance-red-packet.vercel.app","count":1,"limit":200,"results":[{"url":"https://binance-red-packet.vercel.app","domain":"binance-red-packet.vercel.app","company":"binance","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-03-27T13:01:15.282767+00:00","uuid":"f4255572-fb63-4810-baad-2051acebe7ca","ip":"64.29.17.195","country":"United States","asn":"16509","org":"Amazon.com, Inc.","cert":"WR1","malicious_google":false,"malicious_openphish":true,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":false,"service_range":null}]}"""  # noqa: E501
)

SEARCH_SERVICE_RANGE = json.loads(
    r"""{"query":"googlel0gin.netlify.app","count":1,"limit":200,"results":[{"url":"https://googlel0gin.netlify.app","domain":"googlel0gin.netlify.app","company":"google","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-10-11T13:04:20.349528+00:00","uuid":"3499e8ed-96ef-4cf0-9803-be653838dbb0","ip":"63.176.8.218","country":"Germany","asn":"16509","org":"Amazon.com, Inc.","cert":"DigiCert Global G2 TLS RSA SHA256 2020 CA1","malicious_google":false,"malicious_openphish":true,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":false,"service_range":{"best":{"direction":"both","kind":"hosting","kind_label":"rentable cloud hosting","prefix":"63.176.0.0/12","provider":"AWS","region":"eu-central-1","service":"EC2","source":"aws"},"also":[],"note":"Official provider IP range of this IP. Context only, not a verdict."}}]}"""  # noqa: E501
)

# q=pages.dev: a substring query, so it returns many different hosts.
SEARCH_SUBSTRING = json.loads(
    r"""{"query":"pages.dev","count":9,"limit":200,"results":[{"url":"https://exoduswalletcc.pages.dev/%22%3EExodus","domain":"exoduswalletcc.pages.dev","company":"exodus","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-10-11T01:03:34.868264+00:00","uuid":"f8a62c5d-d840-4046-bde8-9e69d47871d6","ip":"188.114.97.3","country":"United States","asn":"13335","org":"Cloudflare, Inc.","cert":"WE1","malicious_google":false,"malicious_openphish":true,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":true,"service_range":{"best":{"direction":"both","kind":"platform","kind_label":"shared platform that serves customer content","prefix":"188.114.96.0/20","provider":"Cloudflare","region":"","service":"CDN","source":"cloudflare"},"also":[],"note":"Official provider IP range of this IP. Context only, not a verdict."}},{"url":"http://uspss.pages.dev/entreg/LoginAction_input%25252CN/A%25252Chttps%25253A/www.googleoptimize.com","domain":"uspss.pages.dev","company":"usps","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-10-10T01:15:33.932766+00:00","uuid":"30b9b094-4a84-4846-bee9-37e7012db00c","ip":"172.66.47.140","country":"United States","asn":"13335","org":"Cloudflare, Inc.","cert":"WE1","malicious_google":true,"malicious_openphish":true,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":true,"service_range":{"best":{"direction":"both","kind":"platform","kind_label":"shared platform that serves customer content","prefix":"172.64.0.0/13","provider":"Cloudflare","region":"","service":"CDN","source":"cloudflare"},"also":[],"note":"Official provider IP range of this IP. Context only, not a verdict."}},{"url":"https://io-trezrn-eng.pages.dev/smart78","domain":"io-trezrn-eng.pages.dev","company":"trezor","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-10-08T13:01:35.660973+00:00","uuid":"777b5fbc-af2e-4a47-be8c-6b6e82e1dec6","ip":"188.114.96.3","country":"United States","asn":"13335","org":"Cloudflare, Inc.","cert":"WE1","malicious_google":false,"malicious_openphish":true,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":true,"service_range":{"best":{"direction":"both","kind":"platform","kind_label":"shared platform that serves customer content","prefix":"188.114.96.0/20","provider":"Cloudflare","region":"","service":"CDN","source":"cloudflare"},"also":[],"note":"Official provider IP range of this IP. Context only, not a verdict."}},{"url":"https://whatsapp11-cnj.pages.dev","domain":"whatsapp11-cnj.pages.dev","company":"whatsapp","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-09-29T23:25:20.403832+00:00","uuid":"afd3e6d6-cc9e-423d-8f81-e156e2418434","ip":"172.66.47.148","country":"United States","asn":"13335","org":"Cloudflare, Inc.","cert":"YE2","malicious_google":true,"malicious_openphish":false,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":false,"service_range":{"best":{"direction":"both","kind":"platform","kind_label":"shared platform that serves customer content","prefix":"172.64.0.0/13","provider":"Cloudflare","region":"","service":"CDN","source":"cloudflare"},"also":[],"note":"Official provider IP range of this IP. Context only, not a verdict."}},{"url":"http://en-ledgre.pages.dev/favicon.ico/","domain":"en-ledgre.pages.dev","company":"ledger","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-09-24T01:03:06.784415+00:00","uuid":"55ce8e45-d5ad-45fe-8f61-7d1609402578","ip":"188.114.97.3","country":"United States","asn":"13335","org":"Cloudflare, Inc.","cert":"WE1","malicious_google":false,"malicious_openphish":true,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":false,"service_range":{"best":{"direction":"both","kind":"platform","kind_label":"shared platform that serves customer content","prefix":"188.114.96.0/20","provider":"Cloudflare","region":"","service":"CDN","source":"cloudflare"},"also":[],"note":"Official provider IP range of this IP. Context only, not a verdict."}},{"url":"https://docs-trezor-app.pages.dev/config.php","domain":"docs-trezor-app.pages.dev","company":"trezor","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-08-26T01:02:17.027467+00:00","uuid":"59dea575-756b-458e-9596-e57ac729496d","ip":"188.114.97.3","country":"United States","asn":"13335","org":"Cloudflare, Inc.","cert":"WE1","malicious_google":false,"malicious_openphish":true,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":true,"service_range":{"best":{"direction":"both","kind":"platform","kind_label":"shared platform that serves customer content","prefix":"188.114.96.0/20","provider":"Cloudflare","region":"","service":"CDN","source":"cloudflare"},"also":[],"note":"Official provider IP range of this IP. Context only, not a verdict."}},{"url":"https://meet-googlee46347975696.pages.dev","domain":"meet-googlee46347975696.pages.dev","company":"google","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-05-16T01:01:11.978995+00:00","uuid":"23496946-bc9c-4abf-a5c3-a890ac313fe6","ip":"188.114.97.3","country":"United States","asn":"13335","org":"Cloudflare, Inc.","cert":"WE1","malicious_google":true,"malicious_openphish":true,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":false,"service_range":{"best":{"direction":"both","kind":"platform","kind_label":"shared platform that serves customer content","prefix":"188.114.96.0/20","provider":"Cloudflare","region":"","service":"CDN","source":"cloudflare"},"also":[],"note":"Official provider IP range of this IP. Context only, not a verdict."}},{"url":"http://meet-googlee7563454656.pages.dev","domain":"meet-googlee7563454656.pages.dev","company":"google","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-05-16T01:01:03.153187+00:00","uuid":"abcada72-c366-451c-915b-0e37f1494a54","ip":"188.114.97.3","country":"United States","asn":"13335","org":"Cloudflare, Inc.","cert":"WE1","malicious_google":false,"malicious_openphish":true,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":false,"service_range":{"best":{"direction":"both","kind":"platform","kind_label":"shared platform that serves customer content","prefix":"188.114.96.0/20","provider":"Cloudflare","region":"","service":"CDN","source":"cloudflare"},"also":[],"note":"Official provider IP range of this IP. Context only, not a verdict."}},{"url":"https://meet-googlee7823629056.pages.dev","domain":"meet-googlee7823629056.pages.dev","company":"google","date":"2026-10-13T05:30:07.546967+00:00","first_seen":"2026-05-16T01:00:55.487212+00:00","uuid":"9444a6f6-f3f9-4b8b-b6c4-0e7eac913ab6","ip":"172.66.45.9","country":"United States","asn":"13335","org":"Cloudflare, Inc.","cert":"WE1","malicious_google":true,"malicious_openphish":true,"malicious_phishtank":false,"malicious_tweetfeed":false,"malicious_urlscan":false,"service_range":{"best":{"direction":"both","kind":"platform","kind_label":"shared platform that serves customer content","prefix":"172.64.0.0/13","provider":"Cloudflare","region":"","service":"CDN","source":"cloudflare"},"also":[],"note":"Official provider IP range of this IP. Context only, not a verdict."}}]}"""  # noqa: E501
)

SEARCH_EMPTY = {"query": "no-such-host.example", "count": 0, "limit": 200, "results": []}

BASE_ROW = SEARCH_SINGLE["results"][0]
UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


class MockResponse:
    def __init__(self, payload, status_code=200, headers=None):
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


def _body(*rows):
    return {"query": "q", "count": len(rows), "limit": 200, "results": list(rows)}


def _row(**overrides):
    # Derived from the verbatim single-row capture above; used for the cases a live query cannot
    # produce on demand (sibling hosts, many rows, missing fields).
    row = copy.deepcopy(BASE_ROW)
    row.update(overrides)
    return row


def _query(attr_type="domain", value="binance-red-packet.vercel.app", uuid=UUID):
    # uuid="" keeps the required "uuid" key present (satisfies check_input_attribute) while being
    # falsy, mirroring a hover call that carries no usable reference uuid.
    return {"module": "phishunt", "attribute": {"type": attr_type, "value": value, "uuid": uuid}}


def _handle(payload, attr_type="domain", value="binance-red-packet.vercel.app", uuid=UUID):
    with patch.object(phishunt.requests, "get", return_value=MockResponse(payload)):
        return phishunt.handler(json.dumps(_query(attr_type, value, uuid)))


def _phishing_objects(result):
    return [o for o in result["results"]["Object"] if o["name"] == "phishing"]


def _values(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


def test_domain_hit_returns_phishing_object_and_search_link():
    result = _handle(SEARCH_SINGLE)
    objects = _phishing_objects(result)
    assert len(objects) == 1
    values = _values(objects[0])
    assert values["url"] == "https://binance-red-packet.vercel.app"
    assert values["hostname"] == "binance-red-packet.vercel.app"
    assert values["ip"] == "64.29.17.195"
    assert values["target"] == "binance"
    assert values["submission-time"].startswith("2026-03-27T13:01:15")
    assert values["internal-reference"] == "phishunt:f4255572-fb63-4810-baad-2051acebe7ca"
    # The detections are automated: nothing is flagged for IDS export and nothing is tagged.
    assert all(not a["to_ids"] for a in objects[0]["Attribute"] if a["object_relation"] in ("url", "hostname", "ip"))
    assert "Tag" not in objects[0]
    refs = objects[0]["ObjectReference"]
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in refs] == [(UUID, "related-to")]

    links = result["results"]["Attribute"]
    assert len(links) == 1
    assert links[0]["type"] == "link"
    assert links[0]["value"] == "https://phishunt.io/search/?q=binance-red-packet.vercel.app"
    assert "1 exact match" in links[0]["comment"]


def test_comment_carries_hosting_and_only_true_flags():
    comment = _phishing_objects(_handle(SEARCH_SINGLE))[0]["comment"]
    assert "hosting: AS16509, Amazon.com, Inc., United States" in comment
    assert "TLS issuer: WR1" in comment
    assert "last checked 2026-10-13T05:30:07" in comment
    assert "also flagged by OpenPhish" in comment
    # malicious_* false is "not flagged when checked", never a clean verdict: it must not be reported.
    for name in ("Google", "PhishTank", "TweetFeed", "urlscan"):
        assert name not in comment


def test_all_true_flags_are_listed():
    flags = {key: True for key in phishunt._FLAG_NAMES}
    comment = _phishing_objects(_handle(_body(_row(**flags))))[0]["comment"]
    assert "also flagged by Google Safe Browsing, OpenPhish, PhishTank, TweetFeed, urlscan.io" in comment


def test_service_range_is_reported_as_context_not_verdict():
    result = _handle(SEARCH_SERVICE_RANGE, value="googlel0gin.netlify.app")
    comment = _phishing_objects(result)[0]["comment"]
    assert "official range of AWS EC2 (eu-central-1, 63.176.0.0/12), rentable cloud hosting" in comment
    assert "(network context, not a verdict)" in comment


def test_exact_match_filters_out_other_hosts_of_a_substring_search():
    assert SEARCH_SUBSTRING["count"] > 1
    result = _handle(SEARCH_SUBSTRING, value="exoduswalletcc.pages.dev")
    objects = _phishing_objects(result)
    assert len(objects) == 1
    assert _values(objects[0])["hostname"] == "exoduswalletcc.pages.dev"


def test_exact_match_rejects_subdomains_and_lookalike_suffixes():
    body = _body(
        _row(domain="example.com", url="https://example.com/a", uuid="u1"),
        _row(domain="evil.example.com", url="https://evil.example.com/", uuid="u2"),
        _row(domain="notexample.com", url="https://notexample.com/", uuid="u3"),
        _row(domain="example.com.evil.net", url="https://example.com.evil.net/", uuid="u4"),
        _row(domain="www.example.com", url="https://www.example.com/", uuid="u5"),
    )
    objects = _phishing_objects(_handle(body, value="example.com"))
    assert [_values(o)["hostname"] for o in objects] == ["example.com"]


def test_one_host_with_several_urls_returns_one_object_per_url():
    body = _body(
        _row(url="https://example.com/a", domain="example.com", uuid="u1", first_seen="2026-10-01T00:00:00+00:00"),
        _row(url="https://example.com/b", domain="example.com", uuid="u2", first_seen="2026-10-03T00:00:00+00:00"),
    )
    objects = _phishing_objects(_handle(body, value="example.com"))
    # Most recently first seen first.
    assert [_values(o)["url"] for o in objects] == ["https://example.com/b", "https://example.com/a"]


def test_host_comparison_ignores_case_and_trailing_dot():
    body = _body(_row(domain="EXAMPLE.com", url="https://EXAMPLE.com/x"))
    assert len(_phishing_objects(_handle(body, value="Example.COM."))) == 1


def test_duplicate_rows_are_collapsed():
    row = _row(domain="example.com", url="https://example.com/a", uuid="u1")
    assert len(_phishing_objects(_handle(_body(row, copy.deepcopy(row)), value="example.com"))) == 1


@pytest.mark.parametrize(
    "value",
    [
        "https://Example.COM/login?next=/a",
        "http://user:secret@example.com:8080/path#frag",
        "example.com/login",
        "//example.com/login",
        "hxxps://example[.]com/login",
        "https://example.com.",
    ],
)
def test_url_attribute_is_reduced_to_its_host(value):
    body = _body(_row(domain="example.com", url="https://example.com/login"))
    with patch.object(phishunt.requests, "get", return_value=MockResponse(body)) as mock_get:
        result = phishunt.handler(json.dumps(_query("url", value)))
    assert mock_get.call_args.kwargs["params"]["q"] == "example.com"
    assert len(_phishing_objects(result)) == 1


def test_hostname_attribute_is_accepted():
    body = _body(_row(domain="example.com", url="https://example.com/login"))
    assert len(_phishing_objects(_handle(body, attr_type="hostname", value="example.com"))) == 1


def test_idn_host_is_queried_in_punycode():
    body = _body(_row(domain="xn--bcher-kva.example", url="https://xn--bcher-kva.example/"))
    with patch.object(phishunt.requests, "get", return_value=MockResponse(body)) as mock_get:
        result = phishunt.handler(json.dumps(_query("domain", "bücher.example")))
    assert mock_get.call_args.kwargs["params"]["q"] == "xn--bcher-kva.example"
    assert len(_phishing_objects(result)) == 1


def test_only_the_search_endpoint_is_called_with_the_result_cap():
    with patch.object(phishunt.requests, "get", return_value=MockResponse(SEARCH_SINGLE)) as mock_get:
        phishunt.handler(json.dumps(_query()))
    assert mock_get.call_count == 1
    assert mock_get.call_args.args[0] == "https://phishunt.io/api/v1/search.json"
    assert mock_get.call_args.kwargs["params"] == {"q": "binance-red-packet.vercel.app", "limit": 200}
    # The analyze endpoints log the query and enqueue unknown domains: never to be used.
    assert "analyze" not in phishunt.API_URL
    assert "analyze" not in phishunt.SEARCH_PAGE_URL


def test_rate_limit_is_retried_once_with_backoff():
    responses = [MockResponse(None, 429), MockResponse(SEARCH_SINGLE)]
    with patch.object(phishunt.requests, "get", side_effect=responses) as mock_get:
        with patch.object(phishunt.time, "sleep") as mock_sleep:
            result = phishunt.handler(json.dumps(_query()))
    assert mock_get.call_count == 2
    mock_sleep.assert_called_once_with(10)
    assert len(_phishing_objects(result)) == 1


@pytest.mark.parametrize(("retry_after", "expected"), [("3", 3), ("999", 15), ("0", 1), ("soon", 10)])
def test_rate_limit_backoff_honours_a_clamped_retry_after(retry_after, expected):
    responses = [MockResponse(None, 429, {"Retry-After": retry_after}), MockResponse(SEARCH_SINGLE)]
    with patch.object(phishunt.requests, "get", side_effect=responses):
        with patch.object(phishunt.time, "sleep") as mock_sleep:
            phishunt.handler(json.dumps(_query()))
    mock_sleep.assert_called_once_with(expected)


def test_rate_limit_twice_returns_a_clear_error():
    with patch.object(phishunt.requests, "get", return_value=MockResponse(None, 429)) as mock_get:
        with patch.object(phishunt.time, "sleep") as mock_sleep:
            result = phishunt.handler(json.dumps(_query()))
    assert mock_get.call_count == 2
    assert mock_sleep.call_count == 1
    assert "rate limit" in result["error"]
    assert "20 requests per 10 seconds" in result["error"]
    assert "results" not in result


def test_results_are_capped_at_25_objects_newest_first():
    rows = [
        _row(
            url=f"https://example.com/p{i}",
            domain="example.com",
            uuid=f"00000000-0000-4000-8000-{i:012d}",
            first_seen=f"2026-09-01T00:00:{i:02d}+00:00",
        )
        for i in range(30)
    ]
    result = _handle(_body(*reversed(rows)), value="example.com")
    objects = _phishing_objects(result)
    assert len(objects) == 25
    assert {_values(o)["url"] for o in objects} == {f"https://example.com/p{i}" for i in range(5, 30)}
    link = result["results"]["Attribute"][0]
    assert "30 exact match" in link["comment"]
    assert "25 most recently first seen" in link["comment"]


def test_capped_search_is_flagged_on_the_link():
    rows = [_row(domain=f"h{i}.example.com", url=f"https://h{i}.example.com/", uuid=f"u{i}") for i in range(199)]
    rows.append(_row(domain="example.com", url="https://example.com/", uuid="exact"))
    result = _handle(_body(*rows), value="example.com")
    assert len(_phishing_objects(result)) == 1
    assert "200-row cap" in result["results"]["Attribute"][0]["comment"]


def test_empty_result_returns_error():
    result = _handle(SEARCH_EMPTY, value="no-such-host.example")
    assert "No phishunt detection found for exactly no-such-host.example" in result["error"]
    assert "results" not in result


def test_only_partial_matches_return_error():
    result = _handle(SEARCH_SUBSTRING, value="pages.dev")
    assert "No phishunt detection found for exactly pages.dev" in result["error"]
    assert "partial match" in result["error"]
    assert "results" not in result


def test_capped_search_without_exact_match_mentions_the_cap():
    rows = [_row(domain=f"h{i}.example.com", url=f"https://h{i}.example.com/", uuid=f"u{i}") for i in range(200)]
    result = _handle(_body(*rows), value="example.com")
    assert "200-row cap" in result["error"]


def test_rows_with_only_url_and_domain_still_work():
    body = _body({"url": "https://example.com/x", "domain": "example.com"})
    objects = _phishing_objects(_handle(body, value="example.com"))
    assert _values(objects[0]) == {"url": "https://example.com/x", "hostname": "example.com"}
    assert objects[0]["comment"] == "phishunt detection"


def test_malformed_rows_are_skipped():
    body = _body(
        "not a row", None, {"domain": "example.com"}, {"url": "https://example.com/x"}, {"url": 5, "domain": 5}
    )
    result = _handle(body, value="example.com")
    assert "No phishunt detection found" in result["error"]


def test_invalid_json_returns_error():
    result = _handle(ValueError("not json"))
    assert result["error"] == "phishunt API returned an invalid JSON response."


@pytest.mark.parametrize("payload", [[], "text", None, {"results": None}, {"count": 0}, {"results": {"a": 1}}])
def test_unexpected_json_structure_returns_error(payload):
    result = _handle(payload)
    assert result["error"] == "phishunt API returned an unexpected response."


def test_http_error_mentions_status_code():
    with patch.object(phishunt.requests, "get", return_value=MockResponse(None, 500)):
        result = phishunt.handler(json.dumps(_query()))
    assert "500" in result["error"]


def test_requests_exception_is_reported():
    with patch.object(phishunt.requests, "get", side_effect=requests.exceptions.RequestException("boom")):
        result = phishunt.handler(json.dumps(_query()))
    assert "phishunt API request failed" in result["error"]


def test_unsupported_attribute_type_returns_error():
    result = phishunt.handler(json.dumps(_query(attr_type="ip-dst", value="192.0.2.1")))
    assert result["error"] == "Unsupported attribute type."


def test_missing_attribute_returns_error():
    result = phishunt.handler(json.dumps({"module": "phishunt"}))
    assert result["error"].startswith('This module requires an "attribute" field')


def test_handler_without_query_returns_false():
    assert phishunt.handler() is False


@pytest.mark.parametrize(("attr_type", "value"), [("url", "https://"), ("domain", "ab"), ("domain", "..")])
def test_unusable_host_returns_error_without_calling_the_api(attr_type, value):
    with patch.object(phishunt.requests, "get") as mock_get:
        result = phishunt.handler(json.dumps(_query(attr_type, value)))
    assert "error" in result
    mock_get.assert_not_called()


def test_hover_call_without_uuid_has_no_reference_to_the_attribute():
    result = _handle(SEARCH_SINGLE, uuid="")
    objects = _phishing_objects(result)
    assert len(objects) == 1
    assert not objects[0].get("ObjectReference")


def test_introspection_and_version():
    assert phishunt.introspection() == phishunt.mispattributes
    assert phishunt.mispattributes["input"] == ["domain", "hostname", "url"]
    info = phishunt.version()
    assert info["name"] == "phishunt Lookup"
    assert info["module-type"] == ["expansion", "hover"]
