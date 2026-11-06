import functools
import http.client
import io
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
import urllib3
from pymisp import MISPEvent

from misp_modules.modules.expansion import darkeye


class FakeHTTP:
    """Offline HTTP layer: the real requests.Session runs and the adapter returns canned replies."""

    def __init__(self):
        self.routes = {}
        self.calls = []

    def get(self, url, status=200, json=None, headers=None, body=None):
        self.routes[url] = (status, json, headers or {}, body)

    def _respond(self, adapter, request):
        self.calls.append(SimpleNamespace(request=request))
        url = request.url.split("?", 1)[0]
        if url not in self.routes:
            raise requests.ConnectionError("No synthetic reply for " + url)
        status, payload, headers, body = self.routes[url]
        if isinstance(body, Exception):
            raise body
        headers = {"Content-Type": "application/json", **headers}
        message = http.client.HTTPMessage()
        for name, value in headers.items():
            message[name] = value
        raw = urllib3.HTTPResponse(
            body=io.BytesIO(b"" if payload is None else json.dumps(payload).encode()),
            headers=headers,
            status=status,
            preload_content=False,
            original_response=SimpleNamespace(msg=message, isclosed=lambda: True, close=lambda: None),
        )
        return adapter.build_response(request, raw)

    def activate(self, func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            self.routes, self.calls = {}, []

            def send(adapter, request, **send_kwargs):
                return self._respond(adapter, request)

            with patch.object(requests.adapters.HTTPAdapter, "send", send):
                return func(*args, **kwargs)

        return wrapper


fake_http = FakeHTTP()

HIBR_KEY = "synthetic-hibr-token"
BH_KEY = "synthetic-bh-token"
DOMAIN = "example.test"
HIBR_URL = darkeye.HIBR_URL + DOMAIN
BH_URL = darkeye.BH_URL


def query(value=DOMAIN, attribute_type="domain", **config):
    return json.dumps(
        {
            "attribute": {"uuid": "3b6e0390-d17d-419d-bd28-a65dd8d07126", "type": attribute_type, "value": value},
            "config": config,
        }
    )


def hibr_page(items=None, next_page=False, documented=False):
    items = (
        items
        if items is not None
        else [{"id_source": "1", "leak_type": "traditional_breach", "post_title": "Synthetic listing"}]
    )
    if documented:
        return {"results": items, "pagination": {"has_next": next_page}, "success": True}
    return {"sources": items, "has_next": next_page}


def bh_page(items=None):
    return {
        "ransomware": {"results": items or [], "total": len(items or [])},
        "breaches": [],
        "leads": [],
        "stealers": [],
    }


def report(result):
    assert "error" not in result
    attributes = result["results"]["Attribute"]
    assert len(attributes) == 1
    assert attributes[0]["type"] == "text"
    assert attributes[0]["to_ids"] is False
    event = MISPEvent()
    event.from_dict(info="Synthetic test", **result["results"])
    assert len(event.attributes) == 1
    return json.loads(attributes[0]["value"])


@fake_http.activate
def test_both_products_share_one_report_with_metadata_only():
    sensitive = {
        "description": "DO_NOT_RETAIN",
        "post_url": "https://invalid.test/DO_NOT_RETAIN",
        "Identities Found": 999,
        "password": "DO_NOT_RETAIN",
        "hibr": {"data": "DO_NOT_RETAIN"},
    }
    item = {"id_source": "1", "leak_type": "ransomware_leak", "post_title": "Synthetic", "website": DOMAIN, **sensitive}
    fake_http.get(HIBR_URL, json=hibr_page([item]))
    fake_http.get(BH_URL, json=bh_page([item]))
    output = darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY, breachhouse_api_key=BH_KEY))
    r = report(output)
    assert r["provider"] == "DarkEye" and r["count"] == 2
    assert r["status"] == "complete"
    assert {row["product"] for row in r["records"]} == {darkeye.HIBR, darkeye.BH}
    assert {row["category"] for row in r["records"]} == {"ransomware"}
    encoded = json.dumps(output)
    assert all(x not in encoded for x in ["DO_NOT_RETAIN", HIBR_KEY, BH_KEY, "Identities Found"])
    assert [x.request.headers["Authorization"] for x in fake_http.calls] == ["Bearer " + HIBR_KEY, "Bearer " + BH_KEY]


@pytest.mark.parametrize("product", ["hibr", "bh"])
@fake_http.activate
def test_either_key_works_independently(product):
    config = {"haveibeenransom_api_key": HIBR_KEY} if product == "hibr" else {"breachhouse_api_key": BH_KEY}
    fake_http.get(HIBR_URL if product == "hibr" else BH_URL, json=hibr_page([]) if product == "hibr" else bh_page())
    r = report(darkeye.handler(query(**config)))
    assert r["count"] == 0 and r["status"] == "complete"
    assert len(fake_http.calls) == 1


@pytest.mark.parametrize("failed", ["hibr", "bh"])
@pytest.mark.parametrize("status", [401, 403, 429, 500])
@fake_http.activate
def test_failure_of_one_product_keeps_the_other(failed, status):
    fake_http.get(HIBR_URL, status=status if failed == "hibr" else 200, json=hibr_page())
    fake_http.get(BH_URL, status=status if failed == "bh" else 200, json=bh_page([{"id": "2", "website": DOMAIN}]))
    r = report(darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY, breachhouse_api_key=BH_KEY)))
    assert r["count"] == 1 and r["status"] == "partial"
    assert len(r["errors"]) == 1


@fake_http.activate
def test_all_failed_is_not_an_empty_success():
    fake_http.get(HIBR_URL, status=401)
    fake_http.get(BH_URL, status=429)
    r = darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY, breachhouse_api_key=BH_KEY))
    assert "error" in r and "results" not in r


@fake_http.activate
def test_pagination_empty_pages_dedup_and_documented_shape():
    fake_http.get(HIBR_URL, json=hibr_page([], True))
    fake_http.get(HIBR_URL + "/2", json=hibr_page(next_page=True, documented=True))
    fake_http.get(HIBR_URL + "/3", json=hibr_page(documented=True))
    r = report(darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY)))
    assert r["count"] == 1 and not r["truncated"]
    assert len(fake_http.calls) == 3


@fake_http.activate
def test_page_failure_does_not_silently_return_an_incomplete_product():
    fake_http.get(HIBR_URL, json=hibr_page(next_page=True))
    fake_http.get(HIBR_URL + "/2", status=500)
    fake_http.get(BH_URL, json=bh_page())
    r = report(darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY, breachhouse_api_key=BH_KEY)))
    assert r["status"] == "partial" and r["count"] == 0
    assert r["products"] == [darkeye.BH]
    assert r["errors"][0]["product"] == darkeye.HIBR


@pytest.mark.parametrize("next_page,expected", [(False, False), (True, True)])
@fake_http.activate
def test_exact_record_limit_and_no_unneeded_page(next_page, expected):
    fake_http.get(HIBR_URL, json=hibr_page(next_page=next_page))
    r = report(darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY, max_records=1)))
    assert r["count"] == 1 and r["truncated"] == expected
    assert len(fake_http.calls) == 1


@fake_http.activate
def test_page_limit_marks_truncation():
    fake_http.get(HIBR_URL, json=hibr_page([], True))
    r = report(darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY, max_pages=1)))
    assert r["count"] == 0 and r["status"] == "partial" and r["truncated"]


@pytest.mark.parametrize(
    "website,title,match",
    [
        (DOMAIN, "", True),
        ("https://sub.example.test/path", "", True),
        ("notexample.test", "example.test", False),
        ("example.test.evil.test", "", False),
        ("", "mail.example.test listing", True),
        ("", "notexample.test listing", False),
        ("", "example.test.other.test", False),
        ("", "my-example.test", False),
        ("", "example.test-backup", False),
        ("", "example.test.", True),
    ],
)
@fake_http.activate
def test_domain_boundary_prevents_false_attribution(website, title, match):
    fake_http.get(BH_URL, json=bh_page([{"id": "a", "website": website, "post_title": title}]))
    r = report(darkeye.handler(query(breachhouse_api_key=BH_KEY)))
    assert r["count"] == int(match)


@fake_http.activate
def test_bh_categories_dedup_and_limits():
    item = {"id": "a", "website": DOMAIN}
    body = {source: {"results": [item, item, {**item, "id": "b"}], "total": 7} for source in darkeye.BH_CATEGORIES}
    fake_http.get(BH_URL, json=body)
    r = report(darkeye.handler(query(breachhouse_api_key=BH_KEY, max_records=7)))
    assert r["count"] == 7 and r["truncated"]
    assert {x["category"] for x in r["records"]} == {"ransomware", "breach", "leads", "stealer"}


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"sources": {}, "has_next": False},
        {"sources": [], "has_next": "false"},
        {"success": False},
        {"error": "synthetic secret"},
        {"sources": [None], "has_next": False},
        {"sources": [{}], "has_next": False},
    ],
)
@fake_http.activate
def test_malformed_hibr_fails_instead_of_reporting_clean(body):
    fake_http.get(HIBR_URL, json=body)
    assert "error" in darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY))


@pytest.mark.parametrize(
    "body", [{}, {"ransomware": []}, {"ransomware": {"results": []}, "breaches": None, "leads": [], "stealers": []}]
)
@fake_http.activate
def test_malformed_bh_is_not_an_empty_result(body):
    fake_http.get(BH_URL, json=body)
    assert "error" in darkeye.handler(query(breachhouse_api_key=BH_KEY))


@pytest.mark.parametrize(
    "domain",
    [
        "https://example.test",
        "127.0.0.1",
        "*.example.test",
        "example.test/path",
        "bad_.test",
        "-bad.test",
        "bad-.test",
        "one",
        "a" * 64 + ".test",
        "x.test?key=x",
    ],
)
@fake_http.activate
def test_invalid_targets_never_leave_the_process(domain):
    assert "error" in darkeye.handler(query(value=domain, haveibeenransom_api_key=HIBR_KEY))
    assert len(fake_http.calls) == 0


@fake_http.activate
def test_hostname_and_idna_are_normalized():
    url = darkeye.HIBR_URL + "xn--bcher-kva.test"
    fake_http.get(url, json=hibr_page([]))
    r = report(
        darkeye.handler(query(value="BÜCHER.test.", attribute_type="hostname", haveibeenransom_api_key=HIBR_KEY))
    )
    assert r["domain"] == "xn--bcher-kva.test"


@pytest.mark.parametrize(
    "config",
    [
        {},
        {"haveibeenransom_api_key": " "},
        {"haveibeenransom_api_key": []},
        {"haveibeenransom_api_key": "x" + chr(13) + chr(10) + "Injected: x"},
        {"haveibeenransom_api_key": HIBR_KEY, "timeout": "nan"},
        {"haveibeenransom_api_key": HIBR_KEY, "max_pages": 0},
        {"haveibeenransom_api_key": HIBR_KEY, "limit": 201},
    ],
)
@fake_http.activate
def test_missing_keys_and_invalid_config_never_send_requests(config):
    assert "error" in darkeye.handler(query(**config))
    assert len(fake_http.calls) == 0


@fake_http.activate
def test_redirect_and_exception_messages_cannot_leak_credentials():
    fake_http.get(HIBR_URL, status=302, headers={"Location": "https://invalid.test/collect"})
    r = darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY))
    assert "302" in r["error"] and len(fake_http.calls) == 1
    fake_http.get(HIBR_URL, body=requests.ConnectionError(HIBR_KEY))
    r = darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY))
    assert HIBR_KEY not in json.dumps(r)
    assert "Request failed" in r["error"]


@fake_http.activate
def test_sessions_are_isolated_and_closed_on_failure():
    created = []
    real_session = requests.Session

    class TrackingSession(real_session):
        def __init__(self):
            super().__init__()
            self.closed = False
            created.append(self)

        def close(self):
            self.closed = True
            super().close()

    fake_http.get(HIBR_URL, status=500, headers={"Set-Cookie": "sensitive=synthetic; Domain=.test"})
    fake_http.get(BH_URL, json=bh_page())
    with patch.object(darkeye.requests, "Session", TrackingSession):
        report(darkeye.handler(query(haveibeenransom_api_key=HIBR_KEY, breachhouse_api_key=BH_KEY)))
    assert len(created) == 2 and all(x.closed and not x.trust_env for x in created)
    assert "Cookie" not in fake_http.calls[1].request.headers


def test_interface_and_invalid_request():
    assert darkeye.handler() is False
    assert darkeye.version()["data-source"] == "external"
    assert darkeye.version()["module-type"] == ["expansion"]
    assert darkeye.introspection()["format"] == "misp_standard"
    for value in ["bad", "[]", "null", "{}", query(attribute_type="ip-src")]:
        assert "error" in darkeye.handler(value)
