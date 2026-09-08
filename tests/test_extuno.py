import json
from unittest.mock import MagicMock, patch

from misp_modules.modules.expansion import extuno

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"

MALICIOUS = {
    "store": "chrome",
    "ext_id": "bidgllfieacmghieipmhgabodmljimfh",
    "verdict": "malicious",
    "known_malicious": True,
    "catalog": {
        "threat_type": "Bundling Unwanted Software",
        "reason": "Listed by a public advisory.",
        "source_url": "https://example.com/report/",
        "still_active": False,
    },
    "scan": None,
}
UNKNOWN = {"store": "chrome", "verdict": "unknown", "known_malicious": False, "catalog": None, "scan": None}
ANALYSED = {
    "store": "chrome",
    "verdict": "review",
    "known_malicious": False,
    "risk_score": 72,
    "catalog": None,
    "scan": {"top_findings": [{"title": "Cookie access combined with broad host reach"}]},
}


class MockResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise extuno.requests.exceptions.HTTPError(response=self)


def _query(value, type_="text", config=None):
    attribute = {"type": type_, "value": value, "uuid": UUID}
    config = {"api_key": "extk_test"} if config is None else config
    return json.dumps({"module": "extuno", "attribute": attribute, "config": config})


def _answer(*payloads):
    """Return a requests.get replacement serving the given payloads in order."""
    queue = list(payloads)

    def _get(url, params=None, headers=None, timeout=None):
        return MockResponse(queue.pop(0) if queue else UNKNOWN)

    return _get


def test_a_catalog_listing_reports_the_threat_and_the_advisory_it_came_from():
    with patch.object(extuno.requests, "get", _answer(MALICIOUS)):
        results = extuno.handler(_query("chrome:bidgllfieacmghieipmhgabodmljimfh"))

    values = [a["value"] for a in results["results"]["Attribute"]]
    assert any("listed as malicious" in v and "Bundling Unwanted Software" in v for v in values)
    assert "https://example.com/report/" in values
    # An extension pulled from the store is no longer installable from it, which changes what an
    # analyst does next, so it is stated rather than left out.
    assert any("removed from the store" in v for v in values)


def test_an_analysis_verdict_carries_its_evidence():
    with patch.object(extuno.requests, "get", _answer(ANALYSED)):
        results = extuno.handler(_query("chrome:kbnfbcpkiaganjpcanopcgeoehkleeck"))

    values = [a["value"] for a in results["results"]["Attribute"]]
    assert any("verdict review" in v and "72/100" in v for v in values)
    assert any("Cookie access combined with broad host reach" in v for v in values)


def test_a_bare_webstore_id_is_also_looked_up_against_edge():
    """Chrome and Edge extension ids share one format, so a miss on Chrome is not an answer."""
    edge_hit = dict(MALICIOUS, store="edge")
    with patch.object(extuno.requests, "get", _answer(UNKNOWN, edge_hit)):
        results = extuno.handler(_query("bidgllfieacmghieipmhgabodmljimfh"))

    assert any("listed as malicious" in a["value"] for a in results["results"]["Attribute"])


def test_no_record_is_reported_as_a_result_rather_than_an_error():
    """"We looked and it is not on record" is an answer; an error would read as "we did not look"."""
    with patch.object(extuno.requests, "get", _answer(UNKNOWN)):
        results = extuno.handler(_query("chrome:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

    assert "error" not in results
    assert any("no record" in a["value"] for a in results["results"]["Attribute"])


def test_a_value_that_cannot_be_resolved_is_never_reported_as_clean():
    """The dangerous failure for a reputation module: a parse failure read as a clean verdict."""
    results = extuno.handler(_query("some free text"))
    assert "error" in results
    assert "results" not in results


def test_a_missing_api_key_is_reported_before_any_request_is_made():
    """No key means no lookup: the module must not query on the caller's behalf without one."""
    request = MagicMock(return_value=MockResponse(MALICIOUS))
    with patch.object(extuno.requests, "get", request):
        results = extuno.handler(_query("chrome:x", config={}))
    assert results["error"].startswith("An Extuno API key is required")
    request.assert_not_called()


def test_a_rejected_key_is_distinguished_from_an_absent_result():
    with patch.object(extuno.requests, "get", lambda *a, **k: MockResponse({}, 401)):
        results = extuno.handler(_query("chrome:bidgllfieacmghieipmhgabodmljimfh"))
    assert results["error"] == "Extuno rejected the API key."


def test_store_listing_urls_resolve_to_the_right_store_and_identifier():
    cases = {
        "https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm": (
            "chrome", "cjpalhdlnbpafiamejdnhcphjbkeiagm"),
        "https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/": ("firefox", "ublock-origin"),
        "https://marketplace.visualstudio.com/items?itemName=esbenp.prettier-vscode": (
            "vscode", "esbenp.prettier-vscode"),
        "https://open-vsx.org/extension/vscodevim/vim": ("openvsx", "vscodevim.vim"),
        "https://plugins.jetbrains.com/plugin/7495-intellijruby": ("jetbrains", "7495"),
        "https://marketplace.eclipse.org/content/checkstyle-plug": ("eclipse", "checkstyle-plug"),
        "https://www.npmjs.com/package/@types/node": ("npm", "@types/node"),
        "https://pypi.org/project/requests/": ("pypi", "requests"),
        "https://packagist.org/packages/monolog/monolog": ("composer", "monolog/monolog"),
        "https://wordpress.org/plugins/classic-editor/": ("wordpress", "classic-editor"),
    }
    for url, expected in cases.items():
        assert extuno._from_url(url) == expected, url
    assert extuno._from_url("https://example.com/whatever") is None
