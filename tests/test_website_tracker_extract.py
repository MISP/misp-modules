import base64
import json
from unittest.mock import patch

import pytest
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as server
from misp_modules.modules.expansion import website_tracker_extract as module

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


def run(content, filename=None, **metadata):
    attribute = {"type": "text", "value": content, "uuid": UUID, **metadata}
    if filename:
        attribute.update(type="attachment", value=filename, data=base64.b64encode(content.encode()).decode())
    return module.handler(json.dumps({"attribute": attribute}))


def objects(result):
    assert "error" not in result, result
    return {value(obj, "id"): obj for obj in result["results"]["Object"]}


def value(obj, relation):
    return next(a["value"] for a in obj["Attribute"] if a["object_relation"] == relation)


def evidence(obj):
    return json.loads(value(obj, "description"))


def har(*entries):
    return json.dumps({"log": {"version": "1.2", "entries": list(entries)}})


@pytest.mark.parametrize(
    "content,key",
    [
        ("ga('create', 'UA-12345678-1', 'auto');", "google-analytics:UA-12345678-1"),
        ("gtag('config','G-ABC1234567');", "google-analytics-4:G-ABC1234567"),
        ("https://www.googletagmanager.com/gtm.js?id=GTM-ABC1234", "google-tag-manager:GTM-ABC1234"),
        ("gtag('event', 'conversion', {'send_to': 'AW-123456789/label'});", "google-ads:AW-123456789"),
        ('data-ad-client="ca-pub-1234567890123456"', "google-adsense:pub-1234567890123456"),
        ("google_ad_client = 'pub-1234567890123456';", "google-adsense:pub-1234567890123456"),
        ("fbq('init', '123456789012345');", "meta-pixel:123456789012345"),
        ("window._hjSettings={hjid:1234567,hjsv:6};", "hotjar:1234567"),
        ('window._hjSettings={"hjid":"1234567"};', "hotjar:1234567"),
        ("ym(12345678, 'init', {});", "yandex-metrica:12345678"),
        ("new Ya.Metrika2({id:12345678});", "yandex-metrica:12345678"),
        ('})(window, document, "clarity", "script", "abc123defg");', "microsoft-clarity:abc123defg"),
        ('_linkedin_partner_id = "123456";', "linkedin-insight:123456"),
        ('ttq.load("CABC1234567890DEFGHI");', "tiktok-pixel:CABC1234567890DEFGHI"),
        ('amzn_assoc_tracking_id = "publisher-20";', "amazon-associates:publisher-20"),
        (
            '<meta content="AbC123_def456-789" name="google-site-verification">',
            "google-site-verification:AbC123_def456-789",
        ),
        (
            "<META NAME=facebook-domain-verification CONTENT=abc123def456789>",
            "facebook-domain-verification:abc123def456789",
        ),
        ('<meta name="msvalidate.01" content="1234567890ABCDEF">', "bing-site-verification:1234567890ABCDEF"),
    ],
)
def test_captured_html_and_scripts(content, key):
    found = objects(run(content))
    assert set(found) == {key}
    assert evidence(found[key])["identifier"] == key.split(":", 1)[1]


@pytest.mark.parametrize(
    "url,key",
    [
        ("https://www.facebook.com/tr/?id=12345678&ev=PageView", "meta-pixel:12345678"),
        ("//www.clarity.ms/tag/abc123defg", "microsoft-clarity:abc123defg"),
        ("https://mc.yandex.ru/watch/12345678", "yandex-metrica:12345678"),
        ("https://www.amazon.co.uk/dp/123?x=1&amp;tag=publisher%2D21", "amazon-associates:publisher-21"),
        ("https://www.awin1.com/cread.php?awinmid=999&awinaffid=12345&clickref=click-id", "awin:12345"),
        ("https://www.shareasale.com/r.cfm?b=2&u=12345&m=6789", "shareasale:12345"),
    ],
)
def test_provider_specific_url_fields(url, key):
    assert set(objects(run(f'<a href="{url}">link</a>'))) == {key}


def test_json_escaped_script_urls():
    content = r'{"pixel":"https:\/\/www.facebook.com\/tr\/?ev=PageView\u0026id=12345678"}'
    assert set(objects(run(content))) == {"meta-pixel:12345678"}


def test_no_false_matches_from_generic_or_wrong_provider_identifiers():
    content = """
    const id = 12345678; const pid = 12345678; const siteId = 42;
    const token = "prefixG-ABC1234567suffix";
    const invalid = "UA-12345678-12345";
    const oversize = "ca-pub-12345678901234567";
    https://example.org/?id=12345678&tag=publisher-20&awinaffid=12345
    https://amazon.com.example.org/?tag=publisher-20
    https://notamazon.com/?tag=publisher-20
    https://facebook.com.evil.example/tr/?id=12345678
    https://facebook.com/tracking/?id=12345678
    https://shareasale.com/r.cfmevil?u=12345678
    https://www.awin1.com/?awinmid=999&clickref=12345
    https://www.amazon.com/?gclid=abc123&fbclid=abc123
    """
    assert objects(run(content)) == {}


def test_locations_deduplication_and_input_metadata():
    content = "<!-- café -->\r\n  gtag('config', 'G-ABC1234567');\n'G-ABC1234567'"
    result = run(content, comment="Keep this", to_ids=True, Tag=[{"name": "tlp:clear"}])
    found = objects(result)
    assert len(found) == 1
    obj = found["google-analytics-4:G-ABC1234567"]
    locations = evidence(obj)["sources"]
    assert [(s["line"], s["column"]) for s in locations] == [(2, 19), (3, 2)]
    for source in locations:
        assert content[source["offset"] :].startswith("G-ABC1234567")
    original = result["results"]["Attribute"][0]
    assert original["comment"] == "Keep this"
    assert original["to_ids"] is True
    assert original["Tag"] == [{"name": "tlp:clear"}]
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in obj["ObjectReference"]] == [
        (UUID, "extracted-from")
    ]
    assert all(a["to_ids"] is False for a in obj["Attribute"])
    assert all(a["disable_correlation"] == (a["object_relation"] != "id") for a in obj["Attribute"])
    event = MISPEvent()
    event.from_dict(info="Extracted capture", **result["results"])
    assert event.objects[0].name == "tracking-id"


def test_numeric_identifiers_are_namespaced_by_provider():
    found = objects(run("fbq('init', '12345678'); ym(12345678, 'init', {});"))
    assert set(found) == {"meta-pixel:12345678", "yandex-metrica:12345678"}


def test_attachment_and_legacy_attachment_inputs():
    text = "UA-12345678-1"
    encoded = base64.b64encode(text.encode()).decode()
    modern = run(text, "capture.html")
    legacy = module.handler(json.dumps({"attachment": "capture.html", "data": encoded}))
    assert set(objects(modern)) == set(objects(legacy)) == {"google-analytics:UA-12345678-1"}
    assert modern["results"]["Attribute"][0]["data"] == encoded
    assert evidence(next(iter(objects(modern).values())))["sources"][0]["source"] == "capture.html"


def test_har_urls_post_data_and_embedded_base64_bodies():
    url = "https://publisher.example/page"
    body = "<script>gtag('config', 'G-ABC1234567');</script>"
    capture = har(
        {"request": {"url": "https://www.facebook.com/tr/?id=12345678"}},
        {"request": {"url": url}, "response": {"content": {"mimeType": "text/html", "text": body}}},
        {
            "request": {"url": "https://cdn.example/script.js"},
            "response": {
                "content": {
                    "mimeType": "application/javascript",
                    "encoding": "base64",
                    "text": base64.b64encode(body.encode()).decode(),
                }
            },
        },
        {
            "request": {
                "url": "https://www.facebook.com/tr/",
                "postData": {"mimeType": "application/x-www-form-urlencoded", "text": "ev=PageView&id=98765432"},
            }
        },
        {
            "request": {"url": "https://cdn.example/image.png"},
            "response": {"content": {"mimeType": "image/png", "text": "G-IGNORE1234"}},
        },
    )
    found = objects(run(capture, "capture.har"))
    assert set(found) == {"meta-pixel:12345678", "meta-pixel:98765432", "google-analytics-4:G-ABC1234567"}
    locations = evidence(found["google-analytics-4:G-ABC1234567"])["sources"]
    assert [s["source"] for s in locations] == [
        "log.entries[1].response.content.text",
        "log.entries[2].response.content.text",
    ]
    assert locations[0]["url"] == url
    assert body[locations[0]["offset"] :].startswith("G-ABC1234567")
    assert value(found["google-analytics-4:G-ABC1234567"], "url") == "https://cdn.example/script.js"
    post = evidence(found["meta-pixel:98765432"])["sources"][0]
    assert post["source"] == "log.entries[3].request.postData.text"
    assert (post["line"], post["column"], post["offset"]) == (1, 1, 0)
    assert set(objects(run(capture))) == set(found)  # HAR detection without a filename


@pytest.mark.parametrize("scheme", ["http", "https", "HTTP", "HTTPS", "hTtP", "hTtPs"])
def test_har_resource_url_preserves_case_insensitive_http_schemes(scheme):
    url = f"{scheme}://cdn.example/Script.js?key=MixedCase"
    capture = har(
        {
            "request": {"url": url},
            "response": {"content": {"mimeType": "application/javascript", "text": "gtag('config', 'G-ABC1234567');"}},
        }
    )
    obj = objects(run(capture, "capture.har"))["google-analytics-4:G-ABC1234567"]
    assert value(obj, "url") == url
    assert evidence(obj)["sources"][0]["url"] == url


@pytest.mark.parametrize("scheme", ["ftp", "file", "javascript"])
def test_har_resource_url_attribute_excludes_other_schemes(scheme):
    url = f"{scheme}://cdn.example/script.js"
    capture = har({"request": {"url": url}, "response": {"content": {"text": "G-ABC1234567"}}})
    obj = objects(run(capture, "capture.har"))["google-analytics-4:G-ABC1234567"]
    assert not any(a["object_relation"] == "url" for a in obj["Attribute"])
    assert evidence(obj)["sources"][0]["url"] == url


def test_post_body_does_not_claim_an_id_only_present_in_the_url():
    capture = har({"request": {"url": "https://www.facebook.com/tr/?id=12345678", "postData": {"text": "ev=PageView"}}})
    obj = objects(run(capture))["meta-pixel:12345678"]
    assert len(evidence(obj)["sources"]) == 1


@pytest.mark.parametrize(
    "query", ["bad json", "null", "[]", "{}", '{"attribute": []}', '{"attribute": {"type":"url"}}']
)
def test_malformed_requests(query):
    assert "error" in module.handler(query)


@pytest.mark.parametrize(
    "change", [{"uuid": "bad"}, {"uuid": None}, {"uuid": []}, {"value": 42}, {"type": []}, {"value": ""}]
)
def test_invalid_attributes(change):
    attribute = {"type": "text", "value": "UA-12345678-1", "uuid": UUID, **change}
    assert "error" in module.handler(json.dumps({"attribute": attribute}))


@pytest.mark.parametrize("data", [None, [], "not base64!", "////=", "a==="])
def test_invalid_attachment_data(data):
    attribute = {"type": "attachment", "value": "capture.har", "uuid": UUID, "data": data}
    assert "error" in module.handler(json.dumps({"attribute": attribute}))


@pytest.mark.parametrize(
    "capture",
    [
        "{bad",
        "{}",
        "[]",
        '{"log": null}',
        '{"log":{"entries":{}}}',
        har(None),
        har({"request": []}),
        har({"request": {"url": 42}}),
        har({"response": {"content": []}}),
        har({"response": {"content": {"text": 42}}}),
        har({"response": {"content": {"text": "bad", "encoding": "base64"}}}),
        har({"response": {"content": {"text": "abc", "encoding": "gzip"}}}),
    ],
)
def test_malformed_har(capture):
    assert "error" in run(capture, "capture.har")


def test_limits_fail_explicitly_without_partial_findings():
    with patch.object(module, "MAX_BYTES", 10):
        assert "error" in run("x" * 11)
        assert "error" in run("x" * 11, "capture.html")
    with patch.object(module, "MAX_ENTRIES", 1):
        assert "error" in run(har({}, {}))
    with patch.object(module, "MAX_DECODED_BYTES", 20):
        assert "error" in run(har({"response": {"content": {"text": "x" * 21}}}))
    with patch.object(module, "MAX_OCCURRENCES", 1):
        assert "error" in run("G-ABC1234567 G-ABC1234567")


def test_offline_no_match_and_discovery():
    with patch("socket.socket", side_effect=AssertionError("No network access allowed")):
        assert objects(run("<script>gtag('config', 'G-ABC1234567');</script>"))
        assert objects(run("<html>No trackers</html>")) == {}
    assert module.handler() is False
    assert module.introspection() == {"input": ["attachment", "text"], "format": "misp_standard"}
    assert module.version()["config"] == []


class TestWebsiteTrackerHTTP(AsyncHTTPTestCase):
    def get_app(self):
        handlers = {"website_tracker_extract": module, "type:website_tracker_extract": "expansion"}
        self.handlers_patch = patch.object(server, "MODULES_HANDLERS", handlers)
        self.handlers_patch.start()
        self.addCleanup(self.handlers_patch.stop)
        return Application([(r"/query", server.QueryModule), (r"/modules", server.ListModules)])

    def test_discovery_and_capture_expansion(self):
        discovery = json.loads(self.fetch("/modules").body)
        assert discovery[0]["name"] == "website_tracker_extract"
        assert discovery[0]["mispattributes"]["format"] == "misp_standard"
        body = {
            "module": "website_tracker_extract",
            "attribute": {
                "type": "attachment",
                "uuid": UUID,
                "value": "capture.har",
                "data": (
                    base64.b64encode(
                        har({"request": {"url": "https://facebook.com/tr/?id=12345678"}}).encode()
                    ).decode()
                ),
            },
        }
        response = self.fetch("/query", method="POST", body=json.dumps(body))
        assert response.code == 200
        obj = objects(json.loads(response.body))["meta-pixel:12345678"]
        assert obj["ObjectReference"][0]["referenced_uuid"] == UUID
