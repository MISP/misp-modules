import base64
import hashlib
import json
from importlib import resources
from unittest.mock import MagicMock, patch

import pytest
import requests
from pymisp import MISPObject

from misp_modules.modules.expansion import _lookyloo as shared
from misp_modules.modules.expansion import lookyloo, lookyloo_capture

SOURCE = "82383d84-3016-4d1c-902f-3de0533bfcec"
CAPTURE = "51de3086-4339-43fa-b290-f6d42d593619"
SECOND = "a86aedf1-b50e-47e6-80bc-06b4608bb52f"
URL = "https://example.org/login"
DIGEST = "a" * 128


def response(data, status=200):
    result = MagicMock(status_code=status)
    result.__enter__.return_value = result
    result.iter_content.return_value = [json.dumps(data).encode()]
    return result


def query(value="1.1.1.1", type_="ip-src", config=None):
    return json.dumps(
        {
            "attribute": {
                "type": type_,
                "value": value,
                "uuid": SOURCE,
                "to_ids": True,
                "comment": "Keep this",
                "Tag": [{"name": "tlp:clear"}],
            },
            "config": config or {},
        }
    )


def records(identifier=CAPTURE, nodes=None):
    record = {"capture_uuid": identifier, "start_timestamp": "2026-10-14T12:00:00+00:00", "title": "Example"}
    if nodes is not None:
        record["urlnodes"] = nodes
    return {"response": [record], "meta": {"limit": 20, "offset": 0, "total": 123}}


def objects(result, name):
    assert "error" not in result, result
    return [obj for obj in result["results"].get("Object", []) if obj["name"] == name]


def values(obj, relation):
    return [a["value"] for a in obj["Attribute"] if a["object_relation"] == relation]


def raw(obj):
    return {
        a["value"]: json.loads(base64.b64decode(a["data"]))
        for a in obj["Attribute"]
        if a["object_relation"] == "raw-data"
    }


def assert_valid(result):
    assert "error" not in result, result
    identifiers = {x["uuid"] for kind in ("Attribute", "Object") for x in result["results"].get(kind, [])}
    template = json.loads(resources.files("misp_modules").joinpath("data/lookyloo-capture/definition.json").read_text())
    for obj in result["results"].get("Object", []):
        loaded = MISPObject(
            obj["name"],
            strict=True,
            **({"misp_objects_template_custom": template} if obj["name"] == "lookyloo-capture" else {})
        )
        loaded.from_dict(**obj)
        loaded.to_json(strict=True)
        assert all(a["to_ids"] is False for a in obj["Attribute"])
        for ref in obj.get("ObjectReference", []):
            assert ref["referenced_uuid"] in identifiers
            assert ref["referenced_uuid"] != obj["uuid"]
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == SOURCE and source["to_ids"] is True
    assert source["comment"] == "Keep this" and source["Tag"] == [{"name": "tlp:clear"}]
    assert all(a["to_ids"] is False for a in result["results"]["Attribute"][1:])


@pytest.mark.parametrize(
    ("type_", "value", "endpoint", "key", "expected"),
    [
        ("ip-src", "1.1.1.1", "ip_info", "ip", "1.1.1.1"),
        ("ip-dst", "2001:4860:4860::8888", "ip_info", "ip", "2001:4860:4860::8888"),
        ("domain|ip", "example.org|1.1.1.1", "ip_info", "ip", "1.1.1.1"),
        ("domain", "example.org", "hostname_info", "hostname", "example.org"),
        ("hostname", "www.example.org", "hostname_info", "hostname", "www.example.org"),
        ("url", URL, "url_info", "url", URL),
        ("sha512", DIGEST.upper(), "hash_info", "body_hash", DIGEST),
        ("filename|sha512", "a|b|" + DIGEST, "hash_info", "body_hash", DIGEST),
    ],
)
def test_indicator_pivots_preserve_provenance(type_, value, endpoint, key, expected):
    with patch.object(requests.Session, "request", return_value=response(records())) as request:
        result = lookyloo.handler(query(value, type_, {"limit": "20", "offset": "0"}))
    assert_valid(result)
    capture = objects(result, "lookyloo-capture")[0]
    assert values(capture, "capture-id") == [CAPTURE]
    assert values(capture, "title") == ["Example"]
    assert raw(capture)[endpoint + ".json"]["meta"]["total"] == 123
    args, kwargs = request.call_args
    assert args == ("POST", shared.DEFAULT_URL + "/json/" + endpoint)
    assert kwargs["json"] == {
        key: expected,
        "limit": 20,
        "offset": 0,
        "cached_captures_only": True,
        "with_urls_occurrences": True,
    }
    assert kwargs["timeout"] == 30 and kwargs["allow_redirects"] is False


def test_favicon_search_and_duplicate_captures():
    with patch.object(requests.Session, "request", side_effect=[response(records()), response(records())]) as request:
        result = lookyloo.handler(query(DIGEST, "sha512", {"hash_lookup": "both"}))
    assert len(objects(result, "lookyloo-capture")) == 1
    assert request.call_args_list[1].args[1].endswith("/json/favicon_info")
    assert "with_urls_occurrences" not in request.call_args_list[1].kwargs["json"]
    assert_valid(result)


def test_hostname_nodes_keep_url_hash_relationship_and_deduplicate():
    record = records(nodes={"node1": {"url": URL, "hash": DIGEST}, "node2": {"url": URL, "hash": DIGEST}})
    record["response"] *= 2  # hostname_info can repeat a capture for multiple hostnodes
    with patch.object(requests.Session, "request", return_value=response(record)):
        result = lookyloo.handler(query("example.org", "hostname"))
    assert_valid(result)
    assert len(objects(result, "url")) == len(objects(result, "file")) == 1
    url, file = objects(result, "url")[0], objects(result, "file")[0]
    assert file["ObjectReference"][0]["referenced_uuid"] == url["uuid"]


def test_url_nodes_without_url_use_queried_url():
    with patch.object(requests.Session, "request", return_value=response(records(nodes={"n": {"hash": DIGEST}}))):
        result = lookyloo.handler(query(URL, "url"))
    assert values(objects(result, "url")[0], "url") == [URL]
    assert_valid(result)


def capture_responses(extra=None):
    result = {
        "info": {
            "uuid": CAPTURE,
            "url": URL,
            "capture_time": "2026-10-14T12:00:00+00:00",
            "title": "Example",
            "user_agent": "Browser",
            "referer": "https://example.org/",
        },
        "status": {"status_code": 1},
        "redirects": {"response": {"url": URL, "redirects": [URL, URL]}},
        "ips": {"response": {"ips": ["1.1.1.1", "2001:4860:4860::8888"]}},
        "hostnames": {"response": {"hostnames": ["example.org"]}},
        "urls": {"response": {"urls": [URL]}},
        "hashes": {"response": {"hashes": [DIGEST], "hashes_with_urls": {DIGEST: [URL]}}},
        "stats": {"total_unique_hostnames": 1},
        "modules": {"VirusTotal": {"verdict": "test"}},
        "comparables": {"root_url": URL, "final_url": URL},
    }
    return {**result, **(extra or {})}


def run_capture(config=None, extra=None, value=CAPTURE, type_="text"):
    replies = capture_responses(extra)

    def request(method, path, **kwargs):
        endpoint = path.rsplit("/", 1)[-1]
        data = replies[endpoint]
        if isinstance(data, Exception):
            raise data
        return data if isinstance(data, MagicMock) else response(data)

    with patch.object(requests.Session, "request", side_effect=request) as mocked:
        result = lookyloo_capture.handler(query(value, type_, config))
    return result, mocked


def test_capture_core_endpoints_and_resources():
    result, request = run_capture()
    assert_valid(result)
    obj = objects(result, "lookyloo-capture")[0]
    assert values(obj, "ip") == ["1.1.1.1", "2001:4860:4860::8888"]
    assert values(obj, "redirect") == [URL, URL]
    assert values(obj, "user-agent") == ["Browser"]
    assert len(values(obj, "download")) == 3
    assert raw(obj)["modules.json"] == {"VirusTotal": {"verdict": "test"}}
    assert len(objects(result, "image")) == 1
    assert {call.args[1].rsplit("/", 1)[-1] for call in request.call_args_list} == {"info", *shared.CORE_ENDPOINTS}
    hashes = next(call for call in request.call_args_list if call.args[1].endswith("/hashes"))
    assert hashes.kwargs["params"] == {"algorithm": "sha512", "hashes_only": 0}


def test_optional_endpoints_cookies_favicon_contacts_and_exports():
    favicon = b"icon bytes"
    digest = hashlib.sha512(favicon).hexdigest()
    replies = {name: {"some": "metadata"} for name in shared.EXTENDED_ENDPOINTS}
    replies.update(
        {
            "cookies": [
                {"name": "session", "value": "a", "secure": False, "httpOnly": True, "domain": ".example.org"},
                {"name": "empty", "value": ""},
            ],
            "favicons": {"response": {"favicons": {digest: base64.b64encode(favicon).decode()}}},
            "misp_export": [{"Event": {"info": "Export"}}],
            "takedown": ["abuse@example.org"],
        }
    )
    result, request = run_capture({name: "true" for name in shared.CAPTURE_CONFIG}, replies)
    assert_valid(result)
    cookie = objects(result, "cookie")[0]
    assert values(cookie, "secure") == [False]
    files = objects(result, "file")
    icon = next(obj for obj in files if values(obj, "sha512") == [digest])
    attachment = next(a for a in icon["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == favicon
    assert any(a["value"] == "empty=" for a in result["results"]["Attribute"])
    assert any(a["value"] == "abuse@example.org" for a in result["results"]["Attribute"])
    assert raw(objects(result, "lookyloo-capture")[0])["misp_export.json"] == replies["misp_export"]
    assert [call.args[0] for call in request.call_args_list].count("POST") == 1


@pytest.mark.parametrize("endpoint", ["modules", "cookies", "favicons", "storage_state"])
def test_missing_optional_data_preserves_other_enrichment(endpoint):
    result, _ = run_capture(
        {"include_cookies": True, "include_favicons": True, "include_extended": True},
        {
            endpoint: response({}, 404),
            "cookies": response({}, 404),
            "favicons": response({}, 404),
            **{x: response({}, 404) for x in shared.EXTENDED_ENDPOINTS},
        },
    )
    assert_valid(result)
    assert values(objects(result, "lookyloo-capture")[0], "error")
    assert objects(result, "file")


def test_capture_error_is_data_and_not_a_transport_failure():
    replies = capture_responses()
    replies["info"]["error"] = "Page failed after redirects"
    result, _ = run_capture(extra={"info": replies["info"]})
    assert "Page failed after redirects" in values(objects(result, "lookyloo-capture")[0], "error")
    assert_valid(result)


def test_limits_and_raw_disable():
    result, _ = run_capture({"max_items": 1, "include_raw": "false"})
    obj = objects(result, "lookyloo-capture")[0]
    assert len(values(obj, "ip")) == 1 and values(obj, "text")
    assert not raw(obj)
    assert_valid(result)


def test_lookup_enrichment_cap():
    result_data = records()
    result_data["response"].append(records(SECOND)["response"][0])
    with patch.object(requests.Session, "request", side_effect=[response(result_data), response({}, 404)]) as request:
        result = lookyloo.handler(query(config={"enrich_captures": True, "max_captures": 1}))
    assert request.call_count == 2
    assert len(objects(result, "lookyloo-capture")) == 2
    assert values(objects(result, "lookyloo-capture")[1], "text")


@pytest.mark.parametrize(
    "failure",
    [
        requests.Timeout("secret"),
        requests.ConnectionError("secret"),
        response({}, 429),
        response({}, 500),
        response({}, 302),
        response({"error": "secret"}),
    ],
)
def test_transport_failures_are_errors_without_leaking_details(failure):
    kwargs = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
    with patch.object(requests.Session, "request", **kwargs):
        result = lookyloo.handler(query())
    assert "error" in result and "secret" not in result["error"]


@pytest.mark.parametrize("body", [b"not json", b"null", b'"text"', b"[]"])
def test_invalid_lookup_responses(body):
    reply = response({})
    reply.iter_content.return_value = [body]
    with patch.object(requests.Session, "request", return_value=reply):
        assert "error" in lookyloo.handler(query())


def test_response_size_limit():
    with patch.object(shared, "MAX_RESPONSE_BYTES", 10), patch.object(
        requests.Session, "request", return_value=response(records())
    ):
        assert "exceeds" in lookyloo.handler(query())["error"]


@pytest.mark.parametrize(
    "config",
    [
        {"url": "https://user:pass@example.org"},
        {"url": "ftp://example.org"},
        {"url": "https://example.org?x=1"},
        {"timeout": "nan"},
        {"timeout": 0},
        {"timeout": []},
        {"max_items": -1},
        {"max_items": 1.5},
        {"limit": 0},
        {"offset": -1},
        {"include_raw": "invalid"},
        {"apikey": "a\nb"},
    ],
)
def test_bad_configuration_never_requests(config):
    with patch.object(requests.Session, "request") as request:
        assert "error" in lookyloo.handler(query(config=config))
    request.assert_not_called()


@pytest.mark.parametrize("value", ["{", "null", "[]", "{}", '{"attribute": []}'])
@pytest.mark.parametrize("module", [lookyloo, lookyloo_capture])
def test_invalid_input(value, module):
    assert "error" in module.handler(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://attacker.org/tree/" + CAPTURE,
        shared.DEFAULT_URL + "/tree/" + CAPTURE + "?seed=secret",
        shared.DEFAULT_URL + "/json/" + CAPTURE,
        "not-a-uuid",
    ],
)
def test_capture_link_validation(value):
    with patch.object(requests.Session, "request") as request:
        assert "error" in lookyloo_capture.handler(query(value, "link"))
    request.assert_not_called()


def test_custom_instance_with_path_and_authentication():
    base = "https://example.net/lookyloo"
    with patch.object(requests.Session, "request", return_value=response({"response": []})) as request:
        result = lookyloo.handler(query(config={"url": base, "apikey": "test-token"}))
    assert_valid(result)
    assert request.call_args.args[1] == base + "/json/ip_info"
    with shared.Client({"apikey": "test-token"}) as client:
        assert client.session.headers["Authorization"] == "test-token"
    assert shared.capture_uuid(base + "/tree/" + CAPTURE + "/", base) == CAPTURE


def test_favicon_integrity_failure_does_not_create_wrong_hash_file():
    result, _ = run_capture(
        {"include_favicons": True}, {"favicons": {"response": {"favicons": {"b" * 128: "aWNvbg=="}}}}
    )
    assert len(objects(result, "file")) == 1  # only the core resource hash
    assert values(objects(result, "lookyloo-capture")[0], "error")


def test_metadata_and_no_query():
    for module in (lookyloo, lookyloo_capture):
        assert module.handler() is False
        assert module.introspection()["format"] == "misp_standard"
        assert "url" in module.version()["config"]


@pytest.mark.parametrize(
    "endpoint,body",
    [
        ("hashes", {"response": None}),
        ("hashes", {"response": {"hashes": [], "hashes_with_urls": []}}),
        ("ips", {"response": []}),
        ("redirects", {"response": {}}),
    ],
)
def test_malformed_endpoint_data_keeps_other_results(endpoint, body):
    result, _ = run_capture(extra={endpoint: body})
    assert_valid(result)
    assert values(objects(result, "lookyloo-capture")[0], "error")
    assert objects(result, "url")
