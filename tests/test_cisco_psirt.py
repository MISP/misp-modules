import copy
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.expansion import cisco_psirt as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
CVE, BUG, ADVISORY = "CVE-2022-20714", "CSCvy48962", "cisco-sa-lsplus-Z6AQEOjk"
CLIENT_ID, SECRET, TOKEN = "synthetic-client", "synthetic-secret", "synthetic-token"
CONFIG = {"client_id": CLIENT_ID, "client_secret": SECRET}
ROW = {
    "advisoryId": ADVISORY,
    "advisoryTitle": "Cisco IOS XR Software Denial of Service Vulnerability",
    "cves": [CVE],
    "bugIDs": [BUG],
    "cwe": ["CWE-20"],
    "ipsSignatures": ["12345"],
    "productNames": ["Cisco IOS XR Software "],
    "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/" + ADVISORY,
    "csafUrl": (
        "https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/"
        + ADVISORY
        + "/csaf/"
        + ADVISORY
        + ".json"
    ),
    "cvssBaseScore": "8.6",
    "firstPublished": "2022-04-13T23:00:00",
    "lastUpdated": "2022-04-29T04:28:53Z",
    "status": "Final",
    "version": "1.1",
    "sir": "High",
    "summary": "<p>A <strong>synthetic</strong> vulnerability &amp; its effects.</p><script>DO_NOT_RETAIN</script>",
}


def query(value=CVE, kind="vulnerability", **config):
    return {
        "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "Original context"},
        "config": {**CONFIG, **config},
    }


def objects(result, name):
    assert "error" not in result, result
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj, relation):
    return [attr["value"] for attr in obj["Attribute"] if attr["object_relation"] == relation]


def contexts(result):
    return [json.loads(values(obj, "text")[0]) for obj in objects(result, "annotation")]


class FakeAPI:
    """Exercise real requests preparation/authentication without contacting Cisco."""

    def __init__(self):
        self.calls = []
        self.replies = {}

    def send(self, adapter, request, **kwargs):
        self.calls.append((request, kwargs))
        url = request.url.split("?", 1)[0]
        reply = self.replies.get(url)
        if isinstance(reply, list):
            reply = reply.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if reply is None:
            if url == module.TOKEN_URL:
                reply = {"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600}
            elif url.startswith(module.API_URL + "/"):
                reply = {"advisories": [copy.deepcopy(ROW)]}
            else:
                raise AssertionError("Unexpected URL: " + url)
        status, data = reply if isinstance(reply, tuple) else (200, reply)
        response = requests.Response()
        response.status_code, response.url, response.request = status, request.url, request
        response._content = data if isinstance(data, bytes) else json.dumps(data).encode()
        response._content_consumed = True
        response.headers["Content-Type"] = "application/json"
        if 300 <= status < 400:
            response.headers["Location"] = "https://unexpected.example/collect"
        return response


@pytest.fixture(autouse=True)
def clear_tokens():
    module._TOKENS.clear()
    yield
    module._TOKENS.clear()


@pytest.fixture
def api():
    fake = FakeAPI()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


@pytest.mark.parametrize(
    "value,kind,path",
    [
        (CVE, "vulnerability", "cve/" + CVE),
        (CVE.lower(), "text", "cve/" + CVE),
        (ADVISORY, "text", "advisory/" + ADVISORY),
        (BUG.lower(), "text", "bugid/" + BUG),
    ],
)
def test_current_oauth_flow_identifier_endpoints_and_source_preservation(api, value, kind, path):
    request = query(value, kind, timeout="8")
    original = copy.deepcopy(request)
    result = module.handler(json.dumps(request))
    assert result["results"]["Attribute"] == [original["attribute"]] and request == original
    assert len(api.calls) == 2
    auth, get = [call[0] for call in api.calls]
    assert auth.method == "POST" and auth.url == module.TOKEN_URL
    assert parse_qs(auth.body) == {
        "client_id": [CLIENT_ID],
        "client_secret": [SECRET],
        "grant_type": ["client_credentials"],
    }
    assert auth.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert "Authorization" not in auth.headers
    assert get.method == "GET" and get.url.split("?")[0] == module.API_URL + "/" + path
    assert parse_qs(urlsplit(get.url).query) == {"summaryDetails": ["true"], "productNames": ["true"]}
    assert get.headers["Authorization"] == "Bearer " + TOKEN and get.headers["Accept"] == "application/json"
    assert all(kwargs["timeout"] == 8 and kwargs["verify"] and kwargs["stream"] for _, kwargs in api.calls)
    assert all(CLIENT_ID not in call.url and SECRET not in call.url for call, _ in api.calls)
    event = MISPEvent()
    event.from_dict(info="Synthetic Cisco PSIRT response", **result["results"])
    assert len(event.objects) == 3
    for obj in result["results"]["Object"]:
        assert all(attr["to_ids"] is False for attr in obj["Attribute"])
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])


def test_advisory_fields_map_to_existing_misp_objects_with_utc_and_csaf(api):
    result = module.handler(json.dumps(query()))
    vulnerability = objects(result, "vulnerability")[0]
    assert values(vulnerability, "id") == [ADVISORY, CVE]
    assert values(vulnerability, "summary") == [ROW["advisoryTitle"]]
    assert values(vulnerability, "description") == ["A synthetic vulnerability & its effects."]
    assert float(values(vulnerability, "cvss-score")[0]) == 8.6
    assert values(vulnerability, "published") == ["2022-04-13T23:00:00+00:00"]
    assert values(vulnerability, "modified") == ["2022-04-29T04:28:53+00:00"]
    assert values(vulnerability, "references") == [ROW["publicationUrl"], ROW["csafUrl"]]
    assert values(vulnerability, "state") == ["Final"]
    context = contexts(result)[0]
    assert context["bugIDs"] == [BUG] and context["cwe"] == ["CWE-20"]
    assert context["productNames"] == ["Cisco IOS XR Software"] and context["sir"] == "High"
    assert context["ipsSignatures"] == ["12345"] and context["version"] == "1.1"
    assert any(
        ref["referenced_uuid"] == vulnerability["uuid"] for ref in objects(result, "annotation")[0]["ObjectReference"]
    )
    assert not values(vulnerability, "vulnerable-configuration")
    assert "DO_NOT_RETAIN" not in json.dumps(result) and "<strong>" not in json.dumps(result)


def test_scalar_schema_fields_numeric_score_and_zero_are_supported(api):
    row = {
        **ROW,
        "cves": CVE,
        "bugIDs": BUG,
        "cwe": "CWE-20",
        "productNames": "Cisco IOS XR Software",
        "cvssBaseScore": 0,
        "version": 1.1,
    }
    api.replies[module.API_URL + "/cve/" + CVE] = {"advisories": [row]}
    result = module.handler(json.dumps(query()))
    assert float(values(objects(result, "vulnerability")[0], "cvss-score")[0]) == 0
    assert contexts(result)[0]["version"] == "1.1"


def test_multiple_cves_belong_to_one_advisory_and_multiple_advisories_are_retained(api):
    row = {**ROW, "cves": [CVE, "CVE-2022-20715"]}
    api.replies[module.API_URL + "/cve/" + CVE] = {"advisories": [row, {**ROW, "advisoryId": "cisco-sa-other-ABC"}]}
    result = module.handler(json.dumps(query()))
    assert len(objects(result, "vulnerability")) == 2 and result["summary"]["count"] == 2
    assert values(objects(result, "vulnerability")[0], "id") == [ADVISORY, CVE, "CVE-2022-20715"]


@pytest.mark.parametrize("field", ["publicationUrl", "csafUrl"])
@pytest.mark.parametrize("placeholder", ["NA", "N/A", "na", " NA ", " n/a ", "", None])
def test_unavailable_optional_url_keeps_advisory_and_other_results(api, field, placeholder):
    api.replies[module.API_URL + "/cve/" + CVE] = {
        "advisories": [{**ROW, field: placeholder}, {**ROW, "advisoryId": "cisco-sa-second-ABC"}]
    }
    result = module.handler(json.dumps(query()))
    vulnerabilities = objects(result, "vulnerability")
    assert len(vulnerabilities) == result["summary"]["count"] == 2
    assert result["results"]["Attribute"] == [query()["attribute"]]
    assert field not in contexts(result)[0]
    remaining_field = "csafUrl" if field == "publicationUrl" else "publicationUrl"
    assert values(vulnerabilities[0], "references") == [ROW[remaining_field]]
    assert values(vulnerabilities[1], "references") == [ROW["publicationUrl"], ROW["csafUrl"]]


def test_advisory_with_both_url_placeholders_still_imports(api):
    api.replies[module.API_URL + "/cve/" + CVE] = {"advisories": [{**ROW, "publicationUrl": "NA", "csafUrl": "N/A"}]}
    result = module.handler(json.dumps(query()))
    vulnerability = objects(result, "vulnerability")[0]
    assert values(vulnerability, "id") == [ADVISORY, CVE]
    assert not values(vulnerability, "references")
    assert "publicationUrl" not in contexts(result)[0] and "csafUrl" not in contexts(result)[0]


def test_partial_bug_matches_are_filtered_and_not_claimed_as_related(api):
    api.replies[module.API_URL + "/bugid/" + BUG] = {
        "advisories": [ROW, {**ROW, "advisoryId": "cisco-sa-unrelated-ABC", "bugIDs": ["CSCvy48963"]}]
    }
    result = module.handler(json.dumps(query(BUG, "text")))
    assert len(objects(result, "vulnerability")) == 1
    assert result["summary"]["returned"] == 2 and result["summary"]["filtered_partial_matches"] == 1
    assert "cisco-sa-unrelated-ABC" not in json.dumps(result)


def test_only_partial_bug_matches_produce_an_explicit_empty_result(api):
    api.replies[module.API_URL + "/bugid/" + BUG] = {"advisories": [{**ROW, "bugIDs": ["CSCvy48963"]}]}
    result = module.handler(json.dumps(query(BUG, "text")))
    assert not objects(result, "vulnerability") and result["summary"]["status"] == "not_found"
    assert result["summary"]["filtered_partial_matches"] == 1


@pytest.mark.parametrize(
    "value,kind,error_code",
    [
        (CVE, "vulnerability", "NO_DATA_FOUND"),
        (BUG, "text", "NO_DATA_FOUND"),
        (ADVISORY, "text", "ADVISORYID_NOT_FOUND"),
    ],
)
def test_documented_missing_codes_are_not_api_failures(api, value, kind, error_code):
    path, identifier = module._identifier(value)
    api.replies[module.API_URL + f"/{path}/{identifier}"] = (404, {"errorCode": error_code, "errorMessage": SECRET})
    result = module.handler(json.dumps(query(value, kind)))
    assert result["results"]["Attribute"] == [query(value, kind)["attribute"]]
    assert result["summary"]["status"] == "not_found" and result["summary"]["count"] == 0
    assert len(objects(result, "annotation")) == 1 and SECRET not in json.dumps(result)


def test_empty_advisory_collection_is_explicit_not_found(api):
    api.replies[module.API_URL + "/cve/" + CVE] = {"advisories": []}
    assert module.handler(json.dumps(query()))["summary"]["status"] == "not_found"


def test_advisory_cap_is_explicit_and_has_no_extra_requests(api):
    api.replies[module.API_URL + "/cve/" + CVE] = {"advisories": [ROW, {**ROW, "advisoryId": "cisco-sa-second-ABC"}]}
    result = module.handler(json.dumps(query(max_advisories="1")))
    assert len(objects(result, "vulnerability")) == 1
    assert result["summary"]["count"] == 1 and result["summary"]["returned"] == 2
    assert result["summary"]["truncated"] is True and result["warnings"] and len(api.calls) == 2


@pytest.mark.parametrize("score", [None, "", "NA", "N/A"])
def test_missing_cvss_is_not_fabricated_as_zero(api, score):
    api.replies[module.API_URL + "/cve/" + CVE] = {"advisories": [{**ROW, "cvssBaseScore": score}]}
    result = module.handler(json.dumps(query()))
    assert not values(objects(result, "vulnerability")[0], "cvss-score")


@pytest.mark.parametrize("status", [302, 400, 401, 403, 406, 429, 500, 503])
def test_api_failures_return_safe_errors_without_retry_or_redirect(api, status):
    api.replies[module.API_URL + "/cve/" + CVE] = (status, {"errorMessage": SECRET})
    result = module.handler(json.dumps(query()))
    assert "error" in result and "results" not in result and str(status) in result["error"]
    assert len(api.calls) == 2 and SECRET not in json.dumps(result) and TOKEN not in json.dumps(result)


@pytest.mark.parametrize(
    "reply",
    [
        (401, {"error": SECRET}),
        (302, {}),
        b"<html>bad gateway</html>",
        {},
        {"access_token": TOKEN, "token_type": "basic", "expires_in": 3600},
        {"access_token": "bad\r\nheader", "token_type": "Bearer", "expires_in": 3600},
        *({"access_token": TOKEN, "token_type": "Bearer", "expires_in": value} for value in [0, None, True, "3600"]),
        requests.Timeout(SECRET),
    ],
)
def test_token_failures_never_query_api_or_echo_credentials(api, reply):
    api.replies[module.TOKEN_URL] = reply
    result = module.handler(json.dumps(query()))
    assert "error" in result and len(api.calls) == 1 and not module._TOKENS
    assert all(value not in json.dumps(result) for value in (CLIENT_ID, SECRET, TOKEN))


@pytest.mark.parametrize(
    "reply",
    [
        b"bad JSON",
        (200, []),
        {"errorCode": "NO_DATA_FOUND"},
        {},
        {"advisories": None},
        {"advisories": [None]},
        {"advisories": [{}]},
        {"advisories": [{**ROW, "cves": ["CVE-2022-99999"]}]},
        (404, {"errorCode": "UNKNOWN_ERROR"}),
        requests.ConnectionError(SECRET),
    ],
)
def test_malformed_api_data_is_not_an_empty_success(api, reply):
    api.replies[module.API_URL + "/cve/" + CVE] = reply
    result = module.handler(json.dumps(query()))
    assert "error" in result and "results" not in result and SECRET not in json.dumps(result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("advisoryId", "CVE-2022-20714"),
        ("advisoryTitle", []),
        ("cves", [None]),
        ("bugIDs", ["not-a-bug"]),
        ("cwe", ["CWE-evil"]),
        ("productNames", {}),
        ("publicationUrl", "https://user:secret@example.org/advisory"),
        ("csafUrl", "javascript:alert(1)"),
        ("firstPublished", "not-a-date"),
        ("lastUpdated", []),
        ("cvssBaseScore", True),
        ("cvssBaseScore", -1),
        ("cvssBaseScore", 11),
        ("cvssBaseScore", "NaN"),
        ("cvssBaseScore", float("inf")),
        ("summary", {}),
        ("version", {}),
    ],
)
def test_invalid_advisory_fields_fail_without_partial_objects(api, field, value):
    api.replies[module.API_URL + "/cve/" + CVE] = {"advisories": [{**ROW, field: value}]}
    result = module.handler(json.dumps(query()))
    assert "error" in result and "results" not in result


def test_wrong_advisory_is_rejected(api):
    api.replies[module.API_URL + "/advisory/" + ADVISORY] = {
        "advisories": [{**ROW, "advisoryId": "cisco-sa-other-ABC"}]
    }
    assert "error" in module.handler(json.dumps(query(ADVISORY, "text")))


def test_large_stream_is_rejected_and_closed(api):
    api.replies[module.API_URL + "/cve/" + CVE] = b" " * (module.MAX_RESPONSE_BYTES + 1)
    with patch.object(requests.Response, "close") as close:
        result = module.handler(json.dumps(query()))
    assert "2 MiB" in result["error"] and close.call_count == 2


@pytest.mark.parametrize(
    "value,kind",
    [
        ("", "vulnerability"),
        ("CVE-2022-123", "vulnerability"),
        ("CVE-２０２２-20714", "vulnerability"),
        ("CVE-2022-20714/path", "text"),
        ("not an identifier", "text"),
        (None, "text"),
        ([], "text"),
        (BUG, "vulnerability"),
        (ADVISORY, "vulnerability"),
        (CVE, "ip-src"),
        ("cisco-sa-bad?x=y", "text"),
        ("CSCvy4896", "text"),
    ],
)
def test_invalid_identifiers_do_not_contact_cisco(api, value, kind):
    assert "error" in module.handler(json.dumps(query(value, kind))) and not api.calls


@pytest.mark.parametrize(
    "config",
    [
        {"client_id": ""},
        {"client_secret": None},
        {"client_id": []},
        {"client_secret": "bad\n"},
        {"max_advisories": 0},
        {"max_advisories": 101},
        {"max_advisories": True},
        {"timeout": "nan"},
        {"timeout": 121},
        {"timeout": 1.5},
    ],
)
def test_invalid_configuration_does_not_contact_cisco(api, config):
    assert "error" in module.handler(json.dumps(query(**config))) and not api.calls


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}', '{"config": []}'])
def test_invalid_envelopes(api, raw):
    assert "error" in module.handler(raw) and not api.calls


def test_invalid_uuid_does_not_contact_cisco(api):
    request = query()
    request["attribute"]["uuid"] = "bad"
    assert "error" in module.handler(json.dumps(request)) and not api.calls


def test_tokens_are_reused_until_near_expiry_and_isolated_by_credentials(api):
    api.replies[module.TOKEN_URL] = [
        {"token_type": "Bearer", "access_token": token, "expires_in": 3600}
        for token in (TOKEN, "other-token", "refreshed-token")
    ]
    with patch.object(module.time, "monotonic", return_value=100):
        for secret in (SECRET, SECRET, "another-secret"):
            assert "error" not in module.handler(json.dumps(query(client_secret=secret)))
    assert [call.headers["Authorization"] for call, _ in api.calls if call.method == "GET"] == [
        "Bearer " + TOKEN,
        "Bearer " + TOKEN,
        "Bearer other-token",
    ]
    assert len(module._TOKENS) == 2 and all(isinstance(key, bytes) for key in module._TOKENS)
    with patch.object(module.time, "monotonic", return_value=3640):
        assert "error" not in module.handler(json.dumps(query()))
    assert sum(call.url == module.TOKEN_URL for call, _ in api.calls) == 3


def test_concurrent_lookups_share_a_token(api):
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(module.handler, [json.dumps(query())] * 4))
    assert all("error" not in result for result in results)
    assert sum(call.url == module.TOKEN_URL for call, _ in api.calls) == 1


@pytest.mark.parametrize("status,evicted", [(401, True), (429, False)])
def test_rejected_tokens_are_evicted_but_rate_limits_keep_valid_tokens(api, status, evicted):
    assert "error" not in module.handler(json.dumps(query()))
    api.replies[module.API_URL + "/cve/" + CVE] = (status, {})
    assert "error" in module.handler(json.dumps(query()))
    assert bool(module._TOKENS) is not evicted and len(api.calls) == 3


def test_auth_does_not_use_netrc_and_keeps_ca_and_proxy_configuration(api):
    with patch("requests.sessions.get_netrc_auth", return_value=("wrong-user", "wrong-password")):
        assert "error" not in module.handler(json.dumps(query()))
    auth, get = [call[0] for call in api.calls]
    assert "Authorization" not in auth.headers and get.headers["Authorization"] == "Bearer " + TOKEN
    assert dict(api.calls[1][1]["proxies"]) == requests.utils.get_environ_proxies(module.API_URL)
    assert api.calls[1][1]["verify"]


def test_sessions_and_responses_close_on_success(api):
    with (
        patch.object(requests.Session, "close") as close_session,
        patch.object(requests.Response, "close") as close_response,
    ):
        assert "error" not in module.handler(json.dumps(query()))
    assert close_session.call_count == 1 and close_response.call_count == 2


def test_discovery_contract():
    assert module.handler(False) is False
    assert module.introspection() == {"input": ["vulnerability", "text"], "format": "misp_standard"}
    assert module.version()["config"] == module.moduleconfig and module.version()["name"] == "Cisco PSIRT"


class TestPsirtHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"cisco_psirt": module, "type:cisco_psirt": "expansion"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "cisco_psirt"
        api = FakeAPI()
        with patch.object(
            requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: api.send(adapter, request, **kw)
        ):
            response = self.fetch(
                "/query",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"module": "cisco_psirt", **query()}),
            )
        assert response.code == 200 and len(objects(json.loads(response.body), "vulnerability")) == 1
