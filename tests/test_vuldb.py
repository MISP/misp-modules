import json
from copy import deepcopy
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import vuldb

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
KEY = "private-test-key"
RECORD = {
    "entry": {"id": "67685", "title": "Bash privilege escalation", "timestamp": {"change": "1539168525"}},
    "advisory": {"date": "1411516800"},
    "source": {"cve": {"id": "CVE-2014-6271"}},
    "vulnerability": {"risk": {"name": "high"}},
}


def query(kind="vulnerability", value="CVE-2014-6271", config=None, **changes):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "Original", **changes},
            "config": {"apikey": KEY} if config is None else config,
        }
    )


def envelope(records=None, status="200"):
    return {"response": {"status": status}, "result": [deepcopy(RECORD)] if records is None else records}


def run(payload=None, http_status=200, **kwargs):
    response = Mock(status_code=http_status)
    response.json.return_value = envelope() if payload is None else payload
    with patch.object(vuldb.requests, "post", return_value=response) as post:
        result = vuldb.handler(query(**kwargs))
    return result, post


def values(obj):
    return {(a["object_relation"], str(a["value"])) for a in obj["Attribute"]}


def test_discovery():
    assert vuldb.handler(False) is False
    assert vuldb.introspection() == {"input": ["vulnerability", "cpe"], "format": "misp_standard"}
    assert vuldb.version()["config"] == vuldb.moduleconfig
    assert vuldb.version()["data-source"] == "external"
    assert vuldb.version()["module-type"] == ["expansion"]


def test_basic_documentation_response_and_request():
    result, post = run()
    post.assert_called_once_with(
        "https://vuldb.com/?api",
        data={"version": 3, "format": "json", "details": 0, "limit": 10, "advancedsearch": "cve:CVE-2014-6271"},
        headers={"X-VulDB-ApiKey": KEY},
        timeout=30,
        allow_redirects=False,
    )
    obj = result["results"]["Object"][0]
    assert obj["name"] == "vulnerability"
    assert {("id", "VULDB-67685"), ("id", "CVE-2014-6271"), ("summary", RECORD["entry"]["title"])} <= values(obj)
    assert ("references", "https://vuldb.com/?id.67685") in values(obj)
    assert ("published", "2014-09-24T00:00:00+00:00") in values(obj)
    assert ("modified", "2018-10-10T10:48:45+00:00") in values(obj)
    assert all(a["to_ids"] is False for a in obj["Attribute"])
    original = result["results"]["Attribute"][0]
    assert original["uuid"] == UUID
    assert original["comment"] == "Original"
    assert original["to_ids"] is True
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in obj["ObjectReference"]] == [(UUID, "related-to")]


@pytest.mark.parametrize("identifier", ["67685", "VULDB-67685", "vuldb-67685"])
def test_vuldb_id_request(identifier):
    _, post = run(value=identifier)
    assert post.call_args.kwargs["data"]["id"] == "67685"
    assert "advancedsearch" not in post.call_args.kwargs["data"]


@pytest.mark.parametrize("cpe", ["cpe:/a:gnu:bash:3.2", "cpe:2.3:a:gnu:bash:3.2:*:*:*:*:*:*:*"])
def test_cpe_request(cpe):
    result, post = run(kind="cpe", value=cpe)
    assert "results" in result
    assert post.call_args.kwargs["data"]["search"] == cpe


def test_detailed_response_and_zero_score():
    record = deepcopy(RECORD)
    record["entry"].update({"summary": "Long description", "details": {"impact": "Confidentiality"}})
    record["software"] = {"cpe23": ["cpe:2.3:a:gnu:bash:3.2:*:*:*:*:*:*:*"], "cpe": ["cpe:/a:gnu:bash:3.2"]}
    record["advisory"]["url"] = "https://example.org/advisory"
    record["vulnerability"]["cvss3"] = {
        "vuldb": {"basescore": "0.0", "basevector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"},
        "nvd": {"basescore": "9.8", "basevector": "other-vector"},
    }
    result, post = run(
        payload=envelope([record]), config={"apikey": KEY, "details": "true", "limit": "2", "timeout": "5"}
    )
    assert post.call_args.kwargs["data"]["details"] == 1
    assert post.call_args.kwargs["timeout"] == 5
    obj = result["results"]["Object"][0]
    assert {("description", "Long description"), ("impact", "Confidentiality"), ("cvss-score", "0.0")} <= values(obj)
    assert ("cvss-string", record["vulnerability"]["cvss3"]["vuldb"]["basevector"]) in values(obj)
    assert ("vulnerable-configuration", record["software"]["cpe23"][0]) in values(obj)
    assert ("references", "https://example.org/advisory") in values(obj)
    assert all("vuldb" in a["comment"] for a in obj["Attribute"] if a["object_relation"].startswith("cvss"))


def test_multiple_entries_missing_cve_and_deduplication():
    second = deepcopy(RECORD)
    second["entry"]["id"] = "67711"
    second.pop("source")
    result, _ = run(payload=envelope([RECORD, RECORD, second]))
    objects = result["results"]["Object"]
    assert len(objects) == 2
    assert ("id", "VULDB-67711") in values(objects[1])
    assert all(r["referenced_uuid"] == UUID for obj in objects for r in obj["ObjectReference"])


def test_local_limit_when_server_returns_too_many():
    result, post = run(payload=envelope([RECORD] * 3 + [{}]), config={"apikey": KEY, "limit": 1})
    assert len(result["results"]["Object"]) == 1
    assert post.call_args.kwargs["data"]["limit"] == 1


@pytest.mark.parametrize("unset", [None, "", " "])
def test_unset_optional_config_uses_defaults(unset):
    result, post = run(config={"apikey": KEY, "details": unset, "timeout": unset, "limit": unset})
    assert "results" in result
    assert post.call_args.kwargs["data"]["details"] == 0
    assert post.call_args.kwargs["data"]["limit"] == 10
    assert post.call_args.kwargs["timeout"] == 30


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"attribute": []}', '{"attribute": {}}'])
def test_bad_request(raw):
    with patch.object(vuldb.requests, "post") as post:
        assert "error" in vuldb.handler(raw)
    post.assert_not_called()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"config": {}},
        {"config": {"apikey": " "}},
        {"config": ["bad"]},
        {"config": {"apikey": KEY, "limit": 0}},
        {"config": {"apikey": KEY, "limit": 101}},
        {"config": {"apikey": KEY, "limit": 1.5}},
        {"config": {"apikey": KEY, "timeout": "NaN"}},
        {"config": {"apikey": KEY, "timeout": 121}},
        {"config": {"apikey": KEY, "timeout": 0}},
        {"config": {"apikey": KEY, "details": "yes"}},
        {"kind": "domain"},
        {"value": ""},
        {"value": 1},
        {"value": "CVE-2014-6271,product:other"},
        {"value": "VULDB-0"},
        {"kind": "cpe", "value": "bad"},
        {"uuid": "bad"},
        {"uuid": None},
    ],
)
def test_invalid_inputs_never_contact_vuldb(kwargs):
    result, post = run(**kwargs)
    assert "error" in result
    post.assert_not_called()


@pytest.mark.parametrize("status", [400, 401, 402, 403, 405, 409, 429, 500, 302])
def test_http_error_without_echoing_body(status):
    result, post = run(http_status=status, payload={"error": KEY})
    assert "error" in result
    assert KEY not in json.dumps(result)
    post.assert_called_once()


@pytest.mark.parametrize("status", ["400", "401", "402", "403", "405", "409", "429", "500"])
def test_api_error_even_with_http_200(status):
    payload = envelope(status=status)
    payload["response"]["error"] = KEY
    result, _ = run(payload=payload)
    assert "error" in result
    assert KEY not in json.dumps(result)


@pytest.mark.parametrize("status", [200, "200"])
def test_numeric_or_string_api_status(status):
    result, _ = run(payload=envelope(status=status))
    assert "results" in result


@pytest.mark.parametrize("payload,http_status", [(envelope([]), 200), (envelope(status="204"), 200), ({}, 204)])
def test_empty_results(payload, http_status):
    result, _ = run(payload=payload, http_status=http_status)
    assert result == {"results": {}}


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"response": []},
        {"response": {"status": 200}},
        envelope([{}]),
        envelope([None]),
        envelope([{"entry": {"id": "67685"}, "vulnerability": []}]),
        envelope([{"entry": {"id": "67685"}, "advisory": {"date": "invalid"}}]),
    ],
)
def test_malformed_responses(payload):
    result, _ = run(payload=payload)
    assert "error" in result


@pytest.mark.parametrize(
    "error", [ValueError(KEY), requests.exceptions.Timeout(KEY), requests.exceptions.ConnectionError(KEY)]
)
def test_transport_and_json_failures_are_redacted(error):
    response = Mock(status_code=200)
    response.json.side_effect = error
    with patch.object(vuldb.requests, "post", return_value=response) as post:
        if isinstance(error, requests.exceptions.RequestException):
            post.side_effect = error
        result = vuldb.handler(query())
    assert "error" in result
    assert KEY not in json.dumps(result)
    post.assert_called_once()


def test_cvss2_fallback_and_missing_dates():
    record = {"entry": {"id": "67685"}, "vulnerability": {"cvss2": {"nvd": {"basescore": "7.5", "basevector": "AV:N"}}}}
    result, _ = run(payload=envelope([record]))
    assert ("cvss-score", "7.5") in values(result["results"]["Object"][0])
    assert not any(relation in ("published", "modified") for relation, _ in values(result["results"]["Object"][0]))
