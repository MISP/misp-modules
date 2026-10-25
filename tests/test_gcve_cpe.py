import copy
import json
from unittest.mock import Mock, patch

import pytest
import requests
from pymisp import MISPEvent

from misp_modules.modules.expansion import gcve_cpe as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
CPE = "cpe:2.3:a:example:application:1.0:*:*:*:*:*:*:*"
ENTRY = {
    "id": 42,
    "cpe_uri": CPE,
    "cpe_name_id": "e041fb7b-4ca9-40b2-ae10-302d7740ea47",
    "title": "Example Application 1.0",
    "part": "a",
    "version": "1.0",
    "deprecated": True,
    "deprecated_by": "cpe:2.3:a:example:application:2.0:*:*:*:*:*:*:*",
    "notes": "Catalog notes",
    "purl_mappings": [{"purl": "pkg:pypi/example@1.0", "source": "purl2cpe"}],
    "vulnerability_references": [
        {
            "id": 1,
            "vulnerability_source": "CVE",
            "vulnerability_id": "CVE-2026-1234",
            "cpe_applicability": "vulnerable",
            "rationale": "Affected in the default configuration",
            "approved_at": "2026-10-01T00:00:00",
        }
    ],
}


def query(value=CPE, kind="cpe", config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "Original"},
            "config": config,
        }
    )


def response(items=None, pages=1, status=200):
    result = Mock(status_code=status)
    result.json.return_value = {"items": [] if items is None else items, "total_pages": pages}
    return result


def run(replies=None, **kwargs):
    with patch.object(module.requests, "get", side_effect=replies or [response([ENTRY])]) as get:
        result = module.handler(query(**kwargs))
    return result, get


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj, relation):
    return [a["value"] for a in obj["Attribute"] if a["object_relation"] == relation]


def test_discovery_contract():
    assert module.handler(False) is False
    assert module.introspection() == {"input": ["cpe"], "format": "misp_standard"}
    assert module.version()["config"] == module.moduleconfig
    assert "expansion" in module.version()["module-type"]


def test_catalog_and_vulnerability_output_preserves_source_and_relationships():
    result, get = run()
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == UUID
    assert source["to_ids"] is True
    assert source["comment"] == "Original"
    annotation = objects(result, "annotation")[0]
    assert json.loads(values(annotation, "text")[0]) == ENTRY
    assert values(annotation, "ref") == ["https://cpe.gcve.eu/cpes/42"]
    vuln = objects(result, "vulnerability")[0]
    assert values(vuln, "id") == ["CVE-2026-1234"]
    assert values(vuln, "vulnerable-configuration") == [CPE]
    assert values(vuln, "description") == [ENTRY["vulnerability_references"][0]["rationale"]]
    assert values(vuln, "state") == ["cpe_applicability=vulnerable"]
    for obj in result["results"]["Object"]:
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])
        assert all(attr["to_ids"] is False for attr in obj["Attribute"])
    assert any(ref["referenced_uuid"] == annotation["uuid"] for ref in vuln["ObjectReference"])
    event = MISPEvent()
    event.from_dict(info="GCVE CPE expansion", **result["results"])
    assert len(event.objects) == 2
    get.assert_called_once_with(
        "https://cpe.gcve.eu/api/cpes",
        params={"q": CPE, "page": 1, "per_page": 100},
        timeout=30,
        allow_redirects=False,
    )


@pytest.mark.parametrize("status", sorted(module.APPLICABILITY - {"vulnerable"}))
@pytest.mark.parametrize("identifier", ["GCVE-1-2026-1234", "GHSA-abcd-efgh-ijkl"])
def test_non_vulnerable_states_never_assert_vulnerability(status, identifier):
    entry = copy.deepcopy(ENTRY)
    entry["vulnerability_references"][0].update(cpe_applicability=status, vulnerability_id=identifier)
    result, _ = run([response([entry])])
    vuln = objects(result, "vulnerability")[0]
    assert values(vuln, "id") == [identifier]
    assert values(vuln, "state") == [f"cpe_applicability={status}"]
    assert values(vuln, "vulnerable-configuration") == []


def test_repeated_reference_is_deduplicated():
    entry = copy.deepcopy(ENTRY)
    entry["vulnerability_references"] *= 2
    result, _ = run([response([entry])])
    assert len(objects(result, "vulnerability")) == 1


def test_empty_reference_list_still_returns_catalog_metadata():
    result, _ = run([response([dict(ENTRY, vulnerability_references=[])])])
    assert len(objects(result, "annotation")) == 1
    assert not objects(result, "vulnerability")


def test_search_ignores_partial_and_wildcard_matches_then_paginates():
    other = dict(ENTRY, cpe_uri=CPE.replace(":1.0:", ":1.0.1:"))
    result, get = run([response([other], pages=2), response([ENTRY], pages=2)])
    assert json.loads(values(objects(result, "annotation")[0], "text")[0])["cpe_uri"] == CPE
    assert get.call_count == 2
    assert get.call_args.kwargs["params"]["page"] == 2


def test_page_limit_is_reported_instead_of_claiming_no_match():
    result, get = run([response([], pages=3)] * 2, config={"max_pages": "2"})
    assert "max_pages" in result["error"]
    assert get.call_count == 2


@pytest.mark.parametrize("items,pages", [([], 0), ([], 1), ([dict(ENTRY, cpe_uri=CPE + "suffix")], 1)])
def test_no_exact_match_returns_only_the_original_attribute(items, pages):
    result, get = run([response(items, pages=pages)])
    assert result["results"]["Object"] == []
    assert len(result["results"]["Attribute"]) == 1
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == UUID
    assert source["value"] == CPE
    assert source["to_ids"] is True
    assert source["comment"] == "Original"
    get.assert_called_once()


@pytest.mark.parametrize(
    "value",
    [
        "cpe:/a:example:application:1.0",
        r"cpe:2.3:a:example:application\:pro:1.0:*:*:*:*:*:*:*",
        r"cpe:2.3:a:example:application\\:1.0:*:*:*:*:*:*:*",
    ],
)
def test_uri_binding_and_escaped_colon_are_sent_as_query_parameters(value):
    result, get = run([response([dict(ENTRY, cpe_uri=value)])], value=value)
    assert "results" in result
    assert get.call_args.kwargs["params"]["q"] == value


def test_custom_instance_and_timeout():
    result, get = run(config={"api_url": "https://example.org/cpe/", "timeout": "12.5", "max_pages": "1"})
    assert get.call_args.args[0] == "https://example.org/cpe/api/cpes"
    assert get.call_args.kwargs["timeout"] == 12.5
    assert values(objects(result, "annotation")[0], "ref") == ["https://example.org/cpe/cpes/42"]


@pytest.mark.parametrize("unset", [None, "", "   "])
def test_unset_config_values_use_defaults(unset):
    _, get = run(config={key: unset for key in module.moduleconfig})
    assert get.call_args.args[0] == "https://cpe.gcve.eu/api/cpes"
    assert get.call_args.kwargs["timeout"] == 30


@pytest.mark.parametrize("raw", [None, "{", "[]", "null", "{}", '{"attribute": []}', '{"attribute": {"type": "cpe"}}'])
def test_invalid_request_never_calls_api(raw):
    with patch.object(module.requests, "get") as get:
        assert "error" in module.handler(raw)
    get.assert_not_called()


@pytest.mark.parametrize("value", ["", "  ", 123, [], "example", "cpe:2.3:a:example", "cpe:/x:example:app"])
def test_invalid_cpe_never_calls_api(value):
    result, get = run(value=value)
    assert "error" in result
    get.assert_not_called()


def test_unsupported_attribute_type_never_calls_api():
    result, get = run(kind="text")
    assert "error" in result
    get.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [
        [],
        False,
        {"timeout": 0},
        {"timeout": 121},
        {"timeout": "NaN"},
        {"timeout": "bad"},
        {"max_pages": 0},
        {"max_pages": 21},
        {"max_pages": "bad"},
        {"max_pages": True},
        {"max_pages": 1.5},
        {"api_url": "file:///tmp/test"},
        {"api_url": "https://"},
        {"api_url": "https://example.org/?a=b"},
    ],
)
def test_invalid_config_never_calls_api(config):
    result, get = run(config=config)
    assert "error" in result
    get.assert_not_called()


@pytest.mark.parametrize("status", [301, 400, 401, 403, 404, 429, 500])
def test_http_errors_are_actionable(status):
    result, _ = run([response(status=status)])
    assert str(status) in result["error"]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_network_failures_do_not_expose_request_details(failure):
    result, _ = run([failure("sensitive request detail")])
    assert "error" in result
    assert "sensitive" not in result["error"]


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"items": [], "total_pages": -1},
        {"items": [ENTRY], "total_pages": 0},
        {"items": [], "total_pages": True},
        {"items": {}, "total_pages": 1},
        {"items": [None], "total_pages": 1},
        {"items": [{"cpe_uri": 123}], "total_pages": 1},
    ],
)
def test_invalid_search_response_is_reported(payload):
    reply = response()
    reply.json.return_value = payload
    result, _ = run([reply])
    assert "error" in result


def test_invalid_json_is_reported():
    reply = response()
    reply.json.side_effect = ValueError("invalid json")
    result, _ = run([reply])
    assert "invalid JSON" in result["error"]


@pytest.mark.parametrize(
    "change",
    [
        {"id": "42"},
        {"id": True},
        {"vulnerability_references": {}},
        {"vulnerability_references": [None]},
        {"vulnerability_references": [{"vulnerability_id": "CVE-2026-1234", "cpe_applicability": "unknown"}]},
    ],
)
def test_invalid_exact_entry_is_reported(change):
    result, _ = run([response([dict(ENTRY, **change)])])
    assert "error" in result
