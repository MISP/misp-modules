import copy
import json
from unittest.mock import Mock, patch

import pytest

from misp_modules import is_valid_module
from misp_modules.modules.expansion import opencti

ATTRIBUTE = {"type": "domain", "value": "example.org", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
CONFIG = {"url": "https://cti.example.test/opencti/", "token": "test-token"}
NODE = {
    "id": "cfd9ef37-90a4-4465-b215-e4f3e4e8acbe",
    "standard_id": "domain-name--a7f2ef9c-4d50-4f5f-a079-ebc3fd24d82e",
    "entity_type": "Domain-Name",
    "observable_value": "example.org",
    "x_opencti_description": "Observed infrastructure; association does not imply maliciousness.",
    "x_opencti_score": 0,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-02T00:00:00Z",
    "createdBy": {"name": "Example Research"},
    "objectLabel": [{"value": "research"}],
    "objectMarking": [
        {"definition_type": "TLP", "definition": "TLP:AMBER+STRICT"},
        {"definition_type": "statement", "definition": "For research only"},
    ],
    "externalReferences": {
        "edges": [
            {"node": {"source_name": "research", "external_id": "R-12", "url": "https://source.test/report"}},
            {"node": {"source_name": "duplicate", "url": "https://source.test/report"}},
            {"node": {"source_name": "unsafe", "url": "javascript:alert(1)"}},
        ]
    },
}


def query(attribute=None, config=None):
    return json.dumps(
        {"attribute": ATTRIBUTE if attribute is None else attribute, "config": CONFIG if config is None else config}
    )


def response(nodes=None, next_page=False):
    return Mock(
        status_code=200,
        json=Mock(
            return_value={
                "data": {
                    "stixCyberObservables": {
                        "edges": [{"node": node} for node in ([NODE] if nodes is None else nodes)],
                        "pageInfo": {"hasNextPage": next_page},
                    }
                }
            }
        ),
    )


def lookup(payload=None, request=None):
    with patch.object(opencti.requests, "post", return_value=response() if payload is None else payload) as post:
        result = opencti.handler(query() if request is None else request)
    return result, post


def test_exact_lookup_and_misp_output():
    result, post = lookup()
    post.assert_called_once_with(
        "https://cti.example.test/opencti/graphql",
        json={
            "query": opencti.QUERY,
            "variables": {
                "types": ["Domain-Name"],
                "first": 20,
                "filters": {
                    "mode": "and",
                    "filters": [
                        {
                            "key": ["value"],
                            "values": ["example.org"],
                            "operator": "eq",
                            "mode": "or",
                        }
                    ],
                    "filterGroups": [],
                },
            },
        },
        headers={"Authorization": "Bearer test-token", "Accept": "application/json"},
        timeout=30,
        allow_redirects=False,
    )
    attributes = result["results"]["Attribute"]
    summary = next(a["value"] for a in attributes if a["type"] == "text")
    for detail in (
        "Score: 0",
        "Example Research",
        "research",
        "For research only",
        "R-12",
        NODE["standard_id"],
        NODE["x_opencti_description"],
    ):
        assert detail in summary
    links = [a["value"] for a in attributes if a["type"] == "link"]
    assert links == [
        f"https://cti.example.test/opencti/dashboard/observations/observables/{NODE['id']}",
        "https://source.test/report",
    ]
    assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in attributes)
    assert all({tag["name"] for tag in a["Tag"]} == {"tlp:amber+strict"} for a in attributes)
    assert "pseudo-open source" not in json.dumps(result)
    assert "test-token" not in json.dumps(result)


@pytest.mark.parametrize(
    "kind,algorithm,length",
    [("md5", "MD5", 32), ("sha1", "SHA-1", 40), ("sha256", "SHA-256", 64), ("sha512", "SHA-512", 128)],
)
@pytest.mark.parametrize("composite", [False, True])
def test_hash_matches_the_requested_algorithm(kind, algorithm, length, composite):
    digest = "a" * length
    attribute = {
        **ATTRIBUTE,
        "type": f"filename|{kind}" if composite else kind,
        "value": f"file|name.exe|{digest.upper()}" if composite else digest.upper(),
    }
    node = {
        **NODE,
        "entity_type": "StixFile",
        "observable_value": "file.exe",
        "hashes": [{"algorithm": algorithm, "hash": digest}],
    }
    wrong = {**node, "id": "another-file", "hashes": [{"algorithm": "wrong-algorithm", "hash": digest}]}
    result, post = lookup(response([node, wrong]), query(attribute=attribute))
    filters = post.call_args.kwargs["json"]["variables"]["filters"]["filters"]
    assert filters[0]["key"] == [f"hashes.{algorithm}"]
    assert filters[0]["values"] == [digest]
    assert len([a for a in result["results"]["Attribute"] if a["type"] == "text"]) == 1


@pytest.mark.parametrize(
    "kind,value,entity_type,normalized",
    [
        ("hostname", "ExAmPlE.org.", "Hostname", "example.org"),
        ("ip-src", "192.0.2.1", "IPv4-Addr", "192.0.2.1"),
        ("ip-dst", "2001:0db8:0:0::1", "IPv6-Addr", "2001:db8::1"),
        ("url", "https://example.org/Case?x=1", "Url", "https://example.org/Case?x=1"),
        ("email-src", "User@example.org", "Email-Addr", "User@example.org"),
        ("email-dst", "User@example.org", "Email-Addr", "User@example.org"),
    ],
)
def test_supported_observable_values(kind, value, entity_type, normalized):
    node = {**NODE, "entity_type": entity_type, "observable_value": normalized}
    result, post = lookup(response([node]), query(attribute={**ATTRIBUTE, "type": kind, "value": value}))
    variables = post.call_args.kwargs["json"]["variables"]
    assert variables["types"] == [entity_type]
    assert variables["filters"]["filters"][0]["values"] == [normalized]
    assert result["results"]["Attribute"]


def test_nonexact_wrong_type_and_duplicate_results_are_excluded():
    result, _ = lookup(
        response(
            [
                NODE,
                NODE,
                {**NODE, "id": "other", "observable_value": "sub.example.org"},
                {**NODE, "id": "url", "entity_type": "Url"},
            ]
        )
    )
    assert len(result["results"]["Attribute"]) == 3


def test_hostname_lookup_returns_hostname_context_and_excludes_other_matches():
    hostname = {**NODE, "entity_type": "Hostname", "observable_value": "Host.Example.org."}
    domain = {**NODE, "id": "domain", "observable_value": "host.example.org"}
    partial = {**hostname, "id": "partial", "observable_value": "other.host.example.org"}
    attribute = {**ATTRIBUTE, "type": "hostname", "value": "HOST.example.org."}

    result, post = lookup(response([hostname, domain, partial]), query(attribute=attribute))

    variables = post.call_args.kwargs["json"]["variables"]
    assert variables["types"] == ["Hostname"]
    assert variables["filters"]["filters"][0]["values"] == ["host.example.org"]
    summaries = [a["value"] for a in result["results"]["Attribute"] if a["type"] == "text"]
    assert len(summaries) == 1
    assert summaries[0].startswith("OpenCTI Hostname: Host.Example.org.")


def test_no_matches_and_null_optional_fields():
    result, _ = lookup(response([]))
    assert result == {"results": {"Attribute": []}}
    node = {key: NODE[key] for key in ("id", "entity_type", "observable_value")}
    node.update({key: None for key in ("createdBy", "objectLabel", "objectMarking", "externalReferences")})
    result, _ = lookup(response([node]))
    assert len(result["results"]["Attribute"]) == 2


def test_result_cap_timeout_and_graphql_url():
    config = {**CONFIG, "url": "https://cti.test/prefix/graphql/", "max_results": "1", "timeout": "5"}
    result, post = lookup(response([NODE], next_page=True), query(config=config))
    assert post.call_args.args[0] == "https://cti.test/prefix/graphql"
    assert post.call_args.kwargs["timeout"] == 5
    assert post.call_args.kwargs["json"]["variables"]["first"] == 1
    assert "limited to 1" in result["results"]["Attribute"][-1]["value"]


@pytest.mark.parametrize(
    "status,message",
    [(401, "denied access"), (403, "denied access"), (429, "rate limit"), (500, "HTTP 500"), (302, "redirect")],
)
def test_http_failures(status, message):
    result, _ = lookup(Mock(status_code=status))
    assert message in result["error"]


@pytest.mark.parametrize(
    "exception,message",
    [
        (opencti.requests.exceptions.Timeout("test-token"), "timed out"),
        (opencti.requests.exceptions.ConnectionError("test-token"), "request failed"),
        (opencti.requests.exceptions.SSLError("test-token"), "TLS"),
    ],
)
def test_transport_failures_do_not_expose_secrets(exception, message):
    with patch.object(opencti.requests, "post", side_effect=exception):
        result = opencti.handler(query())
    assert message in result["error"]
    assert "test-token" not in str(result)


def test_invalid_json_response_and_graphql_partial_failure():
    result, _ = lookup(Mock(status_code=200, json=Mock(side_effect=ValueError("test-token"))))
    assert "invalid JSON" in result["error"]
    payload = response().json()
    payload["errors"] = [{"message": "test-token"}]
    result, _ = lookup(Mock(status_code=200, json=Mock(return_value=payload)))
    assert "GraphQL errors" in result["error"]
    assert "results" not in result and "test-token" not in str(result)


def test_legacy_label_and_marking_connections():
    node = copy.deepcopy(NODE)
    for key in ("objectLabel", "objectMarking"):
        node[key] = {"edges": [{"node": item} for item in node[key]]}
    validation_error = Mock(
        status_code=200,
        json=Mock(return_value={"errors": [{"message": 'Cannot query field "value" on type "LabelConnection".'}]}),
    )
    with patch.object(opencti.requests, "post", side_effect=[validation_error, response([node])]) as post:
        result = opencti.handler(query())
    assert post.call_count == 2
    assert post.call_args_list[0].kwargs["json"]["query"] == opencti.QUERY
    assert post.call_args_list[1].kwargs["json"]["query"] == opencti.LEGACY_QUERY
    assert all(a["Tag"][0]["name"] == "tlp:amber+strict" for a in result["results"]["Attribute"])


def test_legacy_fallback_does_not_retry_indefinitely():
    validation_error = Mock(
        status_code=200,
        json=Mock(return_value={"errors": [{"message": 'Cannot query field "value" on type "LabelConnection".'}]}),
    )
    with patch.object(opencti.requests, "post", return_value=validation_error) as post:
        result = opencti.handler(query())
    assert post.call_count == 2
    assert "GraphQL errors" in result["error"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("objectLabel", [None]),
        ("objectMarking", [None]),
        ("externalReferences", {"edges": [None]}),
        ("createdBy", "bad-author"),
    ],
)
def test_bad_nested_context_returns_an_error(field, value):
    result, _ = lookup(response([{**NODE, field: value}]))
    assert result == {"error": "OpenCTI returned an unexpected observable format."}


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"data": None},
        {"data": {"stixCyberObservables": None}},
        {"data": {"stixCyberObservables": {"edges": [None], "pageInfo": {"hasNextPage": False}}}},
    ],
)
def test_malformed_response_is_not_reported_as_no_matches(payload):
    result, _ = lookup(Mock(status_code=200, json=Mock(return_value=payload)))
    assert "unexpected response" in result["error"]


@pytest.mark.parametrize(
    "changes",
    [
        {"token": ""},
        {"token": "bad\nheader"},
        {"url": ""},
        {"url": "ftp://cti.test"},
        {"url": "https://user:pass@cti.test"},
        {"url": "https://cti.test?token=secret"},
        {"url": "https://cti.test/#fragment"},
        {"url": "https://cti.test:invalid"},
        {"max_results": "0"},
        {"max_results": "101"},
        {"max_results": True},
        {"timeout": "abc"},
        {"timeout": 1.5},
    ],
)
def test_bad_configuration_is_rejected_before_network_access(changes):
    result, post = lookup(request=query(config={**CONFIG, **changes}))
    post.assert_not_called()
    assert "error" in result


@pytest.mark.parametrize(
    "attribute",
    [
        {},
        {"type": "domain"},
        {**ATTRIBUTE, "type": "unsupported"},
        {**ATTRIBUTE, "value": " "},
        {**ATTRIBUTE, "value": None},
        {**ATTRIBUTE, "type": "md5", "value": "g" * 32},
        {**ATTRIBUTE, "type": "filename|md5", "value": "a" * 32},
        {**ATTRIBUTE, "type": "ip-dst", "value": "bad-ip"},
    ],
)
def test_bad_attributes_are_rejected_before_network_access(attribute):
    result, post = lookup(request=query(attribute=attribute))
    post.assert_not_called()
    assert "error" in result


@pytest.mark.parametrize("raw_request", ["not json", "null", "[]", '{"config": [], "attribute": null}'])
def test_bad_requests(raw_request):
    result, post = lookup(request=raw_request)
    post.assert_not_called()
    assert "error" in result


def test_metadata_and_loader_discovery():
    from pathlib import Path

    assert is_valid_module(Path(opencti.__file__))
    assert opencti.handler() is False
    assert opencti.introspection()["format"] == "misp_standard"
    before = copy.deepcopy(opencti.moduleinfo)
    assert opencti.version()["config"] == ["url", "token", "max_results", "timeout"]
    assert opencti.moduleinfo == before
