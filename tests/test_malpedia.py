import copy
import json
from unittest.mock import Mock, patch

import pytest
from pymisp import MISPEvent, MISPObject

from misp_modules.modules.expansion import malpedia

ATTRIBUTE = {
    "type": "text",
    "value": "win.example",
    "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b",
    "comment": "Original evidence",
    "to_ids": True,
    "Tag": [{"name": "tlp:green"}],
}
FAMILY = {
    "common_name": "Example",
    "alt_names": ["ExampleAlias", "ExampleAlias"],
    "description": "Example family description.",
    "urls": ["https://example.org/report", "https://example.org/report"],
    "attribution": ["Example Actor"],
    "notes": ["Family note"],
    "updated": "2026-01-01",
    "uuid": "d29eb927-d53d-4af2-b6ce-17b3a1b34fe7",
    "sources": ["Example source"],
    "library_entries": ["example:20260101:report"],
}
ACTOR = {
    "value": "Example Actor",
    "description": "Actor description.",
    "meta": {"synonyms": ["Example Bear"], "refs": ["https://example.org/actor"], "country": "XY"},
    "families": {"win.example": FAMILY},
    "uuid": "5b4ee3ea-eee3-4c8e-8323-85ae32658754",
    "related": [{"dest-uuid": "external-cluster-uuid", "type": "similar"}],
}
RULE = 'rule example { meta: malpedia_license = "CC BY-SA 4.0" condition: true }'


def invoke(routes, value="win.example", kind="text", config=None, **kwargs):
    attribute = dict(ATTRIBUTE, value=value, type=kind)
    request = {"attribute": attribute, "config": config or {}}
    calls = []

    def get(url, **options):
        path = url.removeprefix(malpedia.BASE_URL + "/api/")
        calls.append((path, options))
        assert path in routes, f"Unexpected request: {path}"
        payload = routes[path]
        if isinstance(payload, Exception):
            raise payload
        if isinstance(payload, Mock):
            return payload
        return Mock(status_code=200, json=lambda: copy.deepcopy(payload))

    with patch.object(malpedia.requests, "get", side_effect=get):
        result = malpedia.handler(json.dumps(request), **kwargs)
    return result, calls


def objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def values(obj, relation):
    return [a["value"] for a in obj["Attribute"] if a["object_relation"] == relation]


def assert_valid_results(result):
    event = MISPEvent()
    event.from_dict(info="Malpedia expansion validation", **copy.deepcopy(result["results"]))
    known_uuids = {a.uuid for a in event.attributes} | {obj.uuid for obj in event.objects}
    for obj in event.objects:
        # Strict validation checks template requirements, cardinality and attribute types.
        parsed = MISPObject(obj.name, strict=True)
        parsed.from_dict(**json.loads(obj.to_json()))
        json.loads(parsed.to_json(strict=True))
        assert obj.template_uuid
        assert all(a.to_ids is False for a in obj.attributes)
        assert all(ref.referenced_uuid in known_uuids for ref in obj.references)
    original = next(a for a in event.attributes if a.uuid == ATTRIBUTE["uuid"])
    assert original.to_ids is True
    assert original.comment == ATTRIBUTE["comment"]
    assert original.tags[0].name == "tlp:green"
    assert all(a.to_ids is False for a in event.attributes if a.uuid != ATTRIBUTE["uuid"])


def test_family_id_preserves_metadata_provenance_and_original_attribute():
    result, calls = invoke({"get/family/win.example": FAMILY})
    family = objects(result, "malware")[0]
    assert values(family, "name") == ["Example"]
    assert values(family, "alias") == ["win.example", "ExampleAlias"]
    assert values(family, "is_family") == [True]
    assert values(family, "description") == [FAMILY["description"]]
    assert "Family note" in family["comment"]
    assert FAMILY["uuid"] in family["comment"]
    assert '"updated": "2026-01-01"' in family["comment"]
    attributes = result["results"]["Attribute"]
    assert len([a for a in attributes if a["value"] == "https://example.org/report"]) == 1
    assert any(a["type"] == "threat-actor" and a["value"] == "Example Actor" for a in attributes)
    assert calls == [
        (
            "get/family/win.example",
            {
                "headers": {"Accept": "application/json", "User-Agent": "misp-modules/malpedia"},
                "timeout": 30,
                "allow_redirects": False,
            },
        )
    ]
    assert_valid_results(result)


def test_alias_search_prefers_exact_match_over_substrings():
    result, calls = invoke(
        {
            "find/family/ExampleAlias": [
                {"name": "js.unrelated", "alt_names": []},
                {"name": "win.example", "alt_names": ["ExampleAlias"]},
            ],
            "get/family/win.example": FAMILY,
            "find/actor/ExampleAlias": [],
        },
        value="ExampleAlias",
    )
    assert len(objects(result, "malware")) == 1
    assert len(calls) == 3
    assert_valid_results(result)


def test_threat_actor_search_maps_synonyms_and_embedded_families():
    result, calls = invoke(
        {
            "find/actor/Example%20Bear": [{"name": "example_actor", "synonyms": ["Example Bear"]}],
            "get/actor/example_actor": ACTOR,
        },
        kind="threat-actor",
        value="Example Bear",
    )
    actor = objects(result, "intrusion-set")[0]
    family = objects(result, "malware")[0]
    assert values(actor, "name") == ["Example Actor"]
    assert "Example Bear" in values(actor, "aliases")
    assert '"country": "XY"' in actor["comment"]
    assert any(
        r["referenced_uuid"] == family["uuid"] and r["relationship_type"] == "uses" for r in actor["ObjectReference"]
    )
    assert len(calls) == 2
    assert_valid_results(result)


@pytest.mark.parametrize("kind,path,record", [("family", "details", FAMILY), ("actor", "actor", ACTOR)])
def test_canonical_urls_use_direct_lookup(kind, path, record):
    record_id = "win.example" if kind == "family" else "example_actor"
    result, calls = invoke(
        {f"get/{kind}/{record_id}": record},
        kind="link",
        value=f"{malpedia.BASE_URL}/{path}/{record_id}/",
    )
    assert len(calls) == 1
    assert_valid_results(result)


@pytest.mark.parametrize("kind", ["md5", "sha256", "filename|md5", "filename|sha256"])
def test_sample_hash_lookup_returns_file_and_linked_family(kind):
    digest = "a" * (32 if kind.endswith("md5") else 64)
    value = f"sample.exe|{digest}" if "|" in kind else digest
    sample = {"md5": "a" * 32, "sha256": "a" * 64, "family": "win.example", "status": "unpacked", "version": "1"}
    result, calls = invoke(
        {f"get/sample/{digest}/info": sample, "get/family/win.example": FAMILY},
        kind=kind,
        value=value,
        config={"apikey": "test-token", "timeout": "10"},
    )
    file_obj = objects(result, "file")[0]
    assert values(file_obj, "md5") == ["a" * 32]
    assert values(file_obj, "sha256") == ["a" * 64]
    assert '"status": "unpacked"' in file_obj["comment"]
    assert any(r["relationship_type"] == "belongs-to" for r in file_obj["ObjectReference"])
    assert calls[0][1]["headers"]["Authorization"] == "apitoken test-token"
    assert calls[0][1]["timeout"] == 10
    assert_valid_results(result)


def test_hash_requires_token_before_network_access():
    result, calls = invoke({}, kind="md5", value="a" * 32)
    assert "apikey is required" in result["error"]
    assert calls == []


def test_optional_yara_preserves_source_license_and_sharing_tags():
    result, calls = invoke(
        {
            "get/family/win.example": FAMILY,
            "get/yara/win.example": {"tlp_white": {"public.yar": RULE}, "tlp_amber": {"restricted.yar": RULE}},
        },
        config={"include_yara": "true"},
    )
    yara = objects(result, "yara")
    assert len(yara) == 2
    assert values(yara[0], "yara") == [RULE]
    assert {a["Tag"][0]["name"] for a in yara[0]["Attribute"]} == {"tlp:white"}
    assert {a["Tag"][0]["name"] for a in yara[1]["Attribute"]} == {"tlp:amber"}
    assert len(calls) == 2
    assert_valid_results(result)


def test_yara_failure_keeps_family_and_adds_explanation():
    result, _ = invoke(
        {"get/family/win.example": FAMILY, "get/yara/win.example": Mock(status_code=403)},
        config={"include_yara": True},
    )
    assert "YARA expansion unavailable" in objects(result, "malware")[0]["comment"]
    assert_valid_results(result)


def test_sample_kept_when_family_enrichment_fails():
    digest = "a" * 32
    result, _ = invoke(
        {
            f"get/sample/{digest}/info": {"md5": digest, "family": "win.example"},
            "get/family/win.example": Mock(status_code=503),
        },
        kind="md5",
        value=digest,
        config={"apikey": "test-token"},
    )
    assert "Family expansion unavailable" in objects(result, "file")[0]["comment"]
    assert_valid_results(result)


def test_fuzzy_search_is_bounded_and_reports_truncation():
    result, calls = invoke(
        {
            "find/family/partial": [{"name": "win.example"}, {"name": "win.second"}],
            "get/family/win.example": FAMILY,
            "find/actor/partial": [],
        },
        value="partial",
        config={"max_results": "1"},
    )
    assert len(objects(result, "malware")) == 1
    assert any("limited to 1 of 2" in a["value"] for a in result["results"]["Attribute"])
    assert len(calls) == 3


def test_actor_families_and_yara_are_bounded_per_collection():
    actor = dict(ACTOR, families={"win.first": FAMILY, "win.second": FAMILY, "win.third": FAMILY})
    result, calls = invoke(
        {
            "get/actor/example_actor": actor,
            "get/yara/win.first": {"tlp_white": {"one.yar": RULE, "two.yar": RULE, "three.yar": RULE}},
            "get/yara/win.second": {"tlp_green": {"one.yar": RULE}},
        },
        kind="url",
        value=f"{malpedia.BASE_URL}/actor/example_actor",
        config={"max_results": 2, "include_yara": True},
    )
    assert "Related families limited to 2 of 3" in objects(result, "intrusion-set")[0]["comment"]
    assert "YARA results limited to 2 of 3" in objects(result, "malware")[0]["comment"]
    assert len(objects(result, "yara")) == 3
    assert len(calls) == 3
    assert_valid_results(result)


@pytest.mark.parametrize("payload", [[], None, {"detail": "error"}, {"error": "bad"}, {"unknown": "data"}])
def test_unexpected_or_error_payloads_are_reported(payload):
    result, _ = invoke({"get/family/win.example": payload})
    assert "error" in result


@pytest.mark.parametrize(
    "response,message",
    [
        (Mock(status_code=404), "No matching records"),
        (Mock(status_code=401), "denied access"),
        (Mock(status_code=403), "denied access"),
        (Mock(status_code=429), "rate limit"),
        (Mock(status_code=500), "HTTP status 500"),
        (Mock(status_code=302), "HTTP status 302"),
        (Mock(status_code=200, json=Mock(side_effect=ValueError())), "invalid JSON"),
        (malpedia.requests.exceptions.Timeout("secret-token"), "timed out"),
        (malpedia.requests.exceptions.ConnectionError("secret-token"), "Unable to contact"),
    ],
)
def test_api_errors_do_not_expose_credentials(response, message):
    result, _ = invoke({"get/family/win.example": response}, config={"apikey": "secret-token"})
    assert message in result["error"]
    assert "secret-token" not in result["error"]


@pytest.mark.parametrize(
    "config",
    [
        {"timeout": 0},
        {"timeout": 121},
        {"timeout": True},
        {"timeout": 1.5},
        {"max_results": "bad"},
        {"max_results": 21},
        {"max_results": 0},
        {"max_results": False},
        {"include_yara": "maybe"},
        {"apikey": "token\nheader"},
        {"apikey": 123},
        {"apikey": False},
    ],
)
def test_invalid_configuration_does_not_contact_api(config):
    result, calls = invoke({}, config=config)
    assert "error" in result
    assert calls == []


@pytest.mark.parametrize("unset", [None, ""])
def test_unset_optional_settings_apply_documented_defaults(unset):
    hits = [{"name": f"win.example{index}"} for index in range(6)]
    routes = {"find/family/partial": hits, "find/actor/partial": []}
    routes.update({f"get/family/{hit['name']}": FAMILY for hit in hits[:5]})
    result, calls = invoke(routes, value="partial", config=dict.fromkeys(malpedia.moduleconfig, unset))

    assert len(objects(result, "malware")) == 5
    assert any("limited to 5 of 6" in attr["value"] for attr in result["results"]["Attribute"])
    assert len(calls) == 7
    assert all(options["timeout"] == 30 for _, options in calls)
    assert all("Authorization" not in options["headers"] for _, options in calls)
    assert not objects(result, "yara")
    assert_valid_results(result)


@pytest.mark.parametrize("unset", [None, ""])
def test_configured_settings_work_alongside_unset_options(unset):
    result, calls = invoke(
        {"get/family/win.example": FAMILY, "get/yara/win.example": {"tlp_white": {"example.yar": RULE}}},
        config={"apikey": "test-token", "timeout": "10", "max_results": unset, "include_yara": "true"},
    )

    assert len(objects(result, "yara")) == 1
    assert len(calls) == 2
    assert all(options["timeout"] == 10 for _, options in calls)
    assert all(options["headers"]["Authorization"] == "apitoken test-token" for _, options in calls)
    assert_valid_results(result)


@pytest.mark.parametrize("unset", [None, ""])
def test_unset_optional_settings_still_require_token_for_hash_queries(unset):
    result, calls = invoke({}, kind="md5", value="a" * 32, config=dict.fromkeys(malpedia.moduleconfig, unset))

    assert "apikey is required" in result["error"]
    assert calls == []


@pytest.mark.parametrize(
    "kind,value",
    [
        ("md5", "a" * 31),
        ("sha256", "z" * 64),
        ("filename|md5", "a" * 32),
        ("url", "https://example.org/details/win.example"),
        ("url", f"{malpedia.BASE_URL}/api/get/family/win.example"),
        ("url", f"{malpedia.BASE_URL}/details/%2e%2e"),
        ("sha1", "a" * 40),
        ("text", " "),
    ],
)
def test_invalid_queries_do_not_contact_api(kind, value):
    result, calls = invoke({}, kind=kind, value=value)
    assert "error" in result
    assert calls == []


@pytest.mark.parametrize("payload", [None, [], {}, {"attribute": {}}, {"attribute": dict(ATTRIBUTE, uuid="bad")}])
def test_invalid_requests(payload):
    with patch.object(malpedia.requests, "get") as get:
        assert "error" in malpedia.handler(json.dumps(payload))
    get.assert_not_called()


def test_no_matches_and_module_contract():
    result, _ = invoke({"find/family/unknown": [], "find/actor/unknown": []}, value="unknown")
    assert result == {"error": "No matching records found on Malpedia."}
    assert malpedia.handler() is False
    assert "error" in malpedia.handler("not json")
    assert malpedia.introspection()["format"] == "misp_standard"
    assert malpedia.version()["config"] == malpedia.moduleconfig


@pytest.mark.parametrize("sample", [{"md5": "b" * 32}, {"sha256": "invalid"}])
def test_sample_hashes_must_be_valid_and_match_query(sample):
    digest = "a" * 32
    result, _ = invoke({f"get/sample/{digest}/info": sample}, kind="md5", value=digest, config={"apikey": "test-token"})
    assert "error" in result


def test_search_query_is_encoded_as_one_path_segment():
    needle = "Example / Bear?#"
    result, calls = invoke({"find/actor/Example%20%2F%20Bear%3F%23": []}, kind="threat-actor", value=needle)
    assert "No matching records" in result["error"]
    assert len(calls) == 1


def test_shared_family_is_deduplicated_and_yara_family_limit_is_reported():
    actor1 = dict(ACTOR, families={"win.first": FAMILY, "win.shared": FAMILY})
    actor2 = dict(ACTOR, families={"win.shared": FAMILY, "win.third": FAMILY})
    result, calls = invoke(
        {
            "find/actor/Example": [{"name": "actor1"}, {"name": "actor2"}],
            "get/actor/actor1": actor1,
            "get/actor/actor2": actor2,
            "get/yara/win.first": {},
            "get/yara/win.shared": {},
        },
        kind="threat-actor",
        value="Example",
        config={"max_results": 2, "include_yara": True},
    )
    assert len(objects(result, "malware")) == 3
    assert len(objects(result, "intrusion-set")) == 2
    assert "YARA lookup omitted" in objects(result, "malware")[-1]["comment"]
    assert len(calls) == 5
    assert_valid_results(result)


def test_malware_type_searches_only_families():
    result, calls = invoke(
        {
            "find/family/ExampleAlias": [{"name": "win.example", "alt_names": ["ExampleAlias"]}],
            "get/family/win.example": FAMILY,
        },
        value="ExampleAlias",
        kind="malware-type",
    )
    assert len(calls) == 2
    assert_valid_results(result)
