import json
from importlib import resources
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

import pytest
from pymisp import MISPObject
from pyparsing import ParseResults
from rdflib import RDFS, SKOS, Graph, Literal, URIRef
from rdflib.plugins.sparql.algebra import translateQuery
from rdflib.plugins.sparql.parser import Query, parseQuery
from rdflib.plugins.sparql.parserutils import CompValue
from SPARQLWrapper import JSON, POST
from SPARQLWrapper.SPARQLExceptions import EndPointInternalError, QueryBadFormed

from misp_modules.modules.expansion import wiki
from tests import test_expansions

SOURCE_UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
ROW = {
    "item": {"type": "uri", "value": "http://www.wikidata.org/entity/Q95"},
    "itemLabel": {"type": "literal", "value": "Google", "xml:lang": "en"},
    "itemDescription": {"type": "literal", "value": "American technology company", "xml:lang": "en"},
}


def query(value="Google", config=None, **changes):
    payload = {
        "attribute": {"type": "text", "value": value, "uuid": SOURCE_UUID, "to_ids": True, "comment": "original"},
        "config": config,
    }
    payload.update(changes)
    return json.dumps(payload)


@pytest.fixture
def client():
    with patch.object(wiki, "SPARQLWrapper") as factory:
        instance = factory.return_value
        instance.query.return_value.convert.return_value = {"results": {"bindings": [ROW]}}
        yield factory, instance


def nodes(value):
    if isinstance(value, CompValue):
        yield value
        for child in value.values():
            yield from nodes(child)
    elif isinstance(value, (list, tuple, ParseResults)):
        for child in value:
            yield from nodes(child)


def test_standard_output_preserves_source_and_validates_annotation(client):
    result = wiki.handler(query())
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == SOURCE_UUID
    assert source["value"] == "Google"
    assert source["to_ids"] is True
    assert source["comment"] == "original"
    annotation = result["results"]["Object"][0]
    assert {a["object_relation"]: a["value"] for a in annotation["Attribute"]} == {
        "ref": "https://www.wikidata.org/wiki/Q95",
        "text": "Google (Q95)\nAmerican technology company",
    }
    assert all(a["to_ids"] is False for a in annotation["Attribute"])
    assert next(a for a in annotation["Attribute"] if a["object_relation"] == "text")["disable_correlation"] is True
    reference = annotation["ObjectReference"][0]
    assert reference["referenced_uuid"] == SOURCE_UUID
    assert reference["relationship_type"] == "related-to"
    template = json.loads(
        resources.files("pymisp").joinpath("data/misp-objects/objects/annotation/definition.json").read_text()
    )
    strict = MISPObject("annotation", strict=True, misp_objects_template_custom=template)
    strict.from_dict(**annotation)
    strict._validate()


@pytest.mark.parametrize(
    "text",
    [
        "Microsoft",
        'a"b\\c',
        '"@en . } UNION { ?item ?p ?o } #',
        '\\"@en . SERVICE <https://example.invalid/> { ?s ?p ?o } #',
        '"""\n} LIMIT 100 #',
        "line\r\nbreak\tbackspace\bformfeed\f\x00\x1f",
        "Café 東京 💡",
        " spaces are preserved ",
    ],
)
@pytest.mark.parametrize("legacy", [False, True])
def test_untrusted_text_stays_inside_sparql_literals(client, text, legacy):
    raw = json.dumps({"text": text}) if legacy else query(text)
    assert "results" in wiki.handler(raw)
    parsed = list(nodes(parseQuery(client[1].setQuery.call_args.args[0])))
    literals = [node for node in parsed if node.name == "literal"]
    assert [(str(node["string"]), node["lang"] if "lang" in node else "") for node in literals] == [
        (text, "en"),
        (text, "en"),
        ("^https?://www[.]wikidata[.]org/entity/Q[1-9][0-9]*$", ""),
        ("en,en", ""),
    ]
    assert sum(node.name == "ServiceGraphPattern" for node in parsed) == 1


def test_literal_unicode_escape_sequences_are_preserved(client):
    text = r'literal \u0022 and \U00000022"@en . } #'
    assert "results" in wiki.handler(query(text))
    # parseQuery's preprocessing incorrectly expands escaped \\u/\\U sequences.
    # The grammar itself correctly parses these literal backslash sequences.
    parsed = list(nodes(Query.parse_string(client[1].setQuery.call_args.args[0], parse_all=True)))
    literals = [node for node in parsed if node.name == "literal" and "lang" in node]
    assert [str(node["string"]) for node in literals] == [text, text]
    assert sum(node.name == "ServiceGraphPattern" for node in parsed) == 1


def test_defaults_and_modern_endpoint(client):
    assert "results" in wiki.handler(query())
    factory, instance = client
    assert factory.call_args.args == ("https://query.wikidata.org/sparql",)
    assert "MISP" in factory.call_args.kwargs["agent"]
    instance.setReturnFormat.assert_called_once_with(JSON)
    instance.setMethod.assert_called_once_with(POST)
    instance.setTimeout.assert_called_once_with(15)
    sparql = instance.setQuery.call_args.args[0]
    assert 'rdfs:label "Google"@en' in sparql
    assert 'skos:altLabel "Google"@en' in sparql
    assert "LIMIT 5" in sparql


@pytest.mark.parametrize("predicate", [RDFS.label, SKOS.altLabel])
@pytest.mark.parametrize("has_item", [True, False])
def test_non_items_do_not_consume_the_query_limit(client, predicate, has_item):
    assert "results" in wiki.handler(query(config={"max_results": 1}))
    parsed = parseQuery(client[1].setQuery.call_args.args[0])
    subquery = next(node for node in nodes(parsed) if node.name == "SubSelect")
    # Evaluate the actual inner SELECT locally, including its ORDER BY/LIMIT,
    # without calling the outer Wikidata label service.
    parsed[1] = CompValue("SelectQuery", **subquery)
    graph = Graph()
    entities = ["P1", "L1", "L1-F1", "L1-S1"]
    if has_item:
        entities.extend(["Q1", "Q9"])
    for entity in entities:
        graph.add((URIRef(f"http://www.wikidata.org/entity/{entity}"), predicate, Literal("Google", lang="en")))
    results = [str(row.item) for row in graph.query(translateQuery(parsed))]
    assert results == (["http://www.wikidata.org/entity/Q1"] if has_item else [])


@pytest.mark.parametrize("config", [{}, {"language": "", "timeout": None, "max_results": "  "}])
def test_blank_settings_use_defaults(client, config):
    assert "results" in wiki.handler(query(config=config))
    client[1].setTimeout.assert_called_once_with(15)
    assert "LIMIT 5" in client[1].setQuery.call_args.args[0]


def test_custom_language_limits_and_timeout(client):
    second = dict(ROW, item={"type": "uri", "value": "https://www.wikidata.org/entity/Q2283"})
    client[1].query.return_value.convert.return_value = {"results": {"bindings": [ROW, second]}}
    result = wiki.handler(query(config={"language": "ZH-Hans", "max_results": "1", "timeout": 30}))
    assert len(result["results"]["Object"]) == 1
    sparql = client[1].setQuery.call_args.args[0]
    assert '"Google"@zh-hans' in sparql
    assert 'wikibase:language "zh-hans,en"' in sparql
    assert "LIMIT 1" in sparql
    client[1].setTimeout.assert_called_once_with(30)
    Query.parse_string(sparql, parse_all=True)


@pytest.mark.parametrize("setting", ["timeout", "max_results"])
@pytest.mark.parametrize(
    "value", [0, -1, 999, "bad", "1.5", 1.5, True, [], {}, "1 } SERVICE <https://example.invalid/> {}"]
)
def test_invalid_numeric_settings_never_contact_wikidata(client, setting, value):
    assert "error" in wiki.handler(query(config={setting: value}))
    client[0].assert_not_called()


@pytest.mark.parametrize("value", [1, False, [], {}, "e", 'en" . } #', "en,en", "en\n", "en_US", "x" * 100])
def test_invalid_language_never_contacts_wikidata(client, value):
    assert "error" in wiki.handler(query(config={"language": value}))
    client[0].assert_not_called()


@pytest.mark.parametrize("config", [[], "bad", False])
def test_invalid_config_never_contacts_wikidata(client, config):
    assert "error" in wiki.handler(query(config=config))
    client[0].assert_not_called()


@pytest.mark.parametrize(
    "raw", [None, True, "{", "null", "[]", "{}", '{"attribute": null}', '{"attribute": []}', '{"attribute": {}}']
)
def test_invalid_requests_never_contact_wikidata(client, raw):
    assert "error" in wiki.handler(raw)
    client[0].assert_not_called()


@pytest.mark.parametrize("value", [None, 123, [], {}, "", "  ", "x" * 2001, "\ud800"])
@pytest.mark.parametrize("legacy", [False, True])
def test_invalid_text_never_contacts_wikidata(client, value, legacy):
    raw = json.dumps({"text": value}) if legacy else query(value)
    assert "error" in wiki.handler(raw)
    client[0].assert_not_called()


@pytest.mark.parametrize("changes", [{"uuid": "bad"}, {"uuid": None}, {"type": "url"}, {"type": []}])
def test_invalid_attributes_never_contact_wikidata(client, changes):
    attribute = {"type": "text", "value": "Google", "uuid": SOURCE_UUID, **changes}
    assert "error" in wiki.handler(query(attribute=attribute, text="Google"))
    client[0].assert_not_called()


def test_missing_source_uuid_never_contacts_wikidata(client):
    assert "error" in wiki.handler(query(attribute={"type": "text", "value": "Google"}))
    client[0].assert_not_called()


def test_attribute_value_takes_precedence_over_legacy_text(client):
    assert "results" in wiki.handler(query(text="different"))
    sparql = client[1].setQuery.call_args.args[0]
    assert '"Google"@en' in sparql
    assert "different" not in sparql


def test_legacy_request_uses_standard_output_without_dangling_references(client):
    result = wiki.handler(json.dumps({"text": "Google"}))
    assert result["results"]["Attribute"] == []
    assert "ObjectReference" not in result["results"]["Object"][0]


def test_no_matches_returns_empty_objects_and_preserves_source(client):
    client[1].query.return_value.convert.return_value = {"results": {"bindings": []}}
    result = wiki.handler(query())
    assert result["results"]["Object"] == []
    assert result["results"]["Attribute"][0]["uuid"] == SOURCE_UUID


def test_distinct_matches_and_duplicate_schemes(client):
    second = dict(ROW, item={"type": "uri", "value": "http://www.wikidata.org/entity/Q2283"})
    duplicate = dict(ROW, item={"type": "uri", "value": "https://www.wikidata.org/entity/Q95"})
    client[1].query.return_value.convert.return_value = {"results": {"bindings": [ROW, duplicate, second]}}
    result = wiki.handler(query())
    assert [obj["Attribute"][0]["value"] for obj in result["results"]["Object"]] == [
        "https://www.wikidata.org/wiki/Q95",
        "https://www.wikidata.org/wiki/Q2283",
    ]


def test_missing_labels_and_descriptions_fall_back_to_entity_id(client):
    client[1].query.return_value.convert.return_value = {"results": {"bindings": [{"item": ROW["item"]}]}}
    annotation = wiki.handler(query())["results"]["Object"][0]
    assert next(a["value"] for a in annotation["Attribute"] if a["object_relation"] == "text") == "Q95"


@pytest.mark.parametrize("payload", [None, [], {}, {"results": []}, {"results": {}}, {"results": {"bindings": {}}}])
def test_malformed_responses_return_errors(client, payload):
    client[1].query.return_value.convert.return_value = payload
    assert "error" in wiki.handler(query())


@pytest.mark.parametrize(
    "row",
    [
        None,
        [],
        {},
        {"item": "bad"},
        {"item": {"type": "uri", "value": 95}},
        {"item": {"type": "literal", "value": ROW["item"]["value"]}},
        {"item": {"type": "uri", "value": "https://example.org/entity/Q95"}},
        {"item": {"type": "uri", "value": "javascript:alert(1)"}},
        {"item": {"type": "uri", "value": "http://www.wikidata.org/entity/Q95\n"}},
    ],
)
def test_invalid_entities_are_never_imported(client, row):
    client[1].query.return_value.convert.return_value = {"results": {"bindings": [row]}}
    assert "error" in wiki.handler(query())
    client[1].query.return_value.convert.return_value = {"results": {"bindings": [row, ROW]}}
    assert len(wiki.handler(query())["results"]["Object"]) == 1


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("private query"),
        URLError("proxy password"),
        HTTPError("https://example.org/private", 429, "secret", {}, None),
        EndPointInternalError("private query"),
        QueryBadFormed("private query"),
        json.JSONDecodeError("private body", "secret", 0),
        OSError("proxy password"),
    ],
)
@pytest.mark.parametrize("stage", ["query", "convert"])
def test_remote_errors_return_safe_error_dictionaries(client, error, stage):
    instance = client[1]
    method = instance.query if stage == "query" else instance.query.return_value.convert
    method.side_effect = error
    result = wiki.handler(query())
    assert isinstance(result, dict) and "error" in result
    assert all(word not in result["error"] for word in ("private", "password", "secret"))
    assert instance.query.call_count == 1


def test_errors_do_not_share_mutable_state(client):
    first = wiki.handler(query(value=""))
    snapshot = dict(first)
    assert "error" in wiki.handler(query(config=[]))
    assert first == snapshot
    assert "results" in wiki.handler(query())


def test_live_smoke_uses_standard_request_and_response(client):
    case = test_expansions.TestExpansions(methodName="test_wikidata")
    case.setUp()

    def post(payload):
        assert payload["attribute"]["type"] == "text"
        return Mock(json=lambda: wiki.handler(json.dumps(payload)))

    with patch.object(case, "misp_modules_post", side_effect=post):
        case.test_wikidata()


def test_metadata_and_false_query(client):
    assert wiki.handler() is False
    assert wiki.introspection()["format"] == "misp_standard"
    assert wiki.introspection()["input"] == ["text"]
    info = wiki.version()
    assert set(info["module-type"]) == {"hover", "expansion"}
    assert info["config"] == ["language", "max_results", "timeout"]
    assert "config" not in wiki.moduleinfo
    client[0].assert_not_called()
