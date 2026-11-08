"""Exercise the real vt-graph-api SDK against synthetic native API v3 replies."""

import base64
import copy
import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
import vt_graph_api
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.lib.vt_graph_parser.helpers.parsers import parse_pymisp_response
from misp_modules.lib.vt_graph_parser.helpers.wrappers import MispAttribute
from misp_modules.lib.vt_graph_parser.importers.pymisp_response import from_pymisp_response
from misp_modules.modules.export_mod import vt_graph as module

GRAPH_ID = "g" + "1" * 64
OTHER_GRAPH = "g" + "2" * 64
SHA256 = "a" * 64
MD5 = "b" * 32
SHA1 = "c" * 40
URL_ID = "d" * 64
SECRET = "synthetic-vt-api-key"


def attribute(kind="domain", value="example.org", **extra):
    return {"type": kind, "value": value, "category": "Network activity", **extra}


def query(data=None, **config):
    return json.dumps(
        {"data": [{"Attribute": [attribute()]}] if data is None else data, "config": {"vt_api_key": SECRET, **config}}
    )


class NativeAPI:
    def __init__(self):
        self.calls = []
        self.overrides = {}
        self.loaded = {
            "data": {
                "type": "graph",
                "id": GRAPH_ID,
                "attributes": {
                    "graph_data": {"description": "Existing investigation", "version": "5.0.0"},
                    "private": True,
                    "nodes": [
                        {
                            "type": "domain",
                            "entity_id": "existing.example",
                            "index": 0,
                            "x": 0,
                            "y": 0,
                            "text": "Retain this node",
                        }
                    ],
                    "links": [],
                },
            }
        }

    def send(self, adapter, request, **kwargs):
        parsed = urlsplit(request.url)
        assert parsed.scheme == "https" and parsed.netloc == "www.virustotal.com"
        assert parsed.path.startswith("/api/v3/") and SECRET not in request.url
        assert request.headers["x-apikey"] == SECRET
        path = parsed.path.removeprefix("/api/v3/")
        self.calls.append(request)
        reply = self.overrides.get((request.method, path))
        if isinstance(reply, Exception):
            raise reply
        if reply is None:
            if request.method in ("POST", "PATCH") and path in (
                "graphs",
                "graphs/" + GRAPH_ID,
                "graphs/" + OTHER_GRAPH,
            ):
                reply = (200, {"data": {"type": "graph", "id": GRAPH_ID}})
            elif request.method == "GET" and path in ("graphs/" + GRAPH_ID, "graphs/" + OTHER_GRAPH):
                reply = (200, copy.deepcopy(self.loaded))
            elif request.method == "GET" and path.endswith(("/relationships/viewers", "/relationships/editors")):
                reply = (200, {"data": []})
            elif request.method == "POST" and path.endswith(("/viewers", "/editors")):
                reply = (200, {"data": []})
            elif request.method == "GET" and path in ("files/" + MD5, "files/" + SHA1, "files/" + SHA256):
                reply = (200, {"data": {"type": "file", "id": SHA256, "attributes": {"sha256": SHA256}}})
            elif request.method == "POST" and path == "urls":
                assert parse_qs(request.body)["url"] == ["https://example.org/path"]
                reply = (200, {"data": {"type": "analysis", "id": "u-" + URL_ID + "-1700000000"}})
            elif (
                request.method == "GET"
                and path.startswith(("domains/", "ip_addresses/", "urls/"))
                and len(path.split("/")) == 3
            ):
                reply = (200, {"data": [], "meta": {}, "links": {}})
            elif request.method == "GET" and path.startswith(("domains/", "ip_addresses/", "urls/")):
                reply = (200, {"data": {"attributes": {}}})
            else:
                raise AssertionError("Unexpected API request: " + request.method + " " + path)
        status, body = reply
        response = requests.Response()
        response.status_code, response.url, response.request = status, request.url, request
        response._content = body if isinstance(body, bytes) else json.dumps(body).encode()
        response._content_consumed = True
        return response

    def saved(self):
        return [
            json.loads(r.body)
            for r in self.calls
            if r.method in ("POST", "PATCH")
            and urlsplit(r.url).path
            in ("/api/v3/graphs", "/api/v3/graphs/" + GRAPH_ID, "/api/v3/graphs/" + OTHER_GRAPH)
        ]


@pytest.fixture
def api():
    fake = NativeAPI()
    with patch.object(
        requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
    ):
        yield fake


def test_discovery_contract_and_direct_import():
    assert module.handler(False) is False
    assert module.version()["config"] == module.moduleconfig
    assert module.introspection()["outputFileExtension"] == "txt"
    assert {"filename|sha1", "filename|sha256", "target-user", "target-email"} <= set(module.mispattributes["input"])


def test_create_native_graph_with_boolean_config_and_downloadable_links(api):
    result = module.handler(
        query(private="false", fetch_information="false", fetch_vt_enterprise="false", expand_one_level="false")
    )
    assert result["response"] == []
    assert base64.b64decode(result["data"]).decode() == "https://www.virustotal.com/graph/" + GRAPH_ID
    assert len(api.calls) == 1 and api.calls[0].method == "POST"
    payload = api.saved()[0]["data"]
    assert payload["type"] == "graph" and payload["attributes"]["private"] is False
    assert payload["attributes"]["nodes"][0]["entity_id"] == "example.org"
    assert payload["attributes"]["graph_data"]["description"] == "Graph created from MISP event"


@pytest.mark.parametrize("value", [True, "true", "1", 1, False, "false", "0", 0, None, ""])
def test_boolean_values_reach_native_private_field(api, value):
    result = module.handler(query(private=value))
    assert "error" not in result
    assert api.saved()[0]["data"]["attributes"]["private"] is (str(value).lower() in ("true", "1"))


def test_expansion_is_explicit_and_string_false_does_not_expand(api):
    assert "error" not in module.handler(query(expand_one_level="false"))
    assert len(api.calls) == 1 and api.calls[0].method == "POST"
    api.calls.clear()
    assert "error" not in module.handler(query(expand_one_level="true"))
    expansions = {urlsplit(r.url).path.rsplit("/", 1)[1] for r in api.calls if r.method == "GET"}
    assert expansions == set(vt_graph_api.Node.NODE_EXPANSIONS["domain"])
    assert len(api.saved()) == 1


@pytest.mark.parametrize(
    "kind,value", [("filename", "report.exe"), ("target-user", "analyst"), ("target-email", "a@example.org")]
)
def test_expansion_saves_custom_only_graph_without_relationship_requests(api, kind, value):
    result = module.handler(query(data=[{"Attribute": [attribute(kind, value)]}], expand_one_level="true"))
    assert "error" not in result and len(api.calls) == 1
    node = api.saved()[0]["data"]["attributes"]["nodes"][0]
    assert node["entity_id"] == value and node["type"] == "custom"


def test_mixed_graph_expands_native_nodes_once_and_preserves_custom_nodes(api):
    api.overrides[("GET", "domains/example.org/resolutions")] = (
        200,
        {"data": [{"id": "192.0.2.99example.org", "type": "resolution", "attributes": {}}]},
    )
    attrs = [
        attribute("filename", "report.exe"),
        attribute("target-user", "analyst"),
        attribute("target-email", "a@example.org"),
        attribute(),
    ]
    result = module.handler(query(data=[{"Attribute": attrs}], expand_one_level="true"))
    assert "error" not in result and len(api.saved()) == 1
    nodes = {node["entity_id"]: node for node in api.saved()[0]["data"]["attributes"]["nodes"]}
    assert all(nodes[value]["type"] == "custom" for value in ("report.exe", "analyst", "a@example.org"))
    assert nodes["192.0.2.99"]["type"] == "ip_address"
    # Newly discovered nodes are retained, but not expanded at this same level.
    gets = [r for r in api.calls if r.method == "GET"]
    assert len(gets) == len(vt_graph_api.Node.NODE_EXPANSIONS["domain"])
    assert all("/domains/example.org/" in r.url for r in gets)


def test_expansion_skips_loaded_custom_and_native_nodes_without_relationships(api):
    api.loaded["data"]["attributes"]["nodes"].extend(
        [
            {
                "type": "custom",
                "entity_id": "existing.txt",
                "entity_attributes": {"custom_type": "filename"},
                "index": 1,
                "x": 0,
                "y": 0,
            },
            {"type": "ssl_cert", "entity_id": SHA256, "index": 2, "x": 0, "y": 0},
        ]
    )
    attrs = [attribute("link", "https://www.virustotal.com/graph/" + GRAPH_ID), attribute()]
    result = module.handler(query(data=[{"Attribute": attrs}], expand_one_level="true"))
    assert "error" not in result and len(api.saved()) == 1
    nodes = {node["entity_id"] for node in api.saved()[0]["data"]["attributes"]["nodes"]}
    assert {"existing.txt", SHA256, "existing.example", "example.org"} <= nodes
    assert all("/ssl_certs/" not in r.url and "existing.txt" not in r.url for r in api.calls)


def test_information_lookup_is_explicit(api):
    assert "error" not in module.handler(query(fetch_information="true"))
    assert [r.method for r in api.calls] == ["GET", "POST"]
    assert api.calls[0].url.endswith("/domains/example.org")


@pytest.mark.parametrize("kind,digest", [("md5", MD5), ("sha1", SHA1), ("sha256", SHA256)])
def test_filename_with_multiple_pipes_exports_canonical_file_and_label(api, kind, digest):
    value = "report|final|v1.exe|" + digest.upper()
    parsed = MispAttribute("filename|" + kind, "Payload delivery", value)
    assert parsed.label == "report|final|v1.exe" and parsed.value == digest
    result = module.handler(query(data=[{"Attribute": [attribute("filename|" + kind, value)]}]))
    assert "error" not in result
    nodes = api.saved()[0]["data"]["attributes"]["nodes"]
    assert len(nodes) == 1 and nodes[0]["type"] == "file"
    assert nodes[0]["entity_id"] == SHA256 and nodes[0]["text"] == "report|final|v1.exe"
    assert all("/intelligence/" not in r.url for r in api.calls)


def test_duplicate_domains_do_not_make_self_links(api):
    result = module.handler(query(data=[{"Attribute": [attribute(), attribute(), attribute("ip-dst", "192.0.2.1")]}]))
    assert "error" not in result
    graph = api.saved()[0]["data"]["attributes"]
    assert len([n for n in graph["nodes"] if n["entity_id"] == "example.org"]) == 1
    assert all(link["source"] != link["target"] for link in graph["links"])
    assert any(link["connection_type"] == "resolutions" for link in graph["links"])


def test_hash_aliases_resolving_to_same_sha256_are_deduplicated(api):
    attrs = [attribute("md5", MD5), attribute("sha1", SHA1), attribute("sha256", SHA256)]
    assert "error" not in module.handler(query(data=[{"Attribute": attrs}]))
    nodes = api.saved()[0]["data"]["attributes"]["nodes"]
    assert len(nodes) == 1 and nodes[0]["entity_id"] == SHA256


@pytest.mark.parametrize(
    "kind,value",
    [("target-user", "analyst"), ("target-email", "analyst@example.org"), ("filename", "report|final.exe")],
)
def test_custom_first_node_is_valid_and_connected_without_file_lookup(api, kind, value):
    attrs = [attribute(kind, value), attribute(), attribute("ip-dst", "192.0.2.2")]
    assert "error" not in module.handler(query(data=[{"Attribute": attrs}]))
    graph = api.saved()[0]["data"]["attributes"]
    assert graph["nodes"][0]["type"] == "custom"
    assert graph["nodes"][0]["entity_attributes"]["custom_type"] in ("victim", "email", "filename")
    assert any(
        link == {"source": value, "target": "example.org", "connection_type": "manual"} for link in graph["links"]
    )
    assert len(api.calls) == 1


def test_custom_only_and_multiple_initial_custom_nodes(api):
    for attrs in (
        [attribute("target-user", "analyst")],
        [attribute("target-user", "analyst"), attribute("target-email", "a@example.org"), attribute()],
    ):
        assert "error" not in module.handler(query(data=[{"Attribute": attrs}]))
    assert api.saved()[0]["data"]["attributes"]["nodes"][0]["type"] == "custom"
    assert len(api.saved()[1]["data"]["attributes"]["links"]) == 2


def test_raw_url_uses_sdk_canonical_identifier_before_graph_save(api):
    attrs = [attribute("url", "https://example.org/path"), attribute("sha256", SHA256)]
    assert "error" not in module.handler(query(data=[{"Attribute": attrs}]))
    graph = api.saved()[0]["data"]["attributes"]
    assert any(node["entity_id"] == URL_ID and node["type"] == "url" for node in graph["nodes"])
    assert all(link["source"] != "https://example.org/path" for link in graph["links"])


@pytest.mark.parametrize("shape", ["flat", "wrapped", "selected", "single"])
def test_event_and_object_envelopes_preserve_selection_and_skip_deleted(api, shape):
    event = {
        "Attribute": [attribute(), attribute("domain", "deleted.example", deleted="1")],
        "Object": [
            {"Attribute": [attribute("ip-src", "192.0.2.3"), attribute("domain", "gone.example", deleted=True)]},
            {"deleted": True, "Attribute": [attribute("domain", "deleted-object.example")]},
        ],
    }
    if shape == "flat":
        data = [event]
    elif shape == "wrapped":
        data = [{"Event": event}]
    elif shape == "selected":
        data = [{"Event": {"Attribute": [attribute("domain", "unselected.example")]}, **event}]
    else:
        data = event
    before = copy.deepcopy(data)
    assert "error" not in module.handler(query(data=data))
    ids = {n["entity_id"] for n in api.saved()[0]["data"]["attributes"]["nodes"] if n["type"] != "relationship"}
    assert ids == {"example.org", "192.0.2.3"} and data == before


@pytest.mark.parametrize("path", ["graph/", "gui/graph/"])
def test_existing_graph_links_without_attribute_id_load_and_patch_native_graph(api, path):
    attrs = [attribute("link", "https://www.virustotal.com/" + path + GRAPH_ID + "?view=tree"), attribute()]
    assert "error" not in module.handler(query(data=[{"Attribute": attrs}]))
    methods = [r.method for r in api.calls]
    assert methods == ["GET", "GET", "GET", "PATCH"]
    assert api.calls[0].url.endswith("/graphs/" + GRAPH_ID)
    graph = api.saved()[0]["data"]["attributes"]
    assert graph["private"] is True and graph["graph_data"]["description"] == "Existing investigation"
    assert {"existing.example", "example.org"} == {n["entity_id"] for n in graph["nodes"]}


def test_graph_link_selection_prefers_highest_numeric_id_then_input_order():
    links = [
        attribute("link", "https://www.virustotal.com/graph/" + GRAPH_ID, id="19"),
        attribute("link", "https://www.virustotal.com/graph/" + OTHER_GRAPH, id="20"),
    ]
    assert parse_pymisp_response({"Attribute": links + [attribute()]})[1] == OTHER_GRAPH
    for link in links:
        link.pop("id")
    assert parse_pymisp_response({"Attribute": links + [attribute()]})[1] == OTHER_GRAPH


@pytest.mark.parametrize(
    "link",
    [
        "https://www.virustotal.com/graph/not-a-graph-id",
        "https://www.virustotal.com/graph/" + GRAPH_ID + "/../../users",
        "https://www.virustotal.com.attacker.example/graph/" + GRAPH_ID,
        "https://user@www.virustotal.com/graph/" + GRAPH_ID,
        "https://www.virustotal.com/graph/",
    ],
)
def test_unrelated_or_malformed_links_are_not_loaded(api, link):
    assert "error" not in module.handler(query(data=[{"Attribute": [attribute("link", link), attribute()]}]))
    assert len(api.calls) == 1 and api.calls[0].method == "POST"


def test_collaborator_csv_is_trimmed_deduplicated_and_sent_with_native_descriptors(api):
    assert "error" not in module.handler(query(user_editors=" alice, alice, ,bob ", group_viewers=" team, "))
    editors = next(json.loads(r.body) for r in api.calls if r.url.endswith("/editors"))
    viewers = next(json.loads(r.body) for r in api.calls if r.url.endswith("/viewers"))
    assert editors == {"data": [{"id": "alice", "type": "user"}, {"id": "bob", "type": "user"}]}
    assert viewers == {"data": [{"id": "team", "type": "group"}]}


def test_multiple_events_return_one_graph_link_per_event(api):
    events = [{"Attribute": [attribute()]}, {"Event": {"Attribute": [attribute("domain", "other.example")]}}]
    result = module.handler(query(data=events))
    assert "error" not in result and len(api.saved()) == 2
    assert base64.b64decode(result["data"]).decode().splitlines() == [
        "https://www.virustotal.com/graph/" + GRAPH_ID,
        "https://www.virustotal.com/graph/" + GRAPH_ID,
    ]


@pytest.mark.parametrize("reply", [(403, {}), (200, b"not-json"), (200, {"data": {}})])
def test_existing_graph_load_failure_never_creates_replacement(api, reply):
    api.overrides[("GET", "graphs/" + GRAPH_ID)] = reply
    attrs = [attribute("link", "https://www.virustotal.com/graph/" + GRAPH_ID), attribute()]
    result = module.handler(query(data=[{"Attribute": attrs}]))
    assert "error" in result and SECRET not in result["error"]
    assert len(api.calls) == 1 and not api.saved()


def test_collaborator_failure_after_creation_does_not_report_success_or_retry(api):
    api.overrides[("POST", "graphs/" + GRAPH_ID + "/viewers")] = (403, {})
    result = module.handler(query(user_viewers="alice"))
    assert "error" in result and "already have been saved" in result["error"]
    assert "data" not in result and len(api.saved()) == 1


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"config":[]}', '{"data":[],"config":{"vt_api_key":"key"}}'])
def test_invalid_requests_never_call_api(api, raw):
    assert "error" in module.handler(raw) and api.calls == []


@pytest.mark.parametrize(
    "config",
    [
        {"private": "perhaps"},
        {"fetch_information": []},
        {"expand_one_level": {}},
        {"user_viewers": ["a"]},
        {"vt_api_key": 123},
    ],
)
def test_invalid_configuration_never_calls_api(api, config):
    assert "error" in module.handler(query(**config)) and api.calls == []


@pytest.mark.parametrize(
    "event",
    [
        {"Attribute": None},
        {"Attribute": [None]},
        {"Event": None},
        {"deleted": True},
        {"Attribute": [attribute("md5", "bad-hash")]},
        {"Attribute": [attribute("filename|sha256", "no-separator")]},
        {"Attribute": [attribute("filename|sha256", "name|bad-hash")]},
        {"Attribute": [attribute(value=None)]},
        {"Attribute": [attribute(category=None)]},
        {"Object": [{"Attribute": "bad"}]},
        {"Attribute": [attribute(deleted=True)]},
        {"Attribute": [attribute("comment", "unsupported")]},
    ],
)
def test_invalid_later_event_prevents_all_sdk_calls(api, event):
    result = module.handler(query(data=[{"Attribute": [attribute()]}, event]))
    assert "error" in result and api.calls == []


@pytest.mark.parametrize(
    "reply",
    [
        (401, {}),
        (403, {}),
        (429, {}),
        (500, {}),
        (200, b"bad-json"),
        (200, {"data": {}}),
        (200, {"data": {"id": "not-a-graph-id"}}),
        requests.Timeout("secret=" + SECRET),
    ],
)
def test_failed_or_unconfirmed_save_is_sanitized_and_not_retried(api, reply):
    api.overrides[("POST", "graphs")] = reply
    result = module.handler(query())
    assert "error" in result and SECRET not in result["error"] and "before retrying" in result["error"]
    assert len(api.calls) == 1


def test_error_results_are_not_shared_between_calls(api):
    failed = module.handler(query(vt_api_key=""))
    failed["error"] = "mutated"
    assert module.handler(query(vt_api_key=""))["error"] != "mutated"
    assert "error" not in module.handler(query())


def test_api_connection_mode_uses_canonical_ids_and_handles_initial_custom_nodes(api):
    data = {
        "data": [
            {
                "Attribute": [
                    attribute("target-user", "analyst"),
                    attribute("sha256", SHA256),
                    attribute("filename", "note.txt"),
                ]
            }
        ]
    }
    with patch.object(vt_graph_api.VTGraph, "connect_with_graph") as connect:
        graph = from_pymisp_response(data, SECRET, fetch_information=False, use_vt_to_connect_the_graph=True)[0]
    assert connect.call_count == 1 and connect.call_args.args == (SHA256,)
    assert connect.call_args.kwargs["max_depth"] == 3
    assert ("analyst", SHA256, "manual") in graph.links and (SHA256, "note.txt", "manual") in graph.links
    assert api.calls == []


class TestGraphHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"vt_graph": module, "type:vt_graph": "export"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_query_and_discovery(self):
        fake = NativeAPI()
        with patch.object(
            requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: fake.send(adapter, request, **kw)
        ):
            response = self.fetch(
                "/query", method="POST", body=json.dumps({"module": "vt_graph", **json.loads(query())})
            )
        assert response.code == 200 and "data" in json.loads(response.body)
        assert json.loads(self.fetch("/modules").body)[0]["name"] == "vt_graph"
        assert len(fake.saved()) == 1
