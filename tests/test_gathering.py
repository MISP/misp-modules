import base64
import copy
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pymisp
import pytest
import requests
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

import misp_modules
from misp_modules import __main__ as service
from misp_modules import openapi
from misp_modules.lib import gathering
from misp_modules.modules.gathering import withaname

FILENAME = "2026-10-01_12-00-00_DDoSia-target-list-full.json"
PARAMS = {"date_from": "2026-10-01", "date_to": "2026-10-02"}


@pytest.fixture
def config():
    return {
        "randoms": [{"id": "rule-1", "digit": True, "min": 5, "max": 5}],
        "targets": [
            {
                "target_id": "target-1",
                "request_id": "request-1",
                "host": "example.org",
                "ip": "192.0.2.1",
                "type": "http",
                "method": "POST",
                "port": 443,
                "use_ssl": True,
                "path": "/?token=$_rule-1",
                "body": {"type": "str", "value": "test"},
                "headers": {"User-Agent": "example", "Accept": "*/*"},
            },
            {"host": "example.org", "method": "GET", "port": 80, "use_ssl": False},
        ],
    }


@pytest.fixture(autouse=True)
def state_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("MISP_MODULES_GATHERING_STATE_DIR", str(tmp_path / "state"))


def bundle(config, filename=FILENAME, deduplicate=True):
    event, timestamp = withaname.convert(config, filename, deduplicate)
    builder = gathering.FeedBuilder()
    builder.add(event, timestamp)
    return builder.build()


def test_standard_feed_round_trip_and_template(config, tmp_path):
    result = bundle(config)
    gathering.write_feed(result, tmp_path / "feed")
    event_uuid = next(iter(result["manifest"]))
    event_file = tmp_path / "feed" / f"{event_uuid}.json"
    event = json.loads(event_file.read_text())["Event"]
    parsed = pymisp.MISPEvent()
    parsed.load(event_file.read_text(), validate=True)
    assert str(parsed.uuid) == event_uuid
    assert all(obj._validate() for obj in parsed.objects)
    manifest = json.loads((tmp_path / "feed/manifest.json").read_text())
    assert manifest[event_uuid]["timestamp"] == event["timestamp"]
    assert len(event["Object"]) == 2
    assert event["Object"][0]["template_uuid"] == "e56d7f93-258e-4ba5-bd8a-463acd6d98c4"
    assert event["Object"][0]["template_version"] == "3"
    for obj in event["Object"]:
        assert UUID(obj["uuid"]).version == 5
        for attribute in obj["Attribute"]:
            assert attribute["to_ids"] is False and attribute["disable_correlation"] is True
            assert UUID(attribute["uuid"]).version == 5
    attachment = next(a for a in event["Attribute"] if a["type"] == "attachment")
    assert json.loads(base64.b64decode(attachment["data"])) == withaname.normalized_config(config)
    values = {a["object_relation"]: a["value"] for a in event["Object"][0]["Attribute"]}
    assert values["path"] == "/?token=$_rule-1"
    assert values["use-ssl"] == "true"
    assert json.loads(values["headers"]) == config["targets"][0]["headers"]
    with pytest.raises(FileExistsError):
        gathering.write_feed(result, tmp_path / "feed")


def test_repeated_and_reordered_collection_is_identical(config):
    first = bundle(config)
    reordered = json.loads(json.dumps(config, sort_keys=True))
    reordered["targets"].reverse()
    assert bundle(reordered) == first
    # A fresh store instance uses the same persisted revision.
    assert bundle(config) == first


def test_correction_keeps_event_identity_and_advances_revision(config):
    first = bundle(config)
    config["randoms"][0]["max"] = 8
    second = bundle(config)
    uuid = next(iter(first["events"]))
    assert list(second["events"]) == [uuid]
    assert int(second["manifest"][uuid]["timestamp"]) > int(first["manifest"][uuid]["timestamp"])
    assert bundle(config) == second


def test_entry_deduplication_preserves_distinct_rules_and_scopes_observations(config):
    config["targets"].append(copy.deepcopy(config["targets"][0]))
    collapsed = next(iter(bundle(config)["events"].values()))["Event"]
    expanded = next(iter(bundle(config, deduplicate=False)["events"].values()))["Event"]
    assert len(collapsed["Object"]) == 2 and len(expanded["Object"]) == 3
    assert collapsed["uuid"] != expanded["uuid"]
    assert len({obj["uuid"] for obj in expanded["Object"]}) == 3
    later = next(iter(bundle(config, FILENAME.replace("12-00-00", "13-00-00"))["events"].values()))["Event"]
    assert {o["uuid"] for o in later["Object"]}.isdisjoint(o["uuid"] for o in collapsed["Object"])


def test_revision_store_serializes_concurrent_requests(config):
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: bundle(config), range(12)))
    assert all(result == results[0] for result in results)


@pytest.mark.parametrize(
    "params",
    [
        None,
        [],
        {"typo": 1},
        {"max_events": True},
        {"max_events": 101},
        {"deduplicate_entries": "false"},
        {"date_from": "invalid"},
        {"date_from": "2026-10-02", "date_to": "2026-10-01"},
    ],
)
def test_parameters_rejected_before_network(params):
    with patch.object(requests.Session, "get") as get:
        assert "error" in withaname.handler(json.dumps({"parameters": params}))
        get.assert_not_called()


@pytest.fixture
def transport(monkeypatch, config):
    calls = []
    listing = f'<a href="{FILENAME}">config</a><a href="{FILENAME}">duplicate link</a>'
    bodies = {withaname.SOURCE: listing.encode(), withaname.SOURCE + FILENAME: json.dumps(config).encode()}

    def send(session, request, **kwargs):
        calls.append((request, kwargs))
        response = requests.Response()
        response.status_code = 200
        response._content = bodies[request.url]
        response._content_consumed = True
        response.url = request.url
        response.request = request
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    return bodies, calls


def test_collection_filters_files_and_never_contacts_targets(transport):
    bodies, calls = transport
    bodies[withaname.SOURCE] += (
        '<a href="https://evil.example/data/'
        + FILENAME
        + '">external</a><a href="//evil.example/'
        + FILENAME
        + '">external</a><a href="../'
        + FILENAME
        + '">traversal</a><a href="2026-09-30_12-00-00_DDoSia-target-list-full.json">old</a>'
    ).encode()
    result = withaname.handler(json.dumps({"parameters": PARAMS}))
    assert len(result["events"]) == 1
    assert [request.url for request, _ in calls] == [withaname.SOURCE, withaname.SOURCE + FILENAME]
    assert all(options["allow_redirects"] is False and options["timeout"] == (5, 15) for _, options in calls)


def test_limit_fails_instead_of_silently_truncating(transport):
    bodies, calls = transport
    bodies[withaname.SOURCE] += f'<a href="{FILENAME.replace("12-00-00", "13-00-00")}">next</a>'.encode()
    result = withaname.handler(json.dumps({"parameters": {**PARAMS, "max_events": 1}}))
    assert "error" in result and len(calls) == 1


def test_failed_configuration_returns_no_partial_feed(transport):
    bodies, _ = transport
    bodies[withaname.SOURCE + FILENAME] = b'{"targets": [null]}'
    assert set(withaname.handler(json.dumps({"parameters": PARAMS}))) == {"error"}


def test_source_and_output_size_limits(transport, monkeypatch, config):
    monkeypatch.setattr(withaname, "MAX_SOURCE_BYTES", 1)
    assert "error" in withaname.handler(json.dumps({"parameters": PARAMS}))
    monkeypatch.setattr(gathering, "MAX_BUNDLE_BYTES", 1)
    with pytest.raises(ValueError, match="32 MiB"):
        bundle(config)


def test_network_error_is_sanitized(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.ConnectionError("provider-secret")

    monkeypatch.setattr(requests.Session, "get", fail)
    result = withaname.handler(json.dumps({"parameters": PARAMS}))
    assert "error" in result and "provider-secret" not in json.dumps(result)


def test_openapi_advertises_the_wire_type_and_gathering_schema():
    document = openapi.build_document({"withaname": withaname, "type:withaname": "gathering"}, "localhost", 6666)
    assert "gathering" in document["components"]["schemas"]["ModuleDescriptor"]["properties"]["type"]["enum"]
    assert "GATHERING" not in document["components"]["schemas"]["ModuleDescriptor"]["properties"]["type"]["enum"]


def test_listing_change_or_redirect_is_an_explicit_failure(transport, monkeypatch):
    bodies, _ = transport
    bodies[withaname.SOURCE] = b"<html>Source unavailable</html>"
    assert "error" in withaname.handler(json.dumps({"parameters": PARAMS}))
    response = requests.Response()
    response.status_code = 302
    response._content = b""
    response._content_consumed = True
    with patch.object(requests.Session, "get", return_value=response):
        assert "error" in withaname.handler(json.dumps({"parameters": PARAMS}))


class TestGatheringHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous = service.MODULES_HANDLERS.copy()
        self.cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"withaname": withaname, "type:withaname": "gathering"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        modules_dir = Path(misp_modules.__file__).parent / "modules"
        assert any(
            kind.name == "gathering" and module.name == "withaname.py"
            for kind, module in misp_modules.iterate_modules(modules_dir)
        )
        descriptor = json.loads(self.fetch("/modules").body)[0]
        assert descriptor["type"] == "gathering"
        assert descriptor["meta"]["module-type"] == ["gathering"]
        assert descriptor["mispattributes"]["parameters"] == withaname.PARAMETERS
        with patch.object(withaname, "gather", return_value=gathering.FeedBuilder().build()):
            response = self.fetch("/query", method="POST", body=json.dumps({"module": "withaname"}))
        assert response.code == 200
        assert json.loads(response.body) == {
            "gathering_version": 1,
            "source_format": "misp",
            "manifest": {},
            "events": {},
        }
