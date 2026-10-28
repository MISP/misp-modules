import base64
import copy
import json
import os
import tempfile
import threading
import time
import tracemalloc
import zipfile
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
    manager = gathering.GatheringJobs(tmp_path / "state", workers=1)
    monkeypatch.setattr(gathering, "_jobs", manager)
    yield manager
    manager.executor.shutdown(wait=True)


def bundle(config, filename=FILENAME, deduplicate=True):
    event, timestamp = withaname.convert(config, filename, deduplicate)
    with tempfile.TemporaryDirectory() as root:
        builder = gathering.FeedBuilder(Path(root) / "feed")
        builder.add(event, timestamp)
        builder.archive(Path(root) / "feed.zip")
        return read_feed(builder.directory)


def read_feed(directory):
    return {
        "manifest": json.loads((directory / "manifest.json").read_text()),
        "events": {
            path.stem: json.loads(path.read_text()) for path in directory.glob("*.json") if path.name != "manifest.json"
        },
    }


def collect(params):
    with tempfile.TemporaryDirectory() as root:
        builder = gathering.FeedBuilder(Path(root) / "feed")
        try:
            withaname.gather(params, builder=builder)
            builder.archive(Path(root) / "feed.zip")
            return read_feed(builder.directory)
        except (ValueError, requests.RequestException) as exc:
            return {"error": str(exc)}


def ready(manager, identifier):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        state = manager.status(identifier)
        if state["status"] not in ("queued", "running"):
            return state
        time.sleep(0.01)
    raise AssertionError("job did not finish")


def test_standard_feed_round_trip_and_template(config, tmp_path):
    result = bundle(config)
    event, timestamp = withaname.convert(config, FILENAME)
    builder = gathering.FeedBuilder(tmp_path / "feed")
    builder.add(event, timestamp)
    archive_metadata = builder.archive(tmp_path / "feed.zip")
    assert archive_metadata["event_count"] == 1
    with zipfile.ZipFile(tmp_path / "feed.zip") as archive:
        assert set(archive.namelist()) == {"manifest.json", *[f"{key}.json" for key in result["events"]]}
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
        gathering.FeedBuilder(tmp_path / "feed")


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
        {"max_events": -1},
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
    result = collect(PARAMS)
    assert len(result["events"]) == 1
    assert [request.url for request, _ in calls] == [withaname.SOURCE, withaname.SOURCE + FILENAME]
    assert all(options["allow_redirects"] is False and options["timeout"] == (5, 15) for _, options in calls)


def test_limit_fails_instead_of_silently_truncating(transport):
    bodies, calls = transport
    bodies[withaname.SOURCE] += f'<a href="{FILENAME.replace("12-00-00", "13-00-00")}">next</a>'.encode()
    result = collect({**PARAMS, "max_events": 1})
    assert "error" in result and len(calls) == 1


def test_failed_configuration_returns_no_partial_feed(transport):
    bodies, _ = transport
    bodies[withaname.SOURCE + FILENAME] = b'{"targets": [null]}'
    assert set(collect(PARAMS)) == {"error"}


def test_source_and_output_size_limits(transport, monkeypatch, config, tmp_path):
    monkeypatch.setattr(withaname, "MAX_SOURCE_BYTES", 1)
    assert "error" in collect(PARAMS)
    builder = gathering.FeedBuilder(tmp_path / "feed")
    builder.max_event_bytes = 1
    event, timestamp = withaname.convert(config, FILENAME)
    with pytest.raises(ValueError, match="budget"):
        builder.add(event, timestamp)


def test_network_error_is_sanitized(monkeypatch, state_directory):
    def fail(*args, **kwargs):
        raise requests.ConnectionError("provider-secret")

    monkeypatch.setattr(requests.Session, "get", fail)
    job = withaname.handler(json.dumps({"parameters": PARAMS}))
    result = ready(state_directory, job["job_id"])
    assert result["status"] == "failed"
    assert "provider-secret" not in json.dumps(result)
    with pytest.raises(ValueError):
        state_directory.archive_path(job["job_id"])


def test_openapi_advertises_the_wire_type_and_gathering_schema():
    document = openapi.build_document({"withaname": withaname, "type:withaname": "gathering"}, "localhost", 6666)
    assert "gathering" in document["components"]["schemas"]["ModuleDescriptor"]["properties"]["type"]["enum"]
    assert "GATHERING" not in document["components"]["schemas"]["ModuleDescriptor"]["properties"]["type"]["enum"]
    assert "/gathering/jobs/{job_id}" in document["paths"]
    assert (
        "application/zip" in document["paths"]["/gathering/jobs/{job_id}/feed.zip"]["get"]["responses"]["200"][
            "content"
        ]
    )


def test_listing_change_or_redirect_is_an_explicit_failure(transport, monkeypatch):
    bodies, _ = transport
    bodies[withaname.SOURCE] = b"<html>Source unavailable</html>"
    assert "error" in collect(PARAMS)
    response = requests.Response()
    response.status_code = 302
    response._content = b""
    response._content_consumed = True
    with patch.object(requests.Session, "get", return_value=response):
        assert "error" in collect(PARAMS)


def test_large_feed_writes_bodies_to_disk_not_a_bundle(tmp_path):
    tracemalloc.start()
    try:
        builder = gathering.FeedBuilder(tmp_path / "feed")
        for index in range(160):
            event = {
                "uuid": gathering.stable_uuid(gathering.NAMESPACE, index),
                "info": "Large fixture",
                "date": "2026-10-01",
                "Orgc": {"uuid": gathering.stable_uuid(gathering.NAMESPACE, "org")},
                "Attribute": [
                    {
                        "uuid": gathering.stable_uuid(gathering.NAMESPACE, "attribute", index),
                        "type": "text",
                        "value": "x" * (256 * 1024),
                    }
                ],
            }
            builder.add(event, 1790856000)
        metadata = builder.archive(tmp_path / "large.zip")
        _, peak = tracemalloc.get_traced_memory()
        assert metadata["event_count"] == 160
        assert builder.bytes_written > 32 * 1024 * 1024
        assert not hasattr(builder, "events")
        assert peak < 8 * 1024 * 1024
    finally:
        tracemalloc.stop()


def test_ready_archives_survive_manager_restart_and_expire(state_directory, tmp_path):
    job = state_directory.submit("fixture", {}, {}, lambda *args, **kwargs: None)
    result = ready(state_directory, job["job_id"])
    assert result["status"] == "ready"
    second = gathering.GatheringJobs(tmp_path / "state", workers=1)
    try:
        assert second.status(job["job_id"]) == result
        assert second.archive_path(job["job_id"]).is_file()
        path = second.path(job["job_id"])
        metadata = json.loads((path / "status.json").read_text())
        metadata["expires_at"] = 0
        second._write(path, metadata)
        with pytest.raises(FileNotFoundError):
            second.status(job["job_id"])
        assert not path.exists()
    finally:
        second.executor.shutdown(wait=True)


def test_interrupted_generation_is_never_downloadable(state_directory):
    identifier = "a" * 64
    path = state_directory.path(identifier)
    path.mkdir()
    state_directory._write(
        path,
        {"gathering_version": 2, "job_id": identifier, "status": "running", "owner_pid": 99999999, "owner_started": 0},
    )
    assert state_directory.status(identifier)["status"] == "failed"
    with pytest.raises(ValueError):
        state_directory.archive_path(identifier)


def test_delete_cancels_running_generation_and_removes_partial_files(state_directory):
    entered = threading.Event()

    def producer(params, builder, config):
        entered.set()
        while True:
            builder.check_cancel()
            time.sleep(0.01)

    job = state_directory.submit("fixture", {}, {}, producer)
    assert entered.wait(2)
    state_directory.delete(job["job_id"])
    state_directory.executor.shutdown(wait=True)
    assert not state_directory.path(job["job_id"]).exists()


def test_failed_job_does_not_publish_an_archive(state_directory):
    def producer(*args, **kwargs):
        raise ValueError("provider-secret")

    job = state_directory.submit("fixture", {}, {}, producer)
    result = ready(state_directory, job["job_id"])
    assert result["status"] == "failed" and "provider-secret" not in json.dumps(result)
    assert not (state_directory.path(job["job_id"]) / "feed").exists()
    assert not (state_directory.path(job["job_id"]) / "feed.zip").exists()


class TestGatheringHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous = service.MODULES_HANDLERS.copy()
        self.cache = service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"withaname": withaname, "type:withaname": "gathering"})
        service.ListModules.CACHE = None
        return Application(
            [
                (r"/modules", service.ListModules),
                (r"/query", service.QueryModule),
                (r"/gathering/jobs/([0-9a-f]{64})", service.GatheringJob),
                (r"/gathering/jobs/([0-9a-f]{64})/feed\.zip", service.GatheringArchive),
            ]
        )

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
        with patch.object(withaname, "gather", return_value=None):
            response = self.fetch("/query", method="POST", body=json.dumps({"module": "withaname"}))
            job = json.loads(response.body)
            identifier = job["job_id"]
            assert job["gathering_version"] == 2 and "events" not in job
            state = ready(gathering.get_jobs(), identifier)
        assert state["status"] == "ready"
        chunks = []
        response = self.fetch(f"/gathering/jobs/{identifier}/feed.zip", streaming_callback=chunks.append)
        assert response.code == 200
        assert response.headers["Content-Type"] == "application/zip"
        assert sum(map(len, chunks)) == state["archive_size"]
        assert self.fetch(f"/gathering/jobs/{identifier}", method="DELETE").code == 204
        assert self.fetch(f"/gathering/jobs/{identifier}").code == 404

    def test_prepare_returns_before_slow_generation_finishes(self):
        gate = threading.Event()

        def slow(parameters, builder, config):
            assert gate.wait(3)
            builder.check_cancel()

        try:
            with patch.object(withaname, "gather", side_effect=slow):
                response = self.fetch("/query", method="POST", body=json.dumps({"module": "withaname", "timeout": 1}))
                job = json.loads(response.body)
                assert "job_id" in job and len(response.body) < 1024
                assert self.fetch(f"/gathering/jobs/{job['job_id']}/feed.zip").code == 409
                assert json.loads(self.fetch(f"/gathering/jobs/{job['job_id']}").body)["status"] in (
                    "queued",
                    "running",
                )
        finally:
            gate.set()
        assert ready(gathering.get_jobs(), job["job_id"])["status"] == "ready"
