import copy
import json
import zipfile
from unittest.mock import Mock, patch

import pytest

from misp_modules.lib.gathering import FeedBuilder, GatheringJobs, RevisionStore
from misp_modules.modules.gathering import beaconbeagle_gathering as module
from tests.test_beaconbeagle_common import ADDRESS, CONFIG_HASH, LAST, beacon_record, c2_record, config_record


def test_contract_and_submit():
    assert module.handler(False) is False
    assert module.introspection()["gathering_version"] == 2
    assert module.version()["module-type"] == ["gathering"]
    with patch.object(module, "get_jobs") as jobs:
        jobs.return_value.submit.return_value = {"status": "queued"}
        assert module.handler('{"parameters":{"dataset":"configs"}}') == {"status": "queued"}
        assert jobs.return_value.submit.call_args.args[0] == "beaconbeagle_gathering"


@pytest.mark.parametrize(
    "params",
    [
        {"dataset": "invalid"},
        {"url": "https://example.com"},
        {"page_size": 0},
        {"page_size": True},
        {"max_events": -1},
        {"date_from": "2026-11-18", "date_to": "2026-11-17"},
    ],
)
def test_invalid_parameters_before_enqueue(params):
    with patch.object(module, "get_jobs") as jobs:
        assert "error" in module.handler(json.dumps({"parameters": params}))
        jobs.assert_not_called()


def test_paginated_collection_archive_and_revisions(tmp_path, config_record):
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.pages.return_value = iter([{"hash": CONFIG_HASH}, {"hash": CONFIG_HASH}])
        client.get.return_value = config_record
        builder = FeedBuilder(tmp_path / "feed", revisions=RevisionStore(tmp_path / "state"))
        module.gather({"dataset": "configs"}, builder)
        builder.archive(tmp_path / "feed.zip")
        assert builder.event_count == 1
        client.get.assert_called_once_with("configs/" + CONFIG_HASH)
    with zipfile.ZipFile(tmp_path / "feed.zip") as archive:
        manifest = json.loads(archive.read("manifest.json"))
        event_uuid = next(iter(manifest))
        event = json.loads(archive.read(event_uuid + ".json"))["Event"]
        assert event["timestamp"] == str(LAST)
        assert manifest[event_uuid]["timestamp"] == event["timestamp"]
    changed = copy.deepcopy(config_record)
    changed["config"]["watermark"] = 456
    event2, timestamp2 = module.convert("configs", CONFIG_HASH, changed)
    builder2 = FeedBuilder(tmp_path / "second" / "feed", revisions=RevisionStore(tmp_path / "state"))
    builder2.add(event2, timestamp2)
    updated = json.loads((builder2.directory / (event_uuid + ".json")).read_text())["Event"]
    assert int(updated["timestamp"]) > LAST


def test_date_filter_and_budget(tmp_path, config_record):
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.pages.return_value = [{"hash": CONFIG_HASH}]
        client.get.return_value = config_record
        builder = Mock()
        module.gather({"dataset": "configs", "date_to": "2020-01-01"}, builder)
        builder.add.assert_not_called()
        second = copy.deepcopy(config_record)
        second["hash"] = "b" * 64
        client.pages.return_value = [{"hash": CONFIG_HASH}, {"hash": "b" * 64}]
        client.get.side_effect = [config_record, second]
        with pytest.raises(ValueError, match="max_events exceeded"):
            module.gather({"dataset": "configs", "max_events": 1}, builder)


def test_all_datasets(config_record, beacon_record, c2_record):
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.pages.side_effect = [[{"hash": CONFIG_HASH}], [{"ip": ADDRESS}], [{"key": "c2.example"}]]
        client.get.side_effect = [config_record, beacon_record, c2_record]
        builder = Mock()
        module.gather({}, builder)
        assert builder.add.call_count == 3


def test_failed_generation_publishes_no_zip(tmp_path):
    manager = GatheringJobs(tmp_path, workers=1)
    with patch.object(module, "Client", side_effect=ValueError("offline")):
        job = manager.submit("beaconbeagle_gathering", {}, {}, module.gather)
        manager.executor.shutdown(wait=True)
    state = manager.status(job["job_id"])
    assert state["status"] == "failed"
    assert not (manager.path(job["job_id"]) / "feed.zip").exists()
