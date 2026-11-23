import base64
import copy
import json
import zipfile
from unittest.mock import Mock, patch
from uuid import UUID

import pytest
from pymisp import MISPEvent

from misp_modules.lib.beaconbeagle import API, normalized
from misp_modules.lib.gathering import FeedBuilder, GatheringJobs
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


def object_attributes(event, name):
    return [attribute for obj in event["Object"] if obj["name"] == name for attribute in obj["Attribute"]]


def test_paginated_collection_archive_and_revisions(tmp_path, config_record):
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.pages.return_value = iter([{"hash": CONFIG_HASH}, {"hash": CONFIG_HASH}])
        client.get.return_value = config_record
        builder = FeedBuilder(tmp_path / "feed")
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
        assert (
            manifest[event_uuid]["Tag"]
            == event["Tag"]
            == [
                {"name": 'misp-gathering:module="beaconbeagle_gathering"', "local": True},
                {"name": 'misp-gathering:source="beaconbeagle.com"', "local": True},
            ]
        )
        parsed = MISPEvent()
        parsed.load(json.dumps({"Event": event}), validate=True)
        assert all(tag.local is True for tag in parsed.tags)
        assert not parsed.attributes
    changed = copy.deepcopy(config_record)
    changed["config"]["watermark"] = 456
    changed["locations"][0]["lasttime"] = LAST + 60
    event2, timestamp2 = module.convert("configs", CONFIG_HASH, changed, objects_only=True)
    builder2 = FeedBuilder(tmp_path / "second" / "feed")
    event2["Tag"] = event["Tag"]
    builder2.add(event2, timestamp2)
    updated = json.loads((builder2.directory / (event_uuid + ".json")).read_text())["Event"]
    assert int(updated["timestamp"]) == LAST + 60
    # Deployed configuration IDs must still address the existing MISP records.
    assert event_uuid == "48c26049-5ae8-5864-ab69-43feaa26c1a8"
    raw = next(a for a in object_attributes(updated, "annotation") if a["type"] == "attachment")
    original = next(a for a in object_attributes(event, "annotation") if a["type"] == "attachment")
    assert raw["uuid"] == original["uuid"]
    assert raw["uuid"] != "92bcdb00-d792-5613-aa56-8428945f4b13"  # Legacy event-level attachment.
    assert raw["timestamp"] == updated["timestamp"]
    config = next(obj for obj in updated["Object"] if obj["name"] == "malware-config")
    assert config["uuid"] == "a46e029e-2458-55ca-97af-add6b9322baa"
    assert config["timestamp"] == updated["timestamp"]
    children = updated["Attribute"] + updated["Object"] + [a for obj in updated["Object"] for a in obj["Attribute"]]
    assert all(item["timestamp"] == str(LAST + 60) for item in children)
    assert {obj["uuid"] for obj in updated["Object"]} == {obj["uuid"] for obj in event["Object"]}


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


def test_all_datasets_repeat_import(tmp_path, config_record, beacon_record, c2_record):
    def gather(directory):
        builder = FeedBuilder(directory / "feed")
        with patch.object(module, "Client") as factory:
            client = factory.return_value.__enter__.return_value
            client.pages.side_effect = [[{"hash": CONFIG_HASH}], [{"ip": ADDRESS}], [{"key": "c2.example"}]]
            client.get.side_effect = [config_record, beacon_record, c2_record]
            module.gather({}, builder)
        builder.archive(directory / "feed.zip")
        with zipfile.ZipFile(directory / "feed.zip") as archive:
            return {name: archive.read(name) for name in archive.namelist()}

    first = gather(tmp_path / "first")
    assert gather(tmp_path / "repeat") == first
    manifest = json.loads(first["manifest.json"])
    assert len(manifest) == 3
    records = {"configs": config_record, "beacons": beacon_record, "c2": c2_record}
    for uuid, metadata in manifest.items():
        event = json.loads(first[uuid + ".json"])["Event"]
        kind, key = event["info"].removeprefix("BeaconBeagle ").split(": ")
        assert not event.get("Attribute")
        assert (
            event["Tag"]
            == metadata["Tag"]
            == [
                {"name": 'misp-gathering:module="beaconbeagle_gathering"', "local": True},
                {"name": 'misp-gathering:source="beaconbeagle.com"', "local": True},
            ]
        )
        items = [event, *event["Object"], *(a for o in event["Object"] for a in o["Attribute"])]
        assert all(UUID(item["uuid"]).version == 5 and item["timestamp"] == metadata["timestamp"] for item in items)
        assert all(not a["to_ids"] for o in event["Object"] for a in o["Attribute"])
        source = {a["object_relation"]: a for a in object_attributes(event, "annotation")}
        assert source["ref"]["value"] == f"{API}{kind}/{key}"
        assert json.loads(base64.b64decode(source["attachment"]["data"])) == normalized(kind, records[kind])
        network = {a["value"] for a in object_attributes(event, "ip-port") if a["type"] in ("ip-dst", "domain")}
        assert ADDRESS in network
        if kind == "configs":
            assert "c2.example" in network
            (config,) = [obj for obj in event["Object"] if obj["name"] == "malware-config"]
            assert config["template_version"] == "3"
            assert [a["value"] for a in config["Attribute"] if a["type"] == "user-agent"] == ["Example agent"]
        if kind == "c2":
            assert "c2.example" in network
            assert [a["value"] for a in object_attributes(event, "url") if a["type"] == "url"] == c2_record["URLs"]


def test_invalid_endpoint_port_preserves_host_in_an_object(config_record):
    config_record["config"]["settings"]["SETTING_PORT"] = 0
    event, _ = module.convert("configs", CONFIG_HASH, config_record, objects_only=True)
    (endpoint,) = [obj for obj in event["Object"] if any(a["value"] == "c2.example" for a in obj["Attribute"])]
    assert endpoint["name"] == "ip-port"
    assert [a["object_relation"] for a in endpoint["Attribute"]] == ["domain"]
    assert not event.get("Attribute")


def test_origin_tags_preserve_converter_tags_and_do_not_modify_shared_conversion(config_record):
    event, observed = module.convert("configs", CONFIG_HASH, config_record, objects_only=True)
    assert "Tag" not in event  # This converter is also used by expansion.
    event["Tag"] = [{"name": "existing-source-tag", "local": False}]
    with patch.object(module, "Client") as factory, patch.object(module, "convert", return_value=(event, observed)):
        client = factory.return_value.__enter__.return_value
        client.pages.return_value = [{"hash": CONFIG_HASH}]
        builder = Mock()
        module.gather({"dataset": "configs"}, builder)
    generated = builder.add.call_args.args[0]
    assert generated["Tag"][0] == {"name": "existing-source-tag", "local": False}
    assert len(generated["Tag"]) == 3


def test_c2_feed_archive_includes_enriched_asns(tmp_path, c2_record):
    c2_record["ip_enrichment"] = {
        ADDRESS: {"ASN": {"number": 64500, "org": "Example network"}},
        "192.0.2.2": {"ASN": {"number": 64500}},
        "192.0.2.3": {"ASN": {"number": 64501}},
        "192.0.2.4": {"GEO": {"country": "FR"}},
    }
    assert "asn" not in c2_record
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.pages.return_value = [{"key": "c2.example"}]
        client.get.return_value = c2_record
        builder = FeedBuilder(tmp_path / "feed")
        module.gather({"dataset": "c2"}, builder)
        builder.archive(tmp_path / "feed.zip")
    with zipfile.ZipFile(tmp_path / "feed.zip") as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert len(manifest) == 1
        event = json.loads(archive.read(next(iter(manifest)) + ".json"))["Event"]
    assert not event.get("Attribute")
    asns = [a for a in object_attributes(event, "asn") if a["type"] == "AS"]
    assert sorted(a["value"] for a in asns) == ["AS64500", "AS64501"]
    assert all(a["to_ids"] is False for a in asns)
    assert event["timestamp"] == str(LAST)


def test_failed_generation_publishes_no_zip(tmp_path):
    manager = GatheringJobs(tmp_path, workers=1)
    with patch.object(module, "Client", side_effect=ValueError("offline")):
        job = manager.submit("beaconbeagle_gathering", {}, {}, module.gather)
        manager.executor.shutdown(wait=True)
    state = manager.status(job["job_id"])
    assert state["status"] == "failed"
    assert not (manager.path(job["job_id"]) / "feed.zip").exists()
