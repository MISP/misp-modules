import json
import time
from unittest.mock import MagicMock, Mock
from urllib.parse import parse_qs
from uuid import UUID
from zipfile import ZipFile

import certifi
import pytest

from misp_modules.lib.gathering import GatheringJobs
from misp_modules.modules.gathering import sinkdb


def record(kind, indicator, **fields):
    return {
        "type": kind,
        "indicator": indicator,
        "date_added": "2026-01-02 03:04:05 UTC",
        "source": "sinkhole",
        "classification": "listed",
        **fields,
    }


@pytest.mark.parametrize(
    "kind, indicator, relation, attribute_type, value",
    [
        ("ipv4", "192.0.2.1", "ip", "ip-dst", "192.0.2.1"),
        ("ipv6", "2001:0db8::1", "ip", "ip-dst", "2001:db8::1"),
        ("ipv4_range", "192.0.2.1/24", "ip", "ip-dst", "192.0.2.0/24"),
        ("ipv6_range", "2001:db8::1/48", "ip", "ip-dst", "2001:db8::/48"),
        ("nameserver", "NS.Example.test", "nameserver", "hostname", "ns.example.test"),
        ("domain_soa", "NS.Example.test", "soa-domain", "domain", "ns.example.test"),
        ("domain_soa", "soa@example.test", "soa-email", "dns-soa-email", "soa@example.test"),
        ("whois_email", "admin@example.test", "whois-email", "whois-registrant-email", "admin@example.test"),
        ("new_type", "new value", "indicator", "text", "new value"),
    ],
)
def test_sinkhole_object(kind, indicator, relation, attribute_type, value):
    obj, date = sinkdb.sinkhole_object(record(kind, indicator, expose_org=0, operator="private"))
    attributes = {a["object_relation"]: a for a in obj["Attribute"]}
    assert (attributes[relation]["type"], attributes[relation]["value"]) == (attribute_type, value)
    assert attributes["date-added"]["value"] == "2026-01-02T03:04:05+00:00"
    assert date == "2026-01-02"
    assert "operator" not in attributes
    assert obj["name"] == "sinkhole-server"
    assert obj["template_uuid"] == sinkdb.OBJECT_TEMPLATE["uuid"]
    assert UUID(obj["uuid"]).version == 5
    assert all(
        UUID(a["uuid"]).version == 5 and not a["to_ids"] and a["disable_correlation"] for a in attributes.values()
    )


@pytest.fixture
def export_api(monkeypatch):
    export = {"query_status": "ok", "results": []}
    pool = MagicMock()
    response = Mock(status=200)
    request = pool.return_value.__enter__.return_value.request
    request.return_value.__enter__.return_value = response
    response.stream.side_effect = lambda *args, **kwargs: iter([json.dumps(export).encode()])
    monkeypatch.setattr(sinkdb.urllib3, "PoolManager", pool)
    return export, request, response


def test_export_uses_certifi_ca_bundle(export_api):
    assert sinkdb.fetch("placeholder", lambda: None) == []
    sinkdb.urllib3.PoolManager.assert_called_once_with(ca_certs=certifi.where())


def test_fixed_event_job_and_revisions(monkeypatch, tmp_path, export_api):
    export, request, _ = export_api
    ipv4 = record("ipv4", "192.0.2.1", expose_org=1, operator="Example CERT")
    ipv6 = record("ipv6_range", "2001:db8::/48")
    config = {"api_key": "key+&placeholder"}

    def collect(jobs):
        monkeypatch.setattr(sinkdb, "get_jobs", lambda: jobs)
        job = sinkdb.handler(json.dumps({"operation": "prepare", "parameters": {}, "config": config}))
        identifier = job["job_id"]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and jobs.status(identifier)["status"] in ("queued", "running"):
            time.sleep(0.01)
        assert jobs.status(identifier)["event_count"] == 1
        with ZipFile(jobs.archive_path(identifier)) as archive:
            event_file = f"{sinkdb.EVENT_UUID}.json"
            assert set(archive.namelist()) == {"manifest.json", event_file}
            event = json.loads(archive.read(event_file))["Event"]
            manifest = json.loads(archive.read("manifest.json"))
            assert list(manifest) == [event["uuid"]] == [sinkdb.EVENT_UUID]
            assert manifest[event["uuid"]]["timestamp"] == event["timestamp"]
            assert config["api_key"].encode() not in archive.read(event_file)
        return event

    jobs = GatheringJobs(tmp_path, workers=1)
    try:
        export["results"] = [ipv4, ipv6, ipv4]
        event = collect(jobs)
    finally:
        jobs.executor.shutdown()

    # The revision survives a service restart and ordering changes upstream.
    jobs = GatheringJobs(tmp_path, workers=1)
    try:
        export["results"] = [ipv6, ipv4]
        assert collect(jobs) == event
        export["results"] = [ipv6, dict(ipv4, classification="query_only")]
        changed = collect(jobs)
        export["results"] = []
        empty = collect(jobs)
    finally:
        jobs.executor.shutdown()

    assert len(event["Object"]) == len(changed["Object"]) == 2
    assert empty["Object"] == event["Attribute"] == []
    assert int(empty["timestamp"]) > int(changed["timestamp"]) > int(event["timestamp"])
    assert event["distribution"] == "0" and event["published"] is False
    assert {"name": "tlp:amber"} in event["Tag"]
    ipv4_uuid = sinkdb.sinkhole_object(ipv4)[0]["uuid"]
    before, after = (
        {
            a["object_relation"]: a
            for a in next(obj for obj in revision["Object"] if obj["uuid"] == ipv4_uuid)["Attribute"]
        }
        for revision in (event, changed)
    )
    assert before["operator"]["value"] == "Example CERT"
    assert before["classification"]["uuid"] == after["classification"]["uuid"]
    assert after["classification"]["value"] == "query_only"
    assert after["classification"]["timestamp"] == changed["timestamp"]
    assert before["ip"] == after["ip"]
    assert request.call_args.args == ("POST", sinkdb.EXPORT_URL)
    assert request.call_args.kwargs["redirect"] is False
    assert parse_qs(request.call_args.kwargs["body"].decode()) == {
        "api_key": [config["api_key"]],
        "export": ["sinkholes"],
    }


def test_rejected_exports_never_become_events(monkeypatch, export_api):
    export, _, response = export_api
    builder = Mock()
    config = {"api_key": "placeholder"}
    export.update(query_status="invalid_api_key")
    with pytest.raises(ValueError, match="check the HTTPS API key"):
        sinkdb.gather({}, builder, config)
    export.update(query_status="ok", results={"unexpected": []})
    with pytest.raises(ValueError, match="results array"):
        sinkdb.gather({}, builder, config)
    export.update(results=[{}])
    with pytest.raises(ValueError, match="missing its indicator or type"):
        sinkdb.gather({}, builder, config)
    response.status = 302
    with pytest.raises(ValueError, match="HTTP 302"):
        sinkdb.gather({}, builder, config)
    response.status = 200
    monkeypatch.setattr(sinkdb, "MAX_EXPORT_BYTES", 8)
    with pytest.raises(ValueError, match="size budget"):
        sinkdb.gather({}, builder, config)
    builder.add.assert_not_called()


def test_missing_key_or_invalid_parameters_fail_before_queueing(monkeypatch):
    jobs = Mock()
    monkeypatch.setattr(sinkdb, "get_jobs", jobs)
    assert "HTTPS API key" in sinkdb.handler("{}")["error"]
    assert "takes no parameters" in sinkdb.handler('{"parameters":{"dataset":"scanners"}}')["error"]
    jobs.assert_not_called()
