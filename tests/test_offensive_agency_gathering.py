import base64
import json
import zipfile
from unittest.mock import Mock
from uuid import UUID

import pytest
import requests
from pymisp import MISPEvent

from misp_modules.lib.gathering import FeedBuilder, RevisionStore
from misp_modules.modules.gathering import offensive_agency as module

IP = "192.0.2.1"
STATS = {
    "ref_day": "2026-11-20",
    "total": 200,
    "active": 100,
    "new": 20,
    "multi": 12,
    "with_c2": 3,
    "countries": [["BE", 2], ["FR", 2]],
    "tools": {"example": {"ports": [[443, 8], [80, 1]]}},
    "days": ["2026-11-19", "2026-11-20"],
    "series": {"example": [4, 1]},
}
HOST = {
    "ip": IP,
    "first_seen": "2026-11-18",
    "last_seen": "2026-11-20",
    "kind": "cdn",
    "org": "Example operator",
    "asn": "AS64500",
    "country": "FR",
    "tools": {"example": "probable"},
    "domains": [{"name": "agent.example", "tools": {"example": "probable"}}],
    "rdns": ["host.example"],
    "ports": {"example": [443]},
    "families": {"example": ["page"]},
    "classes": ["Example device class"],
    "clusters": ["example-cluster"],
    "c2": ["example-cohosted-label"],
    "sources": ["ctiscan", "ctiurl"],
    "titles": ["Example console"],
    "services": [
        {
            "port": 443,
            "tls": True,
            "last_seen": "2026-11-20",
            "cert_cn": ["agent.example"],
            "classes": ["Example device class"],
            "products": ["Example product"],
            "titles": ["Example console"],
            "tools": ["example"],
        }
    ],
}


@pytest.fixture
def api(monkeypatch):
    replies, calls = {}, []

    def send(session, request, **options):
        calls.append(request.url)
        assert options["stream"] and all(options["timeout"])
        status, record = replies[request.url]
        response = requests.Response()
        response.status_code = status
        response._content = json.dumps(record).encode()
        response._content_consumed = True
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    return replies, calls


def collect(root, params, state):
    builder = FeedBuilder(root / "feed", RevisionStore(state))
    module.gather(params, builder)
    builder.archive(root / "feed.zip")
    with zipfile.ZipFile(root / "feed.zip") as archive:
        manifest = json.loads(archive.read("manifest.json"))
        events = {}
        for uuid, metadata in manifest.items():
            body = archive.read(uuid + ".json").decode()
            parsed = MISPEvent()
            parsed.load(body, validate=True)
            event = json.loads(body)["Event"]
            assert UUID(uuid).version == 5 and str(parsed.uuid) == uuid
            assert (
                event["Tag"]
                == metadata["Tag"]
                == [
                    {"name": 'misp-gathering:module="offensive_agency"', "local": True},
                    {"name": 'misp-gathering:source="offensive.agency"', "local": True},
                ]
            )
            assert event["timestamp"] == metadata["timestamp"] == metadata["publish_timestamp"]
            assert all(UUID(a["uuid"]).version == 5 and not a["to_ids"] for a in event["Attribute"])
            events[uuid] = event
    return events


def test_daily_statistics_repeat_and_correction(api, tmp_path):
    replies, calls = api
    url = module.SOURCE + "api/stats.json"
    replies[url] = 200, STATS
    state = tmp_path / "state"
    first = collect(tmp_path / "first", {}, state)
    uuid, event = next(iter(first.items()))
    assert event["date"] == STATS["ref_day"]
    attachment = next(a for a in event["Attribute"] if a["type"] == "attachment")
    assert json.loads(base64.b64decode(attachment["data"])) == STATS
    reordered = dict(reversed(list(STATS.items())))
    reordered["countries"] = list(reversed(STATS["countries"]))
    reordered["tools"] = {"example": {"ports": [[80, 1], [443, 8]]}}
    replies[url] = 200, reordered
    assert collect(tmp_path / "repeat", {}, state) == first
    replies[url] = 200, dict(STATS, active=101)
    changed = collect(tmp_path / "changed", {}, state)[uuid]
    assert {a["uuid"] for a in changed["Attribute"]} == {a["uuid"] for a in event["Attribute"]}
    assert int(changed["timestamp"]) > int(event["timestamp"])
    replies[url] = 200, dict(STATS, ref_day="2026-11-21")
    assert uuid not in collect(tmp_path / "next", {}, state)
    assert calls == [url] * 4


def test_asset_observations_deduplicate_and_skip_missing(api, tmp_path):
    replies, calls = api
    present = module.SOURCE + "api/host/" + IP
    missing = module.SOURCE + "api/host/2001:db8::1"
    replies[present] = 200, HOST
    replies[missing] = 404, None
    params = {"asset_ips": [IP, "2001:db8::1", IP, "2001:0db8::1"]}
    state = tmp_path / "state"
    events = collect(tmp_path / "first", params, state)
    assert len(events) == 1 and calls == [present, missing]
    uuid, event = next(iter(events.items()))
    address = next(a for a in event["Attribute"] if a["type"] == "ip-dst")
    assert (address["value"], address["first_seen"], address["last_seen"]) == (
        IP,
        "2026-11-18T00:00:00+00:00",
        "2026-11-20T00:00:00+00:00",
    )
    assert address["disable_correlation"] is True
    assert any(a["value"] == "example: probable" for a in event["Attribute"])
    attachment = next(a for a in event["Attribute"] if a["type"] == "attachment")
    assert attachment["value"] == f"offensive-agency-host-{IP}.json"
    assert attachment["disable_correlation"] is True
    assert json.loads(base64.b64decode(attachment["data"])) == HOST
    assert collect(tmp_path / "repeat", params, state) == events
    replies[present] = 200, dict(HOST, last_seen="2026-11-21", tools={"example": "confirmed"})
    changed = collect(tmp_path / "changed", params, state)[uuid]
    assert {a["uuid"] for a in changed["Attribute"]} == {a["uuid"] for a in event["Attribute"]}
    updated_attachment = next(a for a in changed["Attribute"] if a["type"] == "attachment")
    assert updated_attachment["uuid"] == attachment["uuid"]
    assert json.loads(base64.b64decode(updated_attachment["data"])) == replies[present][1]
    assert int(changed["timestamp"]) > int(event["timestamp"])


@pytest.mark.parametrize(
    "params",
    [
        {"url": "https://example.org/"},
        {"asset_ips": "192.0.2.1"},
        {"asset_ips": [123]},
        {"asset_ips": ["192.0.2.0/24"]},
        {"asset_ips": ["fe80::1%eth0"]},
        {"asset_ips": ["example.org"]},
    ],
)
def test_parameters_rejected_before_enqueue(monkeypatch, params):
    jobs = Mock()
    monkeypatch.setattr(module, "get_jobs", jobs)
    assert "error" in module.handler(json.dumps({"parameters": params}))
    jobs.assert_not_called()


def test_discovery_and_prepare(monkeypatch):
    jobs = Mock()
    monkeypatch.setattr(module, "get_jobs", lambda: jobs)
    assert module.handler(False) is False
    assert module.version()["module-type"] == ["gathering"]
    assert module.introspection()["gathering_version"] == 2
    assert module.handler('{"operation":"prepare"}') == jobs.submit.return_value
    jobs.submit.assert_called_once_with("offensive_agency", {}, {}, module.gather)


@pytest.mark.parametrize("status,body", [(302, {}), (429, {}), (404, {}), (200, []), (200, dict(STATS, new=-1))])
def test_invalid_statistics_fail_generation(api, status, body):
    api[0][module.SOURCE + "api/stats.json"] = status, body
    builder = Mock()
    with pytest.raises(ValueError):
        module.gather({}, builder)
    builder.add.assert_not_called()


def test_budget_and_cancellation(api, monkeypatch):
    api[0][module.SOURCE + "api/stats.json"] = 200, STATS
    monkeypatch.setattr(module, "MAX_RESPONSE_BYTES", 2)
    with pytest.raises(ValueError, match="size budget"):
        module.gather({}, Mock())
    builder = Mock()
    builder.check_cancel.side_effect = ValueError("cancelled")
    with pytest.raises(ValueError, match="cancelled"):
        module.gather({}, builder)
    assert len(api[1]) == 1


def test_invalid_host_observations():
    for changes in ({"ip": "192.0.2.2"}, {"first_seen": "2026-12-01"}, {"tools": []}, {"tools": {"x": "unknown"}}):
        with pytest.raises(ValueError):
            module.host_observation(IP, {**HOST, **changes})
