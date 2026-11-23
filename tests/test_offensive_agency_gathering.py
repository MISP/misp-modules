import base64
import json
import zipfile
from unittest.mock import Mock
from uuid import UUID

import pytest
import requests
from pymisp import MISPEvent

from misp_modules.lib import offensive_agency as provider
from misp_modules.lib.gathering import FeedBuilder, RevisionStore
from misp_modules.modules.expansion import offensive_agency_lookup as lookup
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
        assert options["stream"] and all(options["timeout"]) and not options["allow_redirects"]
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
            assert not event.get("Attribute") and not parsed.attributes
            assert parsed.objects
            attributes = [a for obj in event["Object"] for a in obj["Attribute"]]
            assert all(UUID(a["uuid"]).version == 5 and not a["to_ids"] for a in attributes)
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
    (stats,) = event["Object"]
    assert stats["name"] == "offensive-agency-statistics"
    assert stats["template_uuid"] == module.STATISTICS_TEMPLATE["uuid"]
    attributes = {a["object_relation"]: a for a in stats["Attribute"]}
    assert {r: int(a["value"]) for r, a in attributes.items() if a["type"] == "counter"} == {
        "tracked-ips": STATS["total"],
        "active-ips": STATS["active"],
        "new-ips": STATS["new"],
        "multi-agent-ips": STATS["multi"],
        "cohosted-c2-ips": STATS["with_c2"],
    }
    assert attributes["report-date"]["value"] == STATS["ref_day"] + "T00:00:00+00:00"
    assert attributes["source-url"]["value"] == module.SOURCE + "stats"
    assert all(a["disable_correlation"] for a in attributes.values())
    attachment = attributes["source-record"]
    assert json.loads(base64.b64decode(attachment["data"])) == STATS
    reordered = dict(reversed(list(STATS.items())))
    reordered["countries"] = list(reversed(STATS["countries"]))
    reordered["tools"] = {"example": {"ports": [[80, 1], [443, 8]]}}
    replies[url] = 200, reordered
    assert collect(tmp_path / "repeat", {}, state) == first
    replies[url] = 200, dict(STATS, active=101, new=0)
    changed = collect(tmp_path / "changed", {}, state)[uuid]
    (updated,) = changed["Object"]
    assert updated["uuid"] == stats["uuid"]
    assert {a["uuid"] for a in updated["Attribute"]} == {a["uuid"] for a in stats["Attribute"]}
    assert next(a["value"] for a in updated["Attribute"] if a["object_relation"] == "new-ips") == "0"
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
    assert not event["Attribute"]
    observation = next(obj for obj in event["Object"] if obj["name"] == provider.OBSERVATION_NAME)
    assert observation["name"] == "offensive-agency-observation"
    assert observation["template_uuid"] == provider.OBSERVATION_TEMPLATE["uuid"]
    assert UUID(observation["uuid"]).version == 5
    attributes = {a["object_relation"]: a for a in observation["Attribute"]}
    assert set(attributes) == {
        "ip",
        "source-url",
        "network-type",
        "country",
        "network-operator",
        "asn",
        "framework",
        "source-record",
    }
    address = attributes["ip"]
    assert (address["value"], address["first_seen"], address["last_seen"]) == (
        IP,
        "2026-11-18T00:00:00+00:00",
        "2026-11-20T00:00:00+00:00",
    )
    assert observation["first_seen"] == address["first_seen"]
    assert observation["last_seen"] == address["last_seen"]
    assert address["disable_correlation"] is True
    cloud_event, _ = module.host_observation(IP, dict(HOST, kind="cloud"))
    cloud_address = next(a for a in cloud_event["Object"][0]["Attribute"] if a["object_relation"] == "ip")
    assert cloud_address["disable_correlation"] is False
    assert (attributes["asn"]["type"], attributes["asn"]["value"]) == ("AS", HOST["asn"])
    assert attributes["framework"]["value"] == "example: probable"
    attachment = attributes["source-record"]
    assert attachment["type"] == "attachment"
    assert attachment["value"] == f"offensive-agency-host-{IP}.json"
    assert attachment["disable_correlation"] is True
    assert json.loads(base64.b64decode(attachment["data"])) == HOST
    assert collect(tmp_path / "repeat", params, state) == events
    replies[present] = 200, dict(HOST, last_seen="2026-11-21", tools={"example": "confirmed"})
    changed = collect(tmp_path / "changed", params, state)[uuid]
    updated = next(obj for obj in changed["Object"] if obj["name"] == provider.OBSERVATION_NAME)
    assert updated["uuid"] == observation["uuid"]
    assert {a["uuid"] for a in updated["Attribute"]} == {a["uuid"] for a in observation["Attribute"]}
    updated_attachment = next(a for a in updated["Attribute"] if a["object_relation"] == "source-record")
    assert updated_attachment["uuid"] == attachment["uuid"]
    assert json.loads(base64.b64decode(updated_attachment["data"])) == replies[present][1]
    assert int(changed["timestamp"]) > int(event["timestamp"])


@pytest.mark.parametrize(
    "params",
    [
        {"url": "https://example.org/"},
        {"all_hosts": "true"},
        {"all_hosts": 1},
        {"all_hosts": True, "asset_ips": [IP]},
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
    monkeypatch.setattr(provider, "MAX_RESPONSE_BYTES", 2)
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


def test_full_export_is_one_request_and_preserves_every_row(api, tmp_path):
    url = module.SOURCE + "api/hosts.json?scope=all"
    row = {k: v for k, v in HOST.items() if k != "services"}
    row["new_provider_field"] = {"source": "retained"}
    older = dict(row, ip="2001:db8::1", last_seen="2026-10-01", first_seen="2026-09-01")
    api[0][url] = 200, [row, older]
    params = {"all_hosts": True}
    state = tmp_path / "state"
    events = collect(tmp_path / "all", params, state)
    assert len(events) == 2 and api[1] == [url]
    for expected in (row, older):
        event = next(e for e in events.values() if e["info"].endswith(expected["ip"]))
        assert event["date"] == expected["last_seen"]
        observation = next(obj for obj in event["Object"] if obj["name"] == provider.OBSERVATION_NAME)
        raw = next(a for a in observation["Attribute"] if a["object_relation"] == "source-record")
        assert json.loads(base64.b64decode(raw["data"])) == expected
        assert module.host_observation(expected["ip"], expected)[0]["uuid"] != event["uuid"]
    api[0][url] = 200, [older, row, row]
    assert collect(tmp_path / "repeat", params, state) == events


@pytest.mark.parametrize("data", [{}, None, [42], [{}]])
def test_invalid_export(api, data):
    api[0][module.SOURCE + "api/hosts.json?scope=all"] = 200, data
    with pytest.raises(ValueError):
        module.gather({"all_hosts": True}, Mock())


def test_empty_export(api, tmp_path):
    api[0][module.SOURCE + "api/hosts.json?scope=all"] = 200, []
    assert collect(tmp_path / "empty", {"all_hosts": True}, tmp_path / "state") == {}


def test_export_budget_and_cancel_between_rows(api, monkeypatch):
    api[0][module.SOURCE + "api/hosts.json?scope=all"] = 200, [HOST, dict(HOST, ip="192.0.2.2")]
    builder = Mock()
    builder.add.side_effect = lambda *_: setattr(builder.check_cancel, "side_effect", ValueError("cancelled"))
    with pytest.raises(ValueError, match="cancelled"):
        module.gather({"all_hosts": True}, builder)
    assert builder.add.call_count == 1
    monkeypatch.setattr(provider, "MAX_EXPORT_BYTES", 10)
    with pytest.raises(ValueError, match="size budget"):
        module.gather({"all_hosts": True}, Mock())


SOURCE_ATTRIBUTE = {"type": "ip-src", "value": IP, "uuid": "7d40c53e-626d-4ddc-8522-c9907e3c25ad", "to_ids": True}


def expand(attribute):
    return lookup.handler(json.dumps({"attribute": attribute}))


def test_lookup_templates_and_references(api):
    url = module.SOURCE + "api/host/" + IP
    api[0][url] = 200, dict(HOST, ports={"example": [443, 443], "another": [443]})
    results = expand(SOURCE_ATTRIBUTE)["results"]
    assert results["Attribute"] == [SOURCE_ATTRIBUTE]
    observation, *network = results["Object"]
    assert observation["name"] == provider.OBSERVATION_NAME
    (ref,) = observation["ObjectReference"]
    assert (ref["referenced_uuid"], ref["relationship_type"]) == (SOURCE_ATTRIBUTE["uuid"], "describes")
    assert sorted(obj["name"] for obj in network) == ["domain-ip", "domain-ip", "ip-port"]
    related = {}
    for obj in network:
        (ref,) = obj["ObjectReference"]
        assert ref["object_uuid"] == obj["uuid"] and ref["referenced_uuid"] == observation["uuid"]
        for attr in obj["Attribute"]:
            assert attr["to_ids"] is False
            if attr["object_relation"] == "ip":
                assert attr["value"] == IP and attr["disable_correlation"] is True
            else:
                related[attr["object_relation"]] = attr
    assert (related["domain"]["type"], related["domain"]["value"]) == ("domain", "agent.example")
    assert related["domain"]["comment"] == "example: probable"
    assert (related["hostname"]["type"], related["hostname"]["value"]) == ("hostname", "host.example")
    assert (related["dst-port"]["type"], related["dst-port"]["value"]) == ("port", "443")
    assert "another, example" in related["dst-port"]["comment"]
    assert "Co-hosted C2 labels: example-cohosted-label" in observation["comment"]
    assert "Fingerprint families: page" in next(
        a["comment"] for a in observation["Attribute"] if a["object_relation"] == "framework"
    )
    assert expand(SOURCE_ATTRIBUTE)["results"] == results
    other = expand(dict(SOURCE_ATTRIBUTE, uuid="08577147-9821-47ea-92bd-9422ebf0667e"))["results"]
    assert {o["uuid"] for o in other["Object"]}.isdisjoint(o["uuid"] for o in results["Object"])
    assert api[1] == [url] * 3


def test_lookup_discovery_and_missing_ipv6(api):
    assert lookup.handler(False) is False
    assert lookup.introspection() == {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
    assert lookup.version()["module-type"] == ["expansion"]
    url = module.SOURCE + "api/host/2001:db8::1"
    api[0][url] = 404, None
    attribute = dict(SOURCE_ATTRIBUTE, type="ip-dst", value="2001:0db8::1")
    assert expand(attribute) == {"results": {"Attribute": [attribute], "Object": []}}
    assert api[1] == [url]


@pytest.mark.parametrize(
    "changes", [{"value": "fe80::1%eth0"}, {"value": "example.org"}, {"type": "domain"}, {"uuid": "bad"}]
)
def test_lookup_invalid_input_precedes_request(api, changes):
    assert "error" in expand({**SOURCE_ATTRIBUTE, **changes})
    assert not api[1]


@pytest.mark.parametrize(
    "status,record",
    [(302, {}), (429, {}), (200, []), (200, dict(HOST, domains=[{"name": ""}])), (200, dict(HOST, ip="192.0.2.2"))],
)
def test_lookup_upstream_errors(api, status, record):
    api[0][module.SOURCE + "api/host/" + IP] = status, record
    assert "error" in expand(SOURCE_ATTRIBUTE)
