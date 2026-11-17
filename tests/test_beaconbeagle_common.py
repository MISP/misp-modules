import base64
import copy
import json
from unittest.mock import Mock

import pytest
import requests
from pymisp import MISPEvent

from misp_modules.lib import beaconbeagle as api

CONFIG_HASH = "a" * 64
ADDRESS = "192.0.2.1"
FIRST, LAST = 1794783919, 1794928000


@pytest.fixture
def config_record():
    return {
        "hash": CONFIG_HASH,
        "locations": [
            {
                "beacon_ip": ADDRESS,
                "beacon_port": "443",
                "arch": "x64",
                "Firsttime": FIRST,
                "lasttime": LAST,
                "protocol": "https",
            }
        ],
        "config": {
            "protocol": "https",
            "watermark": 123,
            "settings": {
                "SETTING_DOMAINS": "c2.example,/api",
                "SETTING_PORT": 443,
                "SETTING_USERAGENT": "Example agent",
                "SETTING_C2_RECOVER": [["append", 12]],
            },
        },
    }


@pytest.fixture
def beacon_record():
    return {
        "ip": ADDRESS,
        "Firsttime": FIRST,
        "lasttime": LAST,
        "asn": "64500",
        "ports": {
            "443": {
                "x64": {
                    "current": CONFIG_HASH,
                    "versions": [{"hash": CONFIG_HASH, "Firsttime": FIRST, "lasttime": LAST, "protocol": "https"}],
                }
            },
            "GEO": {"x64": {"current": None, "versions": []}},
        },
    }


@pytest.fixture
def c2_record():
    return {
        "key": "c2.example",
        "Host": "c2.example",
        "IPs": [ADDRESS],
        "Firsttime": FIRST,
        "lasttime": LAST,
        "URLs": ["https://c2.example/api"],
        "Endpoints": {
            "https:443": {
                "port": "443",
                "protocol": "https",
                "Firsttime": FIRST,
                "lasttime": LAST,
                "seen_in": [{"config_hash": CONFIG_HASH}],
            }
        },
    }


@pytest.mark.parametrize(
    "kind,fixture,key",
    [
        ("configs", "config_record", CONFIG_HASH),
        ("beacons", "beacon_record", ADDRESS),
        ("c2", "c2_record", "c2.example"),
    ],
)
def test_conversion_roundtrip_and_provenance(kind, fixture, key, request):
    data = request.getfixturevalue(fixture)
    event, observed = api.convert(kind, key, data)
    assert observed == LAST
    parsed = MISPEvent()
    parsed.load({"Event": copy.deepcopy(event)})
    assert str(parsed.uuid) == event["uuid"]
    raw = next(item for item in event["Attribute"] if item["type"] == "attachment")
    assert json.loads(base64.b64decode(raw["data"])) == api.normalized(kind, data)
    assert not any(item["to_ids"] for item in event["Attribute"])
    assert all(not item["to_ids"] for obj in event["Object"] for item in obj["Attribute"])
    assert not any(item["type"] == "sha256" for item in event["Attribute"])


def test_stable_identity_and_content(config_record):
    first, _ = api.convert("configs", CONFIG_HASH, config_record)
    reordered = copy.deepcopy(config_record)
    reordered["locations"] += [{**reordered["locations"][0], "arch": "x86"}]
    second, _ = api.convert("configs", CONFIG_HASH, reordered)
    reordered["locations"].reverse()
    third, _ = api.convert("configs", CONFIG_HASH, reordered)
    assert second == third
    assert first["uuid"] == second["uuid"]
    assert len(first["Object"]) == len(second["Object"])
    assert any(item["type"] == "domain" and item["value"] == "c2.example" for item in first["Attribute"])


def test_metadata_is_not_a_port(beacon_record):
    event, _ = api.convert("beacons", ADDRESS, beacon_record)
    ports = [a["value"] for obj in event["Object"] for a in obj["Attribute"] if a["object_relation"] == "dst-port"]
    assert ports == ["443"]


def test_beacon_detail_uses_version_times_when_top_level_times_are_absent(beacon_record):
    del beacon_record["Firsttime"], beacon_record["lasttime"]
    event, observed = api.convert("beacons", ADDRESS, beacon_record)
    assert observed == LAST
    assert event["date"] == api.timestamp(LAST).date().isoformat()


def test_observation_ranges_merge_across_architectures(config_record):
    config_record["locations"].append(
        {**config_record["locations"][0], "Firsttime": FIRST - 3600, "lasttime": LAST + 3600, "arch": "x86"}
    )
    event, _ = api.convert("configs", CONFIG_HASH, config_record)
    ip = next(
        obj
        for obj in event["Object"]
        if obj["name"] == "ip-port" and any(a["value"] == ADDRESS for a in obj["Attribute"])
    )
    assert all(a["first_seen"] == api.timestamp(FIRST - 3600).isoformat() for a in ip["Attribute"])
    assert all(a["last_seen"] == api.timestamp(LAST + 3600).isoformat() for a in ip["Attribute"])


@pytest.mark.parametrize("data", [None, [], {}, {"hash": "b" * 64}])
def test_invalid_config(data):
    with pytest.raises((ValueError, TypeError)):
        api.convert("configs", CONFIG_HASH, data)


@pytest.mark.parametrize("status", [301, 401, 403, 429, 500])
def test_http_error(status):
    with api.Client() as client:
        response = Mock(status_code=status)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        client.session.request = Mock(return_value=response)
        with pytest.raises(ValueError, match=str(status)):
            client.get("beacons")
        assert client.session.request.call_args.kwargs["allow_redirects"] is False
        assert client.session.request.call_args.kwargs["timeout"] == (5, 30)


def test_missing_network_errors_invalid_json_and_budget(monkeypatch):
    with api.Client() as client:
        response = Mock(status_code=404)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        client.session.request = Mock(return_value=response)
        assert client.get("configs/missing", missing=True) is None
        client.session.request.side_effect = requests.Timeout("private details")
        with pytest.raises(ValueError, match="failed or timed out"):
            client.get("beacons")
        client.session.request.side_effect = None
        response.status_code = 200
        response.iter_content.return_value = [b"invalid"]
        with pytest.raises(ValueError):
            client.get("beacons")
        monkeypatch.setattr(api, "MAX_RESPONSE_BYTES", 2)
        with pytest.raises(ValueError, match="size budget"):
            client.get("beacons")


def test_pages_respects_server_page_size_and_detects_incomplete():
    with api.Client() as client:
        client.get = Mock(side_effect=[{"items": [1], "total": 2}, {"items": [2], "total": 2}])
        assert list(client.pages("beacons", page_size=100)) == [1, 2]
        assert client.get.call_args.args[1]["offset"] == 1
        client.get = Mock(side_effect=[{"items": [1], "total": 2}, {"items": [], "total": 2}])
        with pytest.raises(ValueError, match="before the reported total"):
            list(client.pages("beacons"))


def test_cancellation_checked_before_network():
    def cancel():
        raise ValueError("cancelled")

    with api.Client(cancel) as client:
        client.session.request = Mock()
        with pytest.raises(ValueError, match="cancelled"):
            client.get("beacons")
        client.session.request.assert_not_called()
