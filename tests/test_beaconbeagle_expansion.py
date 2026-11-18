import copy
import json
from unittest.mock import patch

import pytest
from pymisp import MISPAttribute, MISPEvent

from misp_modules.modules.expansion import beaconbeagle as module
from tests.test_beaconbeagle_common import ADDRESS, CONFIG_HASH, beacon_record, c2_record, config_record

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"


def query(kind="ip-dst", value=ADDRESS, config=None):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "original metadata"},
            "config": {} if config is None else config,
        }
    )


def coverage(result):
    obj = next(item for item in result["results"]["Object"] if item["name"] == "annotation")
    return json.loads(obj["Attribute"][0]["value"])


def assert_source(result):
    assert "results" in result, result
    original = next(item for item in result["results"]["Attribute"] if item["uuid"] == UUID)
    assert original["to_ids"] is True
    assert original["comment"] == "original metadata"
    for obj in result["results"]["Object"]:
        assert any(ref["referenced_uuid"] == UUID for ref in obj["ObjectReference"])
        assert all(not item["to_ids"] for item in obj["Attribute"])


def test_contract():
    assert module.handler(False) is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["module-type"] == ["expansion"]
    assert set(module.introspection()["input"]) <= set(MISPAttribute().known_types)


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"attribute":[]}'])
def test_bad_envelopes(raw):
    with patch.object(module, "Client") as factory:
        assert "error" in module.handler(raw)
        factory.assert_not_called()


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip-dst", "invalid"),
        ("domain", "bad/host"),
        ("sha256", "abc"),
        ("url", "https://name:password@example.org"),
        ("AS", "AS-1"),
        ("text", '{"countries":["USA"]}'),
        ("text", "{}"),
        ("text", "[]"),
        ("comment", "value"),
        ("domain", 42),
    ],
)
def test_bad_lookups_before_network(kind, value):
    with patch.object(module, "Client") as factory:
        assert "error" in module.handler(query(kind, value))
        factory.assert_not_called()


def test_ip_lookup_both_roles_and_configuration_dedup(config_record, beacon_record, c2_record):
    c2_record["key"] = ADDRESS
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.get.side_effect = [
            beacon_record,
            {"items": [{"hash": CONFIG_HASH}], "total": 1},
            c2_record,
            {"hashes": [CONFIG_HASH]},
            config_record,
        ]
        result = module.handler(query())
        assert_source(result)
        assert client.get.call_count == 5
        assert coverage(result)["configurations_returned"] == 1
        assert coverage(result)["limited"] is False
        assert any(obj["name"] == "malware-config" for obj in result["results"]["Object"])
        event = MISPEvent()
        event.load({"Event": {"info": "Lookup round trip", **copy.deepcopy(result["results"])}})
        assert all(obj.references for obj in event.objects)


def test_no_matches_preserves_source():
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.get.side_effect = [None, None]
        result = module.handler(query())
        assert_source(result)
        assert coverage(result)["configurations_returned"] == 0


@pytest.mark.parametrize(
    "kind,value", [("domain", "c2.example"), ("hostname", "c2.example"), ("url", "https://c2.example/api")]
)
def test_domain_and_url_search(kind, value, config_record):
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.get.side_effect = [None, {"items": [{"hash": CONFIG_HASH}], "total": 1}, config_record]
        result = module.handler(query(kind, value))
        assert_source(result)
        assert client.get.call_args_list[0].args[0] == "c2/c2.example"
        assert client.get.call_args_list[1].args[1]["q"] == value


def test_config_hash_lookup(config_record):
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.get.return_value = config_record
        result = module.handler(query("sha256", CONFIG_HASH))
        assert_source(result)
        client.get.assert_called_once_with("configs/" + CONFIG_HASH, missing=True)


def test_config_hash_lookup_with_hostname_location(config_record):
    config_record["locations"][0]["beacon_ip"] = "beacon.example"
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.get.return_value = config_record
        result = module.handler(query("sha256", CONFIG_HASH))
    assert_source(result)
    assert coverage(result)["configurations_returned"] == 1
    assert any(
        a["object_relation"] == "domain" and a["value"] == "beacon.example"
        for obj in result["results"]["Object"]
        for a in obj["Attribute"]
    )


def test_domain_lookup_keeps_c2_endpoint_and_enriched_asn(c2_record):
    c2_record["URLs"] = []
    c2_record["ip_enrichment"] = {ADDRESS: {"ASN": {"number": 64500}}}
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.get.side_effect = [c2_record, {"hashes": []}, {"items": [], "total": 0}]
        result = module.handler(query("domain", "c2.example"))
    assert_source(result)
    assert any(a["type"] == "AS" and a["value"] == "AS64500" for a in result["results"]["Attribute"])
    endpoint = next(
        obj
        for obj in result["results"]["Object"]
        if any(a["object_relation"] == "domain" and a["value"] == "c2.example" for a in obj["Attribute"])
        and any(a["object_relation"] == "dst-port" for a in obj["Attribute"])
    )
    assert {a["object_relation"]: a["value"] for a in endpoint["Attribute"]} == {
        "domain": "c2.example",
        "dst-port": "443",
        "protocol": "https",
    }


def test_arbitrary_field_pivot_reports_limits(config_record):
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.get.side_effect = [{"hashes": [CONFIG_HASH, "b" * 64], "total": 1000}, config_record]
        value = json.dumps({"path": "settings.SETTING_WATERMARK", "value": 123})
        result = module.handler(query("text", value, {"max_configs": 1}))
        assert_source(result)
        assert coverage(result)["limited"] is True
        assert coverage(result)["pivot_total"] == 1000
        assert client.get.call_args_list[0].args == (
            "pivot",
            {"path": "settings.SETTING_WATERMARK", "value": "123", "limit": 2, "offset": 0},
        )
        assert client.get.call_count == 2


@pytest.mark.parametrize(
    "kind,value,body", [("AS", "AS64500", {"asns": ["64500"]}), ("text", '{"countries":["fr"]}', {"countries": ["FR"]})]
)
def test_network_facets(kind, value, body, config_record):
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.post.return_value = {
            "hashes": [CONFIG_HASH],
            "beacons": [ADDRESS],
            "c2": ["c2.example"],
            "totals": {"hashes": 1, "beacons": 1, "c2": 1},
        }
        client.get.return_value = config_record
        result = module.handler(query(kind, value))
        assert_source(result)
        client.post.assert_called_once_with("netsearch/query", {**body, "limit": 11, "offset": 0})
        assert coverage(result)["network_beacons"] == [ADDRESS]


def test_failures_are_not_no_match():
    with patch.object(module, "Client") as factory:
        client = factory.return_value.__enter__.return_value
        client.get.side_effect = ValueError("HTTP 429")
        assert "error" in module.handler(query())


@pytest.mark.parametrize("value", [0, True, -1, 21, "bad"])
def test_bad_limits(value):
    with patch.object(module, "Client") as factory:
        assert "error" in module.handler(query(config={"max_configs": value}))
        factory.assert_not_called()
