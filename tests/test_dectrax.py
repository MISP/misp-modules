import json
import pytest
from misp_modules.modules.expansion import dectrax


def test_introspection():
    res = dectrax.introspection()
    assert "input" in res
    assert "ip-src" in res["input"]
    assert "ip-dst" in res["input"]
    assert res["format"] == "misp_standard"


def test_version():
    info = dectrax.version()
    assert info["version"] == "1.0.0"
    assert "config" in info
    assert "api_url" in info["config"]


def test_handler_empty():
    assert dectrax.handler(False) is False


def test_handler_missing_attribute():
    res = dectrax.handler(json.dumps({}))
    assert "error" in res


def test_handler_invalid_ip():
    payload = {
        "attribute": {
            "type": "ip-src",
            "value": "not-an-ip",
            "uuid": "11111111-2222-3333-4444-555555555555"
        }
    }
    res = dectrax.handler(json.dumps(payload))
    assert "error" in res
    assert "not a valid" in res["error"]


def test_handler_successful_enrichment():
    payload = {
        "attribute": {
            "type": "ip-src",
            "value": "198.51.100.55",
            "uuid": "12345678-1234-1234-1234-123456789abc"
        },
        "config": {
            "add_threat_level_tag": True,
            "add_decoy_tag": True,
            "add_mitre_tag": True,
            "add_interdiction_tag": True
        }
    }
    res = dectrax.handler(json.dumps(payload))
    assert "error" not in res
    assert "results" in res
    results = res["results"]
    assert "Attribute" in results
    assert "Object" in results

    attr = results["Attribute"][0]
    assert attr["value"] == "198.51.100.55"
    tag_names = [t["name"] for t in attr.get("Tag", [])]
    assert any("dectrax:threat-level=" in t for t in tag_names)
    assert any("dectrax:decoy=" in t for t in tag_names)
    assert any("dectrax:mitre-technique=" in t for t in tag_names)

    obj = results["Object"][0]
    assert obj["name"] == "honeypot"
    obj_attrs = {a["object_relation"]: a["value"] for a in obj["Attribute"]}
    assert obj_attrs["ip"] == "198.51.100.55"
    assert "port" in obj_attrs
