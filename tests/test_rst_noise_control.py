"""Unit tests for rst_noise_control (mocked rstapi, no network)."""

import json
from unittest.mock import patch

from misp_modules.modules.expansion import rst_noise_control


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    def ValueLookup(self, value):
        return self._payload


def _query(attribute, config=None):
    return json.dumps({
        "module": "rst_noise_control",
        "attribute": attribute,
        "config": config if config is not None else {"api_key": "test-key"},
    })


def _verdict_attr(result):
    obj = result["results"]["Object"][0]
    for a in obj["Attribute"]:
        if a.get("object_relation") == "verdict":
            return a
    for a in obj["Attribute"]:
        val = a.get("value") or ""
        if a.get("object_relation") == "text" or (a.get("type") == "text" and "Verdict:" in val):
            return a
    return obj["Attribute"][-1]


def _verdict_tags(result):
    obj = result["results"]["Object"][0]
    for a in obj["Attribute"]:
        if a.get("Tag"):
            return [t["name"] for t in a["Tag"]]
    return []


def test_rst_noise_control_drop_verdict():
    attribute = {"type": "ip-dst", "value": "8.8.8.8", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    payload = {"benign": "true", "reason": "Drop Public DNS/Services/Google", "type": "ipv4"}
    with patch.object(rst_noise_control.rstapi, "noisecontrol", return_value=_FakeClient(payload)):
        result = rst_noise_control.handler(_query(attribute))
    verdict = _verdict_attr(result)
    assert "BENIGN" in verdict["value"]
    tags = _verdict_tags(result)
    assert 'false-positive:risk="high"' in tags
    assert 'rstcloud:noise-control="drop"' in tags
    assert 'rstcloud:noise-category="Public DNS"' in tags


_UBUNTU_CATEGORY = "Ubuntu Server 26.04 LTS/pam_sepermit.so/"
_UBUNTU_TAG = "Ubuntu Server 26.04 LTS"


def test_rst_noise_control_ubuntu_benign_hash():
    attribute = {"type": "md5", "value": "abc", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    payload = {"benign": "true", "reason": f"Drop {_UBUNTU_CATEGORY}", "type": "md5"}
    with patch.object(rst_noise_control.rstapi, "noisecontrol", return_value=_FakeClient(payload)):
        result = rst_noise_control.handler(_query(attribute))
    verdict = _verdict_attr(result)
    assert "BENIGN" in verdict["value"]
    tags = _verdict_tags(result)
    assert 'false-positive:risk="high"' in tags
    assert 'rstcloud:noise-control="drop"' in tags
    assert f'rstcloud:noise-category="{_UBUNTU_TAG}"' in tags


def test_rst_noise_control_deep_category_tag():
    full = "NSRL 2025.03.1_modern/726.LibOVRPlatform64_1.dll/Meta - Oculus Platform SDK"
    attribute = {"type": "md5", "value": "abc", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    payload = {"benign": "true", "reason": f"Drop {full}", "type": "md5"}
    with patch.object(rst_noise_control.rstapi, "noisecontrol", return_value=_FakeClient(payload)):
        result = rst_noise_control.handler(_query(attribute))
    tags = _verdict_tags(result)
    assert 'rstcloud:noise-category="NSRL 2025.03.1_modern"' in tags


def test_rst_noise_control_not_in_database():
    attribute = {"type": "ip-dst", "value": "1.2.3.4", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    payload = {"benign": "false", "reason": "Not Found in our database", "type": "ipv4"}
    with patch.object(rst_noise_control.rstapi, "noisecontrol", return_value=_FakeClient(payload)):
        result = rst_noise_control.handler(_query(attribute))
    verdict = _verdict_attr(result)
    assert "not flagged" in verdict["value"].lower()
    assert _verdict_tags(result) == []
