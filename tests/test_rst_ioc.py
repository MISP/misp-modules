"""Unit tests for rst_ioc (mocked rstapi, no network)."""

import json
from unittest.mock import patch

from misp_modules.modules.expansion import rst_ioc


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    def GetIndicator(self, value):
        return self._payload


def _query(attribute, config=None):
    return json.dumps({
        "module": "rst_ioc",
        "attribute": attribute,
        "config": config if config is not None else {"api_key": "test-key"},
    })


def test_rst_ioc_not_found_returns_text():
    attribute = {"type": "ip-dst", "value": "8.8.8.8", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    with patch.object(rst_ioc.rstapi, "ioclookup", return_value=_FakeClient({"error": "Not Found"})):
        result = rst_ioc.handler(_query(attribute))
    assert "Attribute" in result["results"]
    assert any("not found" in a["value"].lower() for a in result["results"]["Attribute"])


def test_rst_ioc_hit_returns_rst_ioc_object_with_score_tag():
    attribute = {"type": "domain", "value": "evil.example", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    payload = {
        "id": "rst-123",
        "ioc_type": "domain",
        "score": {"total": "82", "tags": "0.5", "frequency": "0.3"},
        "threat": ["akira_ransomware"],
        "fp": {"alarm": "false"},
    }
    with patch.object(rst_ioc.rstapi, "ioclookup", return_value=_FakeClient(payload)):
        result = rst_ioc.handler(_query(attribute))
    obj = result["results"]["Object"][0]
    assert obj["name"] in ("rst-ioc", "annotation")
    relations = {a.get("object_relation"): a for a in obj["Attribute"]}
    tag_target = relations.get("score-total") or relations.get("text") or obj["Attribute"][0]
    tag_names = [t["name"] for t in tag_target.get("Tag", [])]
    assert 'rstcloud:score-total="82"' in tag_names
    assert any("akira" in t.lower() for t in tag_names)


def test_rst_ioc_missing_api_key():
    attribute = {"type": "domain", "value": "evil.example", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    with patch.object(rst_ioc.rstapi, "ioclookup") as mock_lookup:
        result = rst_ioc.handler(_query(attribute, config={}))
    mock_lookup.assert_not_called()
    assert result == {"error": "An RST Cloud API key is required (set api_key in the module config)."}
