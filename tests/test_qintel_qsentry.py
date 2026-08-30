import json
import sys
import types
from unittest.mock import patch

# qintel_helper is an optional third-party dependency of the module and is not
# installed in the test environment; provide a stub so the module is importable.
_fake_helper = types.ModuleType("qintel_helper")
_fake_helper.search_qsentry = lambda *args, **kwargs: {}
sys.modules.setdefault("qintel_helper", _fake_helper)

from misp_modules.modules.expansion import qintel_qsentry  # noqa: E402

UNTAGGED_PAYLOAD = {
    "asn": 64500,
    "asn_name": "example network",
    "descriptions": ["no threat activity observed"],
    "last_seen": "2024-01-01T00:00:00Z",
}


def _query(event_id=None):
    request = {
        "module": "qintel_qsentry",
        "attribute": {
            "type": "ip-src",
            "value": "1.2.3.4",
            "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b",
        },
        "config": {"token": "t"},
    }
    if event_id is not None:
        request["event_id"] = event_id
    return json.dumps(request)


def test_qintel_qsentry_handles_result_without_tags():
    with patch.object(qintel_qsentry, "search_qsentry", return_value=UNTAGGED_PAYLOAD):
        result = qintel_qsentry.handler(_query(event_id=1))

    assert "error" not in result
    enriched = [obj for obj in result["results"]["Object"] if obj["name"] == "Qintel Threat Enrichment"][0]
    enriched_attr = [attr for attr in enriched["Attribute"] if attr["object_relation"] == "enriched-attr"][0]
    assert enriched_attr.get("Tag", []) == []


def test_qintel_qsentry_hover_handles_result_without_tags():
    with patch.object(qintel_qsentry, "search_qsentry", return_value=UNTAGGED_PAYLOAD):
        result = qintel_qsentry.handler(_query())

    assert "error" not in result
    enriched = [obj for obj in result["results"]["Object"] if obj["name"] == "Qintel Threat Enrichment"][0]
    # pymisp drops attributes with an empty value, so the hover "Tags" attribute
    # is simply absent; the point is that the hover path no longer raises.
    assert [attr for attr in enriched["Attribute"] if attr["object_relation"] == "Tags"] == []
