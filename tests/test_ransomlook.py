import json
from unittest.mock import Mock, patch

from misp_modules.modules.expansion import ransomlook


class MockResponse:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload

    def raise_for_status(self):
        return None


def test_ransomlook_search_returns_ransomware_group_post_object():
    attribute = {"type": "text", "value": "Acme Corporation", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    query = {"module": "ransomlook", "attribute": attribute, "config": {}}
    payload = [
        {
            "group_name": "lockbit",
            "post_title": "Acme Corporation",
            "discovered": "2026-05-30T12:34:56",
            "post_url": "http://exampleonion.onion/acme",
            "description": "Victim leak post",
            "country": "US",
            "sector": "Manufacturing",
            "website": "https://acme.example",
        }
    ]

    with patch.object(ransomlook.requests, "get", return_value=MockResponse(payload)) as mocked_get:
        result = ransomlook.handler(json.dumps(query))

    mocked_get.assert_called_once_with(
        "https://www.ransomlook.io/api/search",
        params={"q": "Acme Corporation"},
        headers={"User-Agent": "misp-modules"},
        timeout=30,
    )
    assert "Object" in result["results"]
    misp_object = result["results"]["Object"][0]
    assert misp_object["name"] == "ransomware-group-post"
    relations = {attribute["object_relation"]: attribute["value"] for attribute in misp_object["Attribute"]}
    assert relations["title"] == "Acme Corporation"
    assert relations["entity-name"] == "Acme Corporation"
    assert relations["ransomware-group"] == "lockbit"
    assert relations["date-published"] == "2026-05-30T12:34:56"
    assert relations["leak-site-url"] == "http://exampleonion.onion/acme"
    assert relations["website"] == "https://acme.example"


def test_ransomlook_reports_http_error():
    response = Mock(payload=None)
    response.status_code = 401
    response.raise_for_status.side_effect = ransomlook.requests.exceptions.HTTPError(response=response)
    query = {
        "module": "ransomlook",
        "attribute": {"type": "text", "value": "Acme", "uuid": "uuid"},
        "config": {},
    }

    with patch.object(ransomlook.requests, "get", return_value=response):
        assert ransomlook.handler(json.dumps(query)) == {"error": "RansomLook API returned HTTP status 401."}
