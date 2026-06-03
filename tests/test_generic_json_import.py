import base64
import json

from misp_modules.modules.import_mod import generic_json_import


def _query(url="https://example.test/indicators.json", config=None):
    request = {"data": base64.b64encode(url.encode()).decode()}
    if config is not None:
        request["config"] = config
    return json.dumps(request)


def test_handler_maps_json_url_records_to_misp_objects(monkeypatch):
    def fake_fetch_json(url, timeout):
        assert url == "https://example.test/indicators.json"
        assert timeout == 30
        return [
            {"url": "https://example.com/a?b=c", "host": "example.com"},
            {"ip": "198.51.100.10", "port": 443},
            {"filename": "payload.exe", "sha256": "a" * 64},
        ]

    monkeypatch.setattr(generic_json_import, "fetch_json", fake_fetch_json)

    response = generic_json_import.handler(_query())

    objects = response["results"]["Object"]
    object_names = [misp_object["name"] for misp_object in objects]
    assert "url" in object_names
    assert "ip-port" in object_names
    assert "file" in object_names


def test_handler_can_import_unmapped_indicator_attributes(monkeypatch):
    monkeypatch.setattr(
        generic_json_import, "fetch_json", lambda url, timeout: {"indicator_value": "https://example.com"}
    )

    response = generic_json_import.handler(_query(config={"include_unmapped_attributes": True}))

    attributes = response["results"]["Attribute"]
    assert attributes[0]["type"] == "url"
    assert attributes[0]["value"] == "https://example.com"
