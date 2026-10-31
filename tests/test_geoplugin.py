import json
from copy import deepcopy
from unittest.mock import Mock

import pytest
import requests

from misp_modules.modules.expansion import geoplugin

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SECRET = "test-geoplugin-secret"
ANSWER = {
    "geoplugin_request": "8.8.8.8",
    "geoplugin_status": "200",
    "geoplugin_countryName": "United States",
    "geoplugin_countryCode": "US",
    "geoplugin_regionName": "California",
    "geoplugin_city": "Mountain View",
    "geoplugin_postal_code": "94043",
    "geoplugin_latitude": "37.386",
    "geoplugin_longitude": -122.0838,
    "geoplugin_locationAccuracyRadius": 20,
    "geoplugin_continentName": "North America",
    "geoplugin_timezone": "America/Los_Angeles",
    "geoplugin_credit": "Includes GeoLite2 data created by MaxMind.",
}


def query(kind="ip-src", value="8.8.8.8", **overrides):
    request = {
        "module": "geoplugin",
        "attribute": {"type": kind, "value": value, "uuid": UUID, "to_ids": True, "comment": "source context"},
        "config": {"api_key": SECRET},
    }
    request.update(overrides)
    return json.dumps(request)


@pytest.fixture
def api(monkeypatch):
    response = Mock(status_code=200)
    response.json.return_value = deepcopy(ANSWER)
    get = Mock(return_value=response)
    monkeypatch.setattr(geoplugin.requests, "get", get)
    return get


def location(result):
    assert "results" in result, result
    objects = result["results"]["Object"]
    assert len(objects) == 1
    assert objects[0]["name"] == "geolocation"
    return objects[0]


def values(obj):
    return {a["object_relation"]: a["value"] for a in obj["Attribute"]}


@pytest.mark.parametrize(
    "kind,value", [("ip-src", "8.8.8.8"), ("ip-dst", "8.8.8.8"), ("domain|ip", "dns.google|8.8.8.8")]
)
def test_lookup_maps_location_and_preserves_source(api, kind, value):
    result = geoplugin.handler(query(kind, value))
    obj = location(result)
    assert values(obj) == {
        "country": "United States",
        "countrycode": "US",
        "region": "California",
        "city": "Mountain View",
        "zipcode": "94043",
        "latitude": 37.386,
        "longitude": -122.0838,
        "accuracy-radius": 20.0,
        "text": "timezone: America/Los_Angeles",
    }
    assert {a["value"] for a in obj["Attribute"] if a["object_relation"] == "text"} == {
        "continent: North America",
        "timezone: America/Los_Angeles",
    }
    assert "MaxMind" in obj["comment"]
    assert all(a["to_ids"] is False for a in obj["Attribute"])
    references = obj["ObjectReference"]
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in references] == [(UUID, "related-to")]
    original = result["results"]["Attribute"][0]
    assert original["uuid"] == UUID
    assert original["type"] == kind
    assert original["value"] == value
    assert original["comment"] == "source context"
    assert original["to_ids"] is True
    api.assert_called_once_with(
        "https://api.geoplugin.com/",
        params={"ip": "8.8.8.8", "auth": SECRET},
        headers={"Accept": "application/json", "User-Agent": "misp-modules-geoplugin/1"},
        timeout=(5, 30),
        allow_redirects=False,
    )


@pytest.mark.parametrize("status", [200, "200", 206, "206"])
def test_partial_result_and_zero_coordinates(api, status):
    api.return_value.json.return_value = {
        "geoplugin_status": status,
        "geoplugin_request": "8.8.8.8",
        "geoplugin_countryCode": "US",
        "geoplugin_regionName": None,
        "geoplugin_region": "Some region",
        "geoplugin_city": "",
        "geoplugin_latitude": 0,
        "geoplugin_longitude": "0",
        "geoplugin_locationAccuracyRadius": "null",
        "geoplugin_timezone": "null",
    }
    assert values(location(geoplugin.handler(query()))) == {
        "countrycode": "US",
        "region": "Some region",
        "latitude": 0.0,
        "longitude": 0.0,
    }


def test_partial_http_status(api):
    api.return_value.status_code = 206
    assert location(geoplugin.handler(query()))


@pytest.mark.parametrize("raw", ["{", "null", "[]", "1", "{}", '{"attribute": []}', '{"attribute":{"type":"ip-src"}}'])
def test_invalid_envelope_never_calls_api(api, raw):
    assert "error" in geoplugin.handler(raw)
    api.assert_not_called()


@pytest.mark.parametrize(
    "kind,value",
    [
        ("domain", "dns.google"),
        ("ip-src", "dns.google"),
        ("ip-src", None),
        ("ip-src", 1234),
        ("ip-src", ""),
        ("ip-src", "8.8.8.8/32"),
        ("ip-src", "8.8.8.8&ip=1.1.1.1"),
        ("ip-src", "2001:4860:4860::8888"),
        ("ip-src", "10.0.0.1"),
        ("ip-dst", "127.0.0.1"),
        ("ip-src", "169.254.0.1"),
        ("ip-src", "100.64.0.1"),
        ("ip-src", "192.0.2.1"),
        ("ip-src", "224.0.0.1"),
        ("domain|ip", "dns.google"),
        ("domain|ip", "|8.8.8.8"),
        ("domain|ip", "dns.google|8.8.8.8|1.1.1.1"),
    ],
)
def test_invalid_and_unsupported_addresses_never_call_api(api, kind, value):
    assert "error" in geoplugin.handler(query(kind, value))
    api.assert_not_called()


@pytest.mark.parametrize("config", [None, {}, [], "invalid", {"api_key": ""}, {"api_key": " "}, {"api_key": 1}])
def test_missing_key_never_calls_api(api, config):
    assert "error" in geoplugin.handler(query(config=config))
    api.assert_not_called()


@pytest.mark.parametrize("uuid", [None, "", "not-a-uuid", 1234, [], {}])
def test_invalid_uuid_never_calls_api(api, uuid):
    attribute = {"type": "ip-src", "value": "8.8.8.8", "uuid": uuid}
    assert "error" in geoplugin.handler(query(attribute=attribute))
    api.assert_not_called()


def test_invalid_misp_metadata_never_calls_api(api):
    attribute = {"type": "ip-src", "value": "8.8.8.8", "uuid": UUID, "distribution": 100}
    assert "error" in geoplugin.handler(query(attribute=attribute))
    api.assert_not_called()


@pytest.mark.parametrize("status", [301, 401, 403, 404, 429, 500])
def test_http_errors(api, status):
    api.return_value.status_code = status
    api.return_value.reason = SECRET
    result = geoplugin.handler(query())
    assert result == {"error": f"geoPlugin HTTP error {status}."}
    api.return_value.json.assert_not_called()
    assert api.call_count == 1


@pytest.mark.parametrize("error", [requests.Timeout, requests.ConnectionError, requests.RequestException])
def test_transport_errors_do_not_expose_the_key(api, error):
    api.side_effect = error(f"https://api.geoplugin.com/?auth={SECRET}")
    result = geoplugin.handler(query())
    assert "error" in result
    assert SECRET not in json.dumps(result)
    assert api.call_count == 1


@pytest.mark.parametrize("status", [403, "429", 404, 500, None, True, {}, []])
def test_provider_errors_inside_http_200(api, status):
    api.return_value.json.return_value = {**ANSWER, "geoplugin_status": status, "geoplugin_message": SECRET}
    result = geoplugin.handler(query())
    assert "error" in result
    assert "results" not in result
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize("payload", [None, [], "error", 200])
def test_invalid_response_shape(api, payload):
    api.return_value.json.return_value = payload
    assert "error" in geoplugin.handler(query())


def test_invalid_response_json(api):
    api.return_value.json.side_effect = ValueError(SECRET)
    assert geoplugin.handler(query()) == {"error": "The geoPlugin API returned invalid JSON."}


@pytest.mark.parametrize("address", ["1.1.1.1", None, "", "not-an-ip", [], {}])
def test_response_must_identify_the_requested_ip(api, address):
    api.return_value.json.return_value = {**ANSWER, "geoplugin_request": address}
    assert geoplugin.handler(query()) == {"error": "The geoPlugin response does not match the queried IP address."}


def test_empty_location_does_not_create_empty_object(api):
    api.return_value.json.return_value = {
        "geoplugin_status": 200,
        "geoplugin_request": "8.8.8.8",
        "geoplugin_countryName": "null",
        "geoplugin_countryCode": False,
        "geoplugin_regionName": {},
        "geoplugin_city": [],
        "geoplugin_latitude": "NaN",
        "geoplugin_longitude": "Infinity",
        "geoplugin_locationAccuracyRadius": 10,
        "geoplugin_timezone": "UTC",
    }
    assert geoplugin.handler(query()) == {"error": "No geolocation data found for this IP address."}


@pytest.mark.parametrize(
    "field,value,relation",
    [
        ("geoplugin_latitude", 91, "latitude"),
        ("geoplugin_latitude", True, "latitude"),
        ("geoplugin_longitude", -181, "longitude"),
        ("geoplugin_latitude", "not-a-number", "latitude"),
        ("geoplugin_locationAccuracyRadius", -1, "accuracy-radius"),
        ("geoplugin_latitude", 10**400, "latitude"),
    ],
)
def test_invalid_numbers_are_omitted(api, field, value, relation):
    api.return_value.json.return_value[field] = value
    assert relation not in values(location(geoplugin.handler(query())))


def test_discovery():
    assert geoplugin.handler(False) is False
    assert geoplugin.introspection()["format"] == "misp_standard"
    assert geoplugin.version()["module-type"] == ["expansion", "hover"]
    assert geoplugin.version()["config"] == ["api_key"]
