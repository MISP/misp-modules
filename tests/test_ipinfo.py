import json
from copy import deepcopy
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import ipinfo

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
# Legacy paid response from issue #600; optional data is supplied by the subscription.
LEGACY = {
    "ip": "8.8.8.8",
    "hostname": "dns.google",
    "city": "Mountain View",
    "region": "California",
    "country": "US",
    "loc": "37.4056,-122.0775",
    "postal": "94043",
    "timezone": "America/Los_Angeles",
    "asn": {"asn": "AS15169", "name": "Google LLC", "domain": "google.com", "route": "8.8.8.0/24", "type": "business"},
    "company": {"name": "Google LLC", "domain": "google.com", "type": "business"},
    "privacy": {"vpn": False, "proxy": False, "tor": False, "relay": False, "hosting": False, "service": ""},
    "abuse": {
        "address": "US, CA, Mountain View, 1600 Amphitheatre Parkway, 94043",
        "country": "US",
        "email": "network-abuse@google.com",
        "name": "Abuse",
        "network": "8.8.8.0/24",
        "phone": "+1-650-253-0000",
    },
    "domains": {"ip": "8.8.8.8", "total": 10524, "domains": ["example.com", "example.net", "example.com"]},
}
# Official examples: https://ipinfo.io/developers/{lite,core,plus}-api
LITE = {
    "ip": "8.8.8.8",
    "asn": "AS15169",
    "as_name": "Google LLC",
    "as_domain": "google.com",
    "country_code": "US",
    "country": "United States",
    "continent_code": "NA",
    "continent": "North America",
}
CORE = {
    "ip": "8.8.8.8",
    "hostname": "dns.google",
    "geo": {
        "city": "Mountain View",
        "region": "California",
        "region_code": "CA",
        "country": "United States",
        "country_code": "US",
        "continent": "North America",
        "continent_code": "NA",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "timezone": "America/Los_Angeles",
        "postal_code": "94043",
    },
    "as": {"asn": "AS15169", "name": "Google LLC", "domain": "google.com", "type": "hosting"},
    "is_anonymous": False,
    "is_anycast": True,
    "is_hosting": True,
    "is_mobile": False,
    "is_satellite": False,
}
PLUS = {
    **CORE,
    "anonymous": {"is_vpn": True, "is_tor": False, "is_proxy": False, "is_relay": False, "name": "Example VPN"},
    "is_anonymous": True,
    "geo": {**CORE["geo"], "radius": 50, "last_changed": "2026-08-16"},
    "mobile": {"name": "Example carrier", "mcc": "520", "mnc": "05"},
}


def _query(config=None, value="8.8.8.8", type_="ip-src", attribute=None):
    return json.dumps(
        {
            "attribute": (
                attribute
                if attribute is not None
                else {
                    "type": type_,
                    "value": value,
                    "uuid": UUID,
                    "to_ids": True,
                    "comment": "Original attribute",
                }
            ),
            "config": {"token": "secret"} if config is None else config,
        }
    )


def _run(payload, **kwargs):
    response = Mock(status_code=200)
    response.json.return_value = deepcopy(payload)
    with patch.object(ipinfo.requests, "get", return_value=response) as get:
        result = ipinfo.handler(_query(**kwargs))
    return result, get


def _objects(result):
    return {obj["name"]: obj for obj in result["results"].get("Object", [])}


def _attributes(obj):
    attributes = {}
    for attribute in obj["Attribute"]:
        attributes.setdefault(attribute["object_relation"], []).append(attribute["value"])
    return attributes


def _context(result):
    return json.loads(_attributes(_objects(result)["annotation"])["text"][0])


def test_legacy_paid_response_and_issue_600_context():
    result, get = _run(LEGACY)
    objects = _objects(result)
    assert set(objects) == {"geolocation", "asn", "domain-ip", "annotation"}
    assert _attributes(objects["geolocation"]) == {
        "city": ["Mountain View"],
        "region": ["California"],
        "countrycode": ["US"],
        "zipcode": ["94043"],
        "latitude": ["37.4056"],
        "longitude": ["-122.0775"],
    }
    assert _attributes(objects["domain-ip"]) == {
        "hostname": ["dns.google"],
        "ip": ["8.8.8.8"],
        "domain": ["example.com", "example.net"],
    }
    assert _attributes(objects["asn"]) == {
        "asn": ["AS15169"],
        "description": ["Google LLC"],
        "subnet-announced": ["8.8.8.0/24"],
    }
    context = _context(result)
    for field in ("privacy", "abuse", "company", "timezone"):
        assert context[field] == LEGACY[field]
    assert context["as"] == {"domain": "google.com", "type": "business"}
    assert context["hosted_domains_total"] == 10524
    get.assert_called_once()


def test_legacy_free_org_without_optional_fields():
    result, _ = _run({"ip": "8.8.8.8", "org": "AS15169 Google LLC", "country": "US"})
    objects = _objects(result)
    assert set(objects) == {"geolocation", "asn"}
    assert _attributes(objects["asn"]) == {"asn": ["AS15169"], "description": ["Google LLC"]}
    assert _attributes(objects["geolocation"]) == {"countrycode": ["US"]}


def test_lite_country_name_is_not_used_as_countrycode():
    result, _ = _run(LITE, config={"token": "secret", "api": "lite"})
    objects = _objects(result)
    assert set(objects) == {"geolocation", "asn", "annotation"}
    assert _attributes(objects["geolocation"]) == {"countrycode": ["US"], "country": ["United States"]}
    assert _attributes(objects["asn"]) == {"asn": ["AS15169"], "description": ["Google LLC"]}
    assert _context(result) == {"as_domain": "google.com", "continent": "North America", "continent_code": "NA"}


@pytest.mark.parametrize("payload", [CORE, PLUS])
def test_lookup_nested_geo_as_and_network_context(payload):
    result, get = _run(payload, config={"token": "secret", "api": "lookup"})
    objects = _objects(result)
    geo = _attributes(objects["geolocation"])
    assert geo["countrycode"] == ["US"]
    assert geo["country"] == ["United States"]
    assert geo["zipcode"] == ["94043"]
    assert geo["latitude"] == [37.4056]
    assert _attributes(objects["asn"]) == {"asn": ["AS15169"], "description": ["Google LLC"]}
    context = _context(result)
    for field in ("is_anonymous", "is_anycast", "is_hosting", "is_mobile", "is_satellite"):
        assert context[field] is payload[field]
    assert context["geo"]["timezone"] == "America/Los_Angeles"
    if "anonymous" in payload:
        assert context["anonymous"] == payload["anonymous"]
        assert context["mobile"] == payload["mobile"]
        assert geo["accuracy-radius"] == ["50"]
    get.assert_called_once()


@pytest.mark.parametrize(
    "api, url",
    [
        (None, "https://ipinfo.io/2001:4860:4860::8888/json"),
        ("", "https://ipinfo.io/2001:4860:4860::8888/json"),
        ("legacy", "https://ipinfo.io/2001:4860:4860::8888/json"),
        ("lite", "https://api.ipinfo.io/lite/2001:4860:4860::8888"),
        ("lookup", "https://api.ipinfo.io/lookup/2001:4860:4860::8888"),
        (" LOOKUP ", "https://api.ipinfo.io/lookup/2001:4860:4860::8888"),
    ],
)
def test_api_selection_and_bearer_authentication(api, url):
    _, get = _run(
        {"ip": "2001:4860:4860::8888"},
        config={"token": " secret ", "api": api},
        value="2001:4860:4860::8888",
        type_="ip-dst",
    )
    get.assert_called_once_with(
        url, headers={"Authorization": "Bearer secret", "Accept": "application/json"}, timeout=10
    )
    assert "secret" not in get.call_args.args[0]


@pytest.mark.parametrize("api", ["legacy", "lite", "lookup"])
@pytest.mark.parametrize(
    "optional",
    [{}, {"geo": None, "asn": None, "as": None, "domains": None, "hostname": None, "city": None, "loc": None}],
)
def test_sparse_responses_do_not_create_empty_objects(api, optional):
    result, _ = _run({"ip": "8.8.8.8", **optional}, config={"token": "secret", "api": api})
    assert "Object" not in result["results"]
    assert result["results"]["Attribute"][0]["uuid"] == UUID


def test_zero_coordinates_are_preserved():
    result, _ = _run({"geo": {"latitude": 0, "longitude": 0}}, config={"token": "secret", "api": "lookup"})
    assert _attributes(_objects(result)["geolocation"]) == {"latitude": ["0"], "longitude": ["0"]}


def test_hosted_domains_without_hostname():
    result, _ = _run({"domains": {"domains": ["example.org"]}})
    assert _attributes(_objects(result)["domain-ip"]) == {"domain": ["example.org"], "ip": ["8.8.8.8"]}


def test_source_metadata_references_and_enrichment_detection():
    result, _ = _run(LEGACY)
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == UUID
    assert source["to_ids"] is True
    assert source["comment"] == "Original attribute"
    for name, obj in _objects(result).items():
        assert obj["template_uuid"]
        (reference,) = obj["ObjectReference"]
        assert reference["referenced_uuid"] == UUID
        assert (
            reference["relationship_type"]
            == {
                "geolocation": "locates",
                "asn": "includes",
                "domain-ip": "resolves",
                "annotation": "annotates",
            }[name]
        )
        assert all(a["to_ids"] is False for a in obj["Attribute"])
    assert all(a["disable_correlation"] for a in _objects(result)["annotation"]["Attribute"])


@pytest.mark.parametrize(
    "payload, error",
    [
        ({"bogon": True}, "reserved for special use"),
        ({"error": {"title": "Invalid token", "message": "secret"}}, "check your token and selected API"),
        ([], "unexpected response"),
        (None, "unexpected response"),
    ],
)
def test_api_response_errors(payload, error):
    result, _ = _run(payload)
    assert error in result["error"]
    assert "secret" not in result["error"]


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_http_errors_are_not_retried_or_downgraded(status):
    with patch.object(ipinfo.requests, "get", return_value=Mock(status_code=status)) as get:
        result = ipinfo.handler(_query(config={"token": "secret", "api": "lookup"}))
    assert str(status) in result["error"]
    get.assert_called_once()


@pytest.mark.parametrize("exception", [requests.Timeout("secret"), requests.ConnectionError("secret")])
def test_request_errors_do_not_leak_credentials(exception):
    with patch.object(ipinfo.requests, "get", side_effect=exception) as get:
        result = ipinfo.handler(_query())
    assert result == {"error": "Could not reach the IPinfo API."}
    get.assert_called_once()


def test_invalid_json_response():
    response = Mock(status_code=200)
    response.json.side_effect = requests.JSONDecodeError("Expecting value", "", 0)
    with patch.object(ipinfo.requests, "get", return_value=response):
        assert ipinfo.handler(_query()) == {"error": "The IPinfo API returned invalid JSON."}


@pytest.mark.parametrize(
    "kwargs, error",
    [
        ({"attribute": {"type": "ip-src", "value": "8.8.8.8"}}, "requires an"),
        ({"type_": "domain"}, "Wrong input"),
        ({"config": {}}, "Missing ipinfo config"),
        ({"config": {"token": "  "}}, "Missing ipinfo token"),
        ({"config": {"token": "secret", "api": "invalid"}}, "Invalid ipinfo api"),
        ({"value": "me"}, "valid IPv4 or IPv6"),
        ({"value": "8.8.8.8/24"}, "valid IPv4 or IPv6"),
        ({"value": "8.8.8.8?token=another"}, "valid IPv4 or IPv6"),
    ],
)
def test_invalid_inputs_do_not_call_api(kwargs, error):
    result, get = _run(LEGACY, **kwargs)
    assert error in result["error"]
    get.assert_not_called()


def test_introspection():
    assert ipinfo.handler(False) is False
    assert ipinfo.introspection() == {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}
    assert ipinfo.version()["config"] == ["token", "api"]
