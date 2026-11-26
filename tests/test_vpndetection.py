import json
import os
from unittest.mock import patch

import pytest
import requests

from misp_modules.modules.expansion import vpndetection

# A VPN server on a hosting network, looked up with a key.
VPN = json.loads(
    r"""{"ip":"45.83.91.1","is_bogon":false,"is_vpn":true,"is_hosting":true,"is_relay":false,"is_tor":false,"is_cdn":false,"is_resproxy":false,"is_dcproxy":false,"is_mobproxy":false,"is_pubproxy":false,"is_anycast":false,"is_carrier":false,"is_satellite":false,"is_ssh":false,"is_smtp":false,"is_web":false,"is_dns_resolver":false,"is_bittorrent":false,"vpn":{"provider":"nordvpn","provider_name":"NordVPN","last_seen":"2026-11-19","confidence":"low"},"hosting":{"provider":"m247","provider_name":"M247","confidence":"high","last_seen":"2026-11-18"},"relay":{},"tor":{},"cdn":{},"resproxy":{},"dcproxy":{},"mobproxy":{},"pubproxy":{},"carrier":{},"satellite":{},"ssh":{},"smtp":{},"web":[],"dns_resolver":{},"bittorrent":{},"location":{"continent":"EU","continent_name":"Europe","country":"SE","country_name":"Sweden","timezone":"Europe/Stockholm","currency_code":"SEK","currency_name":"Krona","currency_symbol":"SEK","flag_emoji":"🇸🇪","flag_unicode":"U+1F1F8 U+1F1EA","region":"Stockholm","region_code":"SE-AB","city":"Stockholm","postal_code":"164 74","latitude":59.32938,"longitude":18.06871,"accuracy_radius":10,"geoname_id":"2673730","dma_code":"","last_changed":"2026-10-01"},"asn":{"asn":9009,"name":"M247 Europe SRL","domain":"m247global.com","type":"hosting","prefix":"45.83.91.0/24","country":"RO","rpki_status":"not_found"},"company":{"name":"M247 Europe SRL","domain":"m247global.com","type":"hosting","country":"KH"},"hostname":"vlan3000.as06.stk1.se.m247.ro","abuse":{"email":"abuse@m247.ro","name":"GLOBALAXS NOC","phone":"","address":"1 Ball Green, Cobra Court, M32 0QT, Manchester - United Kingdom","country":"SE","network":"45.83.91.0-45.83.91.255","validated":false,"unvalidated_since":""},"cap_reached":false}"""  # noqa: E501
)
# A Tor exit looked up without a key: the hosting, CDN and proxy flags are left out.
TOR_KEYLESS = json.loads(
    r"""{"ip":"185.220.101.1","is_bogon":false,"is_vpn":false,"is_relay":false,"is_tor":true,"relay":{},"tor":{"provider":"","provider_name":"","confidence":"high","last_seen":"2026-11-17"},"location":{"continent":"EU","continent_name":"Europe","country":"DE","country_name":"Germany","timezone":"Europe/Berlin","currency_code":"EUR","currency_name":"Euro","currency_symbol":"€","flag_emoji":"🇩🇪","flag_unicode":"U+1F1E9 U+1F1EA"},"asn":{"asn":60729,"name":"Stiftung Erneuerbare Freiheit","domain":"zwiebelfreunde.de","type":"hosting","prefix":"185.220.101.0/24"}}"""  # noqa: E501
)
# An address no flag is set for, looked up without a key.
CLEAN_KEYLESS = json.loads(
    r"""{"ip":"8.8.8.8","is_bogon":false,"is_vpn":false,"is_relay":false,"is_tor":false,"relay":{},"tor":{},"location":{"continent":"NA","continent_name":"North America","country":"US","country_name":"United States","timezone":"America/Los_Angeles","currency_code":"USD","currency_name":"Dollar","currency_symbol":"$","flag_emoji":"🇺🇸","flag_unicode":"U+1F1FA U+1F1F8"},"asn":{"asn":15169,"name":"Google LLC","domain":"google.com","type":"hosting","prefix":"8.8.8.0/24"}}"""  # noqa: E501
)
# A satellite customer address, looked up with a key.
SATELLITE = json.loads(
    r"""{"ip":"98.97.16.1","is_bogon":false,"is_vpn":false,"is_hosting":false,"is_relay":false,"is_tor":false,"is_cdn":false,"is_resproxy":false,"is_dcproxy":false,"is_mobproxy":false,"is_pubproxy":false,"is_anycast":false,"is_carrier":false,"is_satellite":true,"is_ssh":false,"is_smtp":false,"is_web":false,"is_dns_resolver":false,"is_bittorrent":false,"vpn":{},"hosting":{},"relay":{},"tor":{},"cdn":{},"resproxy":{},"dcproxy":{},"mobproxy":{},"pubproxy":{},"carrier":{},"satellite":{"provider":"starlink","provider_name":"Starlink","orbit":"leo","segment":"mixed","country":"US","asn":14593,"confidence":"high"},"ssh":{},"smtp":{},"web":[],"dns_resolver":{},"bittorrent":{},"location":{"continent":"NA","continent_name":"North America","country":"US","country_name":"United States","timezone":"America/New_York","currency_code":"USD","currency_name":"Dollar","currency_symbol":"$","flag_emoji":"🇺🇸","flag_unicode":"U+1F1FA U+1F1F8","region":"Virginia","region_code":"US-VA","city":"Ashburn","postal_code":"20147","latitude":39.04372,"longitude":-77.48749,"accuracy_radius":500,"geoname_id":"4744870","dma_code":"511","last_changed":"2026-10-01"},"asn":{"asn":14593,"name":"Space Exploration Technologies Corporation","domain":"spacex.com","type":"isp","prefix":"98.97.16.0/23","country":"US","rpki_status":"valid"},"company":{"name":"SpaceX Services, Inc.","domain":"spacex.com","type":"isp","country":"US"},"hostname":"customer.ashnvax2.isp.starlink.com","abuse":{"email":"starlink-abuse@spacex.com","name":"Starlink Abuse","phone":"+1-310-363-6000","address":"1 Rocket Rd, Hawthorne, CA, 90250","country":"US","network":"98.97.16.0-98.97.16.255","validated":false,"unvalidated_since":"2025-03-08"},"cap_reached":false}"""  # noqa: E501
)
UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


class MockResponse:
    def __init__(self, payload, status_code=200, reason="OK"):
        self.payload = payload
        self.status_code = status_code
        self.reason = reason

    def json(self):
        if self.payload is None:
            raise requests.JSONDecodeError("Expecting value", "", 0)
        return self.payload


def _query(value="45.83.91.1", type_="ip-src", config=None):
    attribute = {"type": type_, "value": value, "uuid": UUID}
    config = {"api_key": "k"} if config is None else config
    return json.dumps({"module": "vpndetection", "attribute": attribute, "config": config})


def _run(response, query=None, **kwargs):
    with patch.object(vpndetection.requests, "get", side_effect=[response]) as get:
        result = vpndetection.handler(query or _query(**kwargs))
    return result, get


def _objects(result):
    return {obj["name"]: obj for obj in result["results"].get("Object", [])}


def _attributes(misp_object):
    attributes = {}
    for attribute in misp_object["Attribute"]:
        attributes.setdefault(attribute["object_relation"], []).append(attribute["value"])
    return attributes


def _references(misp_object):
    return [(r["referenced_uuid"], r["relationship_type"]) for r in misp_object["ObjectReference"]]


def test_vpn_with_key():
    result, get = _run(MockResponse(VPN))

    assert get.call_args.args == ("https://api.vpndetection.io/45.83.91.1",)
    assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer k"
    assert result["results"]["Attribute"][0]["value"] == "45.83.91.1"
    objects = _objects(result)
    assert set(objects) == {"geolocation", "asn", "vpndetection-ip"}
    assert _attributes(objects["geolocation"]) == {
        "countrycode": ["SE"],
        "country": ["Sweden"],
        "region": ["Stockholm"],
        "city": ["Stockholm"],
        "zipcode": ["164 74"],
        "latitude": [59.32938],
        "longitude": [18.06871],
        "accuracy-radius": ["10"],
    }
    assert _references(objects["geolocation"]) == [(UUID, "locates")]
    assert _attributes(objects["asn"]) == {
        "asn": ["AS9009"],
        "organization": ["M247 Europe SRL"],
        "subnet-announced": ["45.83.91.0/24"],
        "country": ["RO"],
    }
    assert _references(objects["asn"]) == [(UUID, "includes")]
    intelligence = objects["vpndetection-ip"]
    assert _attributes(intelligence) == {
        "ip": ["45.83.91.1"],
        "hostname": ["vlan3000.as06.stk1.se.m247.ro"],
        "company-name": ["M247 Europe SRL"],
        "company-domain": ["m247global.com"],
        "company-type": ["hosting"],
        "abuse-email": ["abuse@m247.ro"],
        "abuse-name": ["GLOBALAXS NOC"],
        "is-vpn": ["1"],
        "vpn-provider": ["NordVPN"],
        "vpn-confidence": ["low"],
        "vpn-last-seen": ["2026-11-19T00:00:00"],
        "is-hosting": ["1"],
        "hosting-provider": ["M247"],
        "hosting-confidence": ["high"],
        "hosting-last-seen": ["2026-11-18T00:00:00"],
    }
    assert intelligence["template_uuid"] == vpndetection.VPNDETECTION_TEMPLATE["uuid"]
    assert intelligence["meta-category"] == "network"
    assert not intelligence.get("comment")
    assert _references(intelligence) == [(UUID, "describes")]
    correlating = {a["object_relation"] for a in intelligence["Attribute"] if not a["disable_correlation"]}
    assert correlating == {"ip"}


def test_satellite():
    result, _ = _run(MockResponse(SATELLITE), value="98.97.16.1")

    attributes = _attributes(_objects(result)["vpndetection-ip"])
    assert attributes["is-satellite"] == ["1"]
    assert attributes["satellite-provider"] == ["Starlink"]
    assert attributes["hostname"] == ["customer.ashnvax2.isp.starlink.com"]
    assert "is-carrier" not in attributes


def test_carrier():
    carrier = {**SATELLITE, "is_satellite": False, "is_carrier": True, "carrier": {"name": "T-Mobile", "mcc": "310"}}
    result, _ = _run(MockResponse(carrier), value="98.97.16.1")

    attributes = _attributes(_objects(result)["vpndetection-ip"])
    assert attributes["is-carrier"] == ["1"]
    assert attributes["carrier-name"] == ["T-Mobile"]
    assert "is-satellite" not in attributes


def test_services():
    services = {**VPN, "is_anycast": True, "is_ssh": True, "is_dns_resolver": True}
    result, _ = _run(MockResponse(services))

    attributes = _attributes(_objects(result)["vpndetection-ip"])
    assert {"is-anycast", "is-ssh", "is-dns-resolver"} <= set(attributes)
    assert not {"is-smtp", "is-web", "is-bittorrent"} & set(attributes)


def test_tor_without_key():
    result, get = _run(MockResponse(TOR_KEYLESS), value="185.220.101.1", type_="ip-dst", config={})

    assert "Authorization" not in get.call_args.kwargs["headers"]
    intelligence = _objects(result)["vpndetection-ip"]
    assert _attributes(intelligence) == {
        "ip": ["185.220.101.1"],
        "is-tor": ["1"],
        "tor-confidence": ["high"],
        "tor-last-seen": ["2026-11-17T00:00:00"],
    }
    # The flags a keyless answer leaves out must not read as "no".
    assert intelligence["comment"] == vpndetection.PARTIAL_COMMENT


def test_blank_key_is_keyless():
    _, get = _run(MockResponse(CLEAN_KEYLESS), value="8.8.8.8", config={"api_key": "  "})

    assert "Authorization" not in get.call_args.kwargs["headers"]


def test_no_flag_set():
    result, _ = _run(MockResponse(CLEAN_KEYLESS), value="8.8.8.8", config={})

    objects = _objects(result)
    assert set(objects) == {"geolocation", "asn"}
    assert _attributes(objects["asn"])["asn"] == ["AS15169"]


def test_trial_spent_is_partial():
    spent = {**VPN, "trial_expired": True, **{f"is_{flag}": None for flag in vpndetection.KEYED_FLAGS}}
    result, _ = _run(MockResponse(spent))

    intelligence = _objects(result)["vpndetection-ip"]
    assert intelligence["comment"] == vpndetection.PARTIAL_COMMENT
    assert "is-hosting" not in _attributes(intelligence)


def test_ipv6():
    _, get = _run(MockResponse(CLEAN_KEYLESS), value=" 2001:4860:4860::8888 ")

    assert get.call_args.args == ("https://api.vpndetection.io/2001:4860:4860::8888",)


@pytest.mark.parametrize("value", ["10.0.0.1", "127.0.0.1", "::1", "192.168.1.1"])
def test_private_address_is_not_looked_up(value):
    with patch.object(vpndetection.requests, "get") as get:
        result = vpndetection.handler(_query(value=value))
    assert "private or reserved" in result["error"]
    get.assert_not_called()


def test_bogon_answer():
    result, _ = _run(MockResponse({**CLEAN_KEYLESS, "is_bogon": True}))
    assert "bogon" in result["error"]


def test_invalid_address():
    result = vpndetection.handler(_query(value="not-an-ip"))
    assert result["error"] == "not-an-ip is not a valid IP address."


def test_wrong_type():
    result = vpndetection.handler(_query(type_="domain"))
    assert result["error"] == "Wrong input attribute type."


def test_missing_attribute():
    result = vpndetection.handler(json.dumps({"module": "vpndetection", "config": {}}))
    assert "which should contain at least a type, a value and an uuid" in result["error"]


def test_api_error():
    result, _ = _run(MockResponse({"error": "invalid API key"}, status_code=401, reason="Unauthorized"))
    assert result["error"] == "VPNDetection API error 401: invalid API key"


def test_api_error_without_json():
    result, _ = _run(MockResponse(None, status_code=502, reason="Bad Gateway"))
    assert result["error"] == "VPNDetection API error 502: Bad Gateway"


def test_unreachable():
    with patch.object(vpndetection.requests, "get", side_effect=requests.ConnectionError("down")):
        result = vpndetection.handler(_query())
    assert result["error"] == "Could not reach the VPNDetection API: down"


def test_handler_without_query():
    assert vpndetection.handler() is False


def test_version_and_introspection():
    assert vpndetection.version()["config"] == ["api_key"]
    assert vpndetection.introspection() == {"input": ["ip-src", "ip-dst"], "format": "misp_standard"}


@pytest.mark.skipif(not os.environ.get("VPNDETECTION_LIVE"), reason="set VPNDETECTION_LIVE=1 to call the live API")
def test_live_tor_exit():
    query = json.dumps(
        {"module": "vpndetection", "attribute": {"type": "ip-src", "value": "185.220.101.1", "uuid": UUID}}
    )
    result = vpndetection.handler(query)
    objects = _objects(result)
    assert _attributes(objects["vpndetection-ip"])["is-tor"] == ["1"]
    assert _attributes(objects["asn"])["asn"] == ["AS60729"]
