import json
from unittest.mock import patch

import pytest
import requests

from misp_modules.modules.expansion import ipapi_is

# A VPN exit node looked up with a key.
VPN = json.loads(
    r"""{"ip":"85.203.46.163","rir":"RIPE","is_bogon":false,"is_mobile":false,"is_satellite":false,"is_anycast":false,"is_crawler":false,"is_datacenter":false,"is_tor":false,"is_proxy":false,"is_vpn":true,"is_abuser":true,"vpn":{"ip":"85.203.46.163","service":"Private Internet Access","url":"https://privateinternetaccess.com","type":"exit_node","last_seen":1791512121028,"last_seen_str":"2026-10-09T02:15:21.028Z","exit_node_region":"uk-london","country_code":"GB","city_name":"London","latitude":51.50853,"longitude":-0.12574},"company":{"name":"EXPRESS-EQUINIX-LONDON","abuser_score":"0.3086 (Very High)","domain":"falco-networks.com","type":"business","network":"85.203.46.0 - 85.203.46.255","netname":"Express-Equinix-London"},"abuse":{"name":"Jeroen van veen","address":"Falco IPR B.V., De Hoefsmid 11-13, 1851 PZ Heiloo, The Netherlands","email":"jeroen@falco-networks.com","phone":"+31 72 532 3744"},"asn":{"asn":212238,"abuser_score":"0.0327 (High)","route":"85.203.46.0/24","descr":"CDNEXT - Datacamp Limited, GB","country":"gb","active":true,"org":"Datacamp Limited","domain":"cogentco.com","abuse":"abuse@datacamp.co.uk","type":"isp","created":"2020-12-02","updated":"2026-07-14","rir":"RIPE"},"location":{"is_eu_member":false,"calling_code":"44","currency_code":"GBP","continent":"EU","country":"United Kingdom","country_code":"GB","state":"England","city":"London","latitude":51.50853,"longitude":-0.12574,"zip":"EC1A","timezone":"Europe/London","utcoffset":"+01:00","accuracy":"MEDIUM"}}"""  # noqa: E501
)
# A datacenter address that is also a Tor exit: the example response of https://ipapi.is/developers.html
DATACENTER = json.loads(
    r"""{"ip":"107.174.138.172","rir":"ARIN","is_bogon":false,"is_mobile":false,"is_satellite":false,"is_anycast":false,"is_crawler":false,"is_datacenter":true,"is_tor":true,"is_proxy":false,"is_vpn":false,"is_abuser":true,"datacenter":{"datacenter":"HostPapa","domain":"hostpapa.com","network":"107.172.0.0 - 107.175.255.255"},"company":{"name":"VPS ACE","abuser_score":"0.1016 (High)","domain":"vpsace.com","type":"business","network":"107.174.138.128 - 107.174.138.255","netname":"CC-107-174-138-0-25"},"abuse":{"name":"VPS ACE","address":"350 Main Street, Buffalo, NY, 14202, US","email":"support@vpsace.com","phone":"+1-855-587-7223"},"asn":{"asn":36352,"abuser_score":"0.0374 (High)","route":"107.174.138.0/24","descr":"AS-COLOCROSSING - HostPapa, US","country":"us","active":true,"org":"HostPapa","domain":"hostpapa.com","abuse":"net-abuse-global@hostpapa.com","type":"hosting","created":"2005-12-12","updated":"2024-01-04","rir":"ARIN"},"location":{"is_eu_member":false,"calling_code":"1","currency_code":"USD","continent":"NA","country":"United States","country_code":"US","state":"New York","city":"Buffalo","latitude":42.88645,"longitude":-78.87837,"zip":"14205","timezone":"America/New_York","local_time":"2026-08-01T14:32:13-04:00","local_time_unix":1785609133,"is_dst":true,"utcoffset":"-04:00","accuracy":"VERY_HIGH"},"elapsed_ms":0.05}"""  # noqa: E501
)
# The reduced response to a lookup without a key.
KEYLESS = json.loads(
    r"""{"ip":"187.13.12.227","is_bogon":false,"company":"PacketHub S.A.","asn":"AS212238 Datacamp Limited","city":"Bordeaux","region":"New Aquitaine","country":"France","lat":44.84048,"lon":-0.58079,"timezone":"Europe/Paris","docs":"https://ipapi.is/free-tier.html?ref=api"}"""  # noqa: E501
)
CLEAN = {**{k: v for k, v in DATACENTER.items() if k != "datacenter"}, **dict.fromkeys(ipapi_is._FLAGS, False)}
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


def _query(value="85.203.46.163", type_="ip-src", config=None):
    attribute = {"type": type_, "value": value, "uuid": UUID}
    config = {"api_key": "k"} if config is None else config
    return json.dumps({"module": "ipapi_is", "attribute": attribute, "config": config})


def _run(response, query=None, **kwargs):
    with patch.object(ipapi_is.requests, "post", side_effect=[response]) as post:
        result = ipapi_is.handler(query or _query(**kwargs))
    return result, post


def _objects(result):
    return {obj["name"]: obj for obj in result["results"].get("Object", [])}


def _attributes(misp_object):
    attributes = {}
    for attribute in misp_object["Attribute"]:
        attributes.setdefault(attribute["object_relation"], []).append(attribute["value"])
    return attributes


def _references(misp_object):
    return [(r["referenced_uuid"], r["relationship_type"]) for r in misp_object["ObjectReference"]]


def test_vpn_exit_node():
    result, _ = _run(MockResponse(VPN))

    assert result["results"]["Attribute"][0]["value"] == "85.203.46.163"
    objects = _objects(result)
    assert set(objects) == {"geolocation", "asn", "ipapi-is-ip"}
    assert _attributes(objects["geolocation"]) == {
        "countrycode": ["GB"],
        "country": ["United Kingdom"],
        "region": ["England"],
        "city": ["London"],
        "zipcode": ["EC1A"],
        "latitude": [51.50853],
        "longitude": [-0.12574],
    }
    assert _references(objects["geolocation"]) == [(UUID, "locates")]
    assert _attributes(objects["asn"]) == {
        "asn": ["AS212238"],
        "organization": ["Datacamp Limited"],
        "description": ["CDNEXT - Datacamp Limited, GB"],
        "subnet-announced": ["85.203.46.0/24"],
        "country": ["gb"],
    }
    assert _references(objects["asn"]) == [(UUID, "includes")]
    intelligence = objects["ipapi-is-ip"]
    assert _attributes(intelligence) == {
        "ip": ["85.203.46.163"],
        "is-vpn": ["1"],
        "is-abuser": ["1"],
        "vpn-service": ["Private Internet Access"],
        "vpn-type": ["exit_node"],
        "vpn-last-seen": ["2026-10-09T02:15:21.028000+00:00"],
        "company-name": ["EXPRESS-EQUINIX-LONDON"],
        "company-type": ["business"],
        "company-domain": ["falco-networks.com"],
        "company-abuser-score": ["0.3086 (Very High)"],
        "asn-abuser-score": ["0.0327 (High)"],
        "abuse-name": ["Jeroen van veen"],
        "abuse-email": ["jeroen@falco-networks.com"],
        "abuse-phone": ["+31 72 532 3744"],
        "abuse-address": ["Falco IPR B.V., De Hoefsmid 11-13, 1851 PZ Heiloo, The Netherlands"],
        "rir": ["RIPE"],
    }
    assert _references(intelligence) == [(UUID, "describes")]
    assert not intelligence.get("comment")
    assert [a["object_relation"] for a in intelligence["Attribute"] if not a["disable_correlation"]] == ["ip"]
    # MISP only creates objects that carry their template, even when PyMISP does not ship it yet.
    assert intelligence["template_uuid"] == "2961a5dc-0c3c-4e68-8d65-1565c118c723"
    assert intelligence["template_version"] == "1"
    assert intelligence["meta-category"] == "network"


def test_datacenter_and_tor_exit():
    result, _ = _run(MockResponse(DATACENTER), value="107.174.138.172")

    attributes = _attributes(_objects(result)["ipapi-is-ip"])
    assert [relation for relation in attributes if relation.startswith("is-")] == [
        "is-tor",
        "is-datacenter",
        "is-abuser",
    ]
    assert attributes["datacenter"] == ["HostPapa"]
    assert not [relation for relation in attributes if relation.startswith("vpn-")]


@pytest.mark.parametrize("flag", ipapi_is._FLAGS)
def test_each_flag(flag):
    result, _ = _run(MockResponse({**CLEAN, flag: True}), value="107.174.138.172")
    attributes = _attributes(_objects(result)["ipapi-is-ip"])
    assert [relation for relation in attributes if relation.startswith("is-")] == [flag.replace("_", "-")]


def test_clean_address_has_no_flags():
    result, _ = _run(MockResponse(CLEAN), value="107.174.138.172")
    attributes = _attributes(_objects(result)["ipapi-is-ip"])
    assert not [relation for relation in attributes if relation.startswith("is-")]
    assert attributes["company-name"] == ["VPS ACE"]


def test_crawler_name_and_unknown_location():
    result, _ = _run(MockResponse({**CLEAN, "is_crawler": "GoogleBot", "location": None}), value="107.174.138.172")

    objects = _objects(result)
    assert "geolocation" not in objects
    attributes = _attributes(objects["ipapi-is-ip"])
    assert attributes["is-crawler"] == ["1"]
    assert attributes["crawler"] == ["GoogleBot"]


def test_keyless_response():
    result, post = _run(MockResponse(KEYLESS), value="187.13.12.227", config={})

    assert post.call_args.kwargs["json"] == {"q": "187.13.12.227"}
    objects = _objects(result)
    assert set(objects) == {"geolocation", "asn", "ipapi-is-ip"}
    assert _attributes(objects["geolocation"]) == {
        "country": ["France"],
        "region": ["New Aquitaine"],
        "city": ["Bordeaux"],
        "latitude": [44.84048],
        "longitude": [-0.58079],
    }
    assert _attributes(objects["asn"]) == {"asn": ["AS212238"], "organization": ["Datacamp Limited"]}
    intelligence = objects["ipapi-is-ip"]
    assert _attributes(intelligence) == {"ip": ["187.13.12.227"], "company-name": ["PacketHub S.A."]}
    assert intelligence["comment"] == ipapi_is.KEYLESS_COMMENT


def test_keyless_response_with_unknown_fields():
    payload = {**dict.fromkeys(KEYLESS), "ip": "187.13.12.227", "is_bogon": False, "asn": "AS12322"}
    result, _ = _run(MockResponse(payload), value="187.13.12.227", config={})

    objects = _objects(result)
    assert set(objects) == {"asn"}
    assert _attributes(objects["asn"]) == {"asn": ["AS12322"]}


@pytest.mark.parametrize("type_, value", [("ip-src", "85.203.46.163"), ("ip-dst", "2A00:1450:4001::1")])
def test_key_is_sent_in_the_body(type_, value):
    _, post = _run(MockResponse(VPN), type_=type_, value=value, config={"api_key": " secret-key "})

    (url,), kwargs = post.call_args
    assert url == "https://api.ipapi.is/"
    assert kwargs["json"] == {"q": value.lower(), "key": "secret-key"}
    assert "params" not in kwargs
    assert kwargs["timeout"] == 10
    sent = requests.Request("POST", url, json=kwargs["json"], headers=kwargs["headers"]).prepare()
    assert sent.headers["Content-Type"] == "application/json"
    assert "secret-key" not in sent.url


@pytest.mark.parametrize("config", [{}, {"api_key": ""}, {"api_key": "   "}, {"api_key": None}])
def test_no_key_field_without_api_key(config):
    _, post = _run(MockResponse(KEYLESS), value="187.13.12.227", config=config)
    assert post.call_args.kwargs["json"] == {"q": "187.13.12.227"}


def test_missing_config_is_a_keyless_lookup():
    query = json.dumps({"module": "ipapi_is", "attribute": {"type": "ip-src", "value": "187.13.12.227", "uuid": UUID}})
    _, post = _run(MockResponse(KEYLESS), query=query)
    assert post.call_args.kwargs["json"] == {"q": "187.13.12.227"}


def test_bogon_reported_by_the_api():
    bogon = {"ip": "85.203.46.163", "rir": None, "is_bogon": True, **dict.fromkeys(ipapi_is._FLAGS, False)}
    result, _ = _run(MockResponse(bogon))
    assert result == {"error": "ipapi.is reports 85.203.46.163 as a bogon: a private or reserved address."}


@pytest.mark.parametrize(
    "response, error",
    [
        (
            MockResponse(
                {
                    "error": "Invalid API key. Please register at https://ipapi.is/ to obtain a valid API key",
                    "error_code": "ERR_FORBIDDEN_INVALID_API_KEY",
                },
                403,
                "Forbidden",
            ),
            "ipapi.is API error 403: Invalid API key. Please register at https://ipapi.is/ to obtain a valid API key",
        ),
        (
            MockResponse(
                {
                    "error": "Daily limit reached: 30 free lookups per IP address per day.",
                    "error_code": "ERR_FREE_TIER_EXHAUSTED",
                    "docs": "https://ipapi.is/free-tier.html?ref=api",
                },
                429,
                "Too Many Requests",
            ),
            "ipapi.is API error 429: Daily limit reached: 30 free lookups per IP address per day.",
        ),
        (
            MockResponse({"error": "Unexpected Server Error", "error_code": "ERR_UNEXPECTED_SERVER_ERROR"}),
            "ipapi.is API error 200: Unexpected Server Error",
        ),
        (MockResponse(None, 403, "Forbidden"), "ipapi.is API error 403: Forbidden"),  # a bare 403 from a ban
        (MockResponse(None, 502, "Bad Gateway"), "ipapi.is API error 502: Bad Gateway"),
        (MockResponse(None), "The ipapi.is API returned a response that is not JSON."),
        (MockResponse(["85.203.46.163"]), "The ipapi.is API returned a response that is not JSON."),
        (requests.Timeout("Read timed out."), "Could not reach the ipapi.is API: Read timed out."),
    ],
)
def test_api_errors(response, error):
    result, _ = _run(response)
    assert result == {"error": error}


@pytest.mark.parametrize(
    "attribute, error",
    [
        (None, "which should contain at least a type, a value and an uuid."),
        ({"type": "ip-src", "value": "85.203.46.163"}, "which should contain at least a type, a value and an uuid."),
        ({"type": "domain", "value": "example.com", "uuid": UUID}, "Wrong input attribute type."),
        ({"type": "ip-src", "value": "not-an-ip", "uuid": UUID}, "not-an-ip is not a valid IP address."),
        ({"type": "ip-dst", "value": "10.0.0.1", "uuid": UUID}, "10.0.0.1 is a private or reserved address"),
        ({"type": "ip-src", "value": "2001:db8::1", "uuid": UUID}, "2001:db8::1 is a private or reserved address"),
    ],
)
def test_input_errors_do_not_call_the_api(attribute, error):
    query = json.dumps({"module": "ipapi_is", "attribute": attribute, "config": {"api_key": "k"}})
    result, post = _run(MockResponse(VPN), query=query)
    assert error in result["error"]
    post.assert_not_called()


def test_version_and_introspection():
    assert ipapi_is.handler(False) is False
    assert ipapi_is.version()["config"] == ["api_key"]
    assert ipapi_is.introspection()["input"] == ["ip-src", "ip-dst"]
