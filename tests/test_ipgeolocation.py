import copy
import ipaddress
import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import requests

from misp_modules.modules.expansion import ipgeolocation

FILES = os.path.join(os.path.dirname(__file__), "test_files", "ipgeolocation")

# Records in the layouts of the IPGeolocation.io sample databases: names stored per language, booleans in the
# Security databases stored as text, several abuse contacts joined with commas. Name -> (type, IP version, records).
DATABASES = {
    "location": (
        "ipgeolocation.io Database",
        6,
        {
            "91.128.0.0/14": {
                "location": {
                    "country": {"code2": "SE", "name": {"en": "Sweden", "de": "Schweden"}},
                    "state": {"code": "SE-AB", "name": {"en": "Stockholm County", "sv": "Stockholms län"}},
                    "city": {"name": {"en": "Stockholm"}},
                    "zipcode": "164 40",
                    "latitude": "59.40510",
                    "longitude": "17.95510",
                    "accuracy_radius": "4.395",
                },
                "asn": {"as_number": "1257", "organization": "Tele2 Sverige AB", "country": "SE"},
                "company": {"name": {"en": "Tele2 Sverige AB"}, "domain": "tele2.com", "type": "ISP"},
                "abuse": {
                    "emails": "abuse@tele2.com, hostmaster@tele2.com",
                    "phone_numbers": "+46856264210, +46856264211",
                },
            },
            "185.220.101.0/24": {
                "location": {"country": {"code2": "DE", "name": {"en": "Germany"}}, "city": {"name": {"en": "Berlin"}}},
                # Whole numbers can come back as doubles.
                "asn": {"as_number": 208294.0, "organization": "Example Hosting GmbH", "country": "DE"},
            },
            "2a00:1450::/32": {
                "location": {"country": {"code2": "IE", "name": {"en": "Ireland"}}, "city": {"name": {"en": "Dublin"}}}
            },
        },
    ),
    "security-v4": (
        "ipgeolocation.io IP-Security Database",
        4,
        {
            "185.220.101.0/24": {
                "threat_score": 95,
                "is_tor": "true",
                "is_vpn": "false",
                "is_anonymous": "true",
                "is_known_attacker": "true",
                "proxy_provider_names": [],
                "vpn_provider_names": [],
                "vpn_confidence_score": 0,
                "cloud_provider_name": "",
            }
        },
    ),
    "security-v1": (  # the first Security database marks VPN exits with proxy_type
        "ipgeolocation.io IP-Security Database",
        4,
        {
            "45.80.0.0/24": {
                "is_proxy": "true",
                "proxy_type": "VPN",
                "proxy_provider": "Nord VPN",
                "is_anonymous": "true",
                "threat_score": 40,
            },
            "45.81.0.0/24": {
                "is_proxy": "true",
                "proxy_type": "PROXY",
                "proxy_provider": "FleetProxy",
                "threat_score": 45,
            },
        },
    ),
    "residential": (
        "ipgeolocation.io Residential Database",
        4,
        {"1.0.141.172/32": {"proxy_provider": "ProxyShare", "last_seen": "2026-08-19"}},
    ),
    "hosting": ("ipgeolocation.io IP Hosting Database", 4, {"104.16.0.0/13": {"hosting_provider": "Cloudflare, Inc."}}),
}
BUILT = datetime(2026, 9, 30, tzinfo=timezone.utc)


class FakeReader:
    """Answers like a maxminddb reader, from the records in DATABASES."""

    def __init__(self, name):
        database_type, self.ip_version, networks = DATABASES[name]
        self.networks = [(ipaddress.ip_network(network), record) for network, record in networks.items()]
        self._metadata = SimpleNamespace(database_type=database_type, build_epoch=int(BUILT.timestamp()))

    def metadata(self):
        return self._metadata

    def get(self, ip):
        address = ipaddress.ip_address(ip)
        if address.version == 6 and self.ip_version == 4:
            raise ValueError(
                f"Error looking up {ip}. You attempted to look up an IPv6 address in an IPv4-only database."
            )
        return next((record for network, record in self.networks if address in network), None)


@pytest.fixture(autouse=True)
def _fake_maxminddb():
    """Each placeholder .mmdb file holds the name of the fake database it stands for."""

    def open_database(path, mode=None):
        with open(path) as f:
            return FakeReader(f.read().strip())

    fake = SimpleNamespace(open_database=open_database, MODE_AUTO=0, InvalidDatabaseError=ValueError)
    with patch.object(ipgeolocation, "maxminddb", fake):
        yield


def _databases(directory, files):
    directory.mkdir(exist_ok=True)
    for file_name, database in files.items():
        (directory / file_name).write_text(database)
    return str(directory)


def _load(name):
    with open(os.path.join(FILES, name)) as f:
        return json.load(f)


PAID = _load("api_paid.json")  # paidFullResponse example from the official OpenAPI specification
FREE = _load("api_free.json")  # freeMinimalResponse example from the official OpenAPI specification
FREE_PLAN_INCLUDE = {"message": "This feature is not supported on your subscription."}
INVALID_KEY = {"message": "Provided API key is not valid."}


class MockResponse:
    def __init__(self, payload, status_code=200, reason="OK"):
        self.payload = payload
        self.status_code = status_code
        self.reason = reason

    def json(self):
        return self.payload


@pytest.fixture(autouse=True)
def _reset_state():
    ipgeolocation._cache.clear()
    ipgeolocation._mmdb_sets.clear()
    yield
    ipgeolocation._cache.clear()
    ipgeolocation._mmdb_sets.clear()


def _query(value="91.128.103.196", type_="ip-src", config=None):
    attribute = {"type": type_, "value": value, "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    return json.dumps({"module": "ipgeolocation", "attribute": attribute, "config": config or {"api_key": "k"}})


def _run(responses, **query):
    session = Mock()
    session.get.side_effect = responses
    with patch.object(ipgeolocation, "_session", return_value=session):
        result = ipgeolocation.handler(_query(**query))
    return result, session.get


def _objects(result):
    return {obj["name"]: obj for obj in result["results"].get("Object", [])}


def _values(misp_object, relation):
    return [a["value"] for a in misp_object["Attribute"] if a["object_relation"] == relation]


def test_api_paid_response():
    result, get = _run([MockResponse(PAID)])

    params = get.call_args.kwargs["params"]
    assert params == {"apiKey": "k", "ip": "91.128.103.196", "include": "security,abuse,hostname"}
    objects = _objects(result)
    assert set(objects) == {"geolocation", "asn", "ipgeolocation-ip"}  # hostname equals the IP: no domain-ip
    assert _values(objects["geolocation"], "countrycode") == ["SE"]
    assert _values(objects["geolocation"], "city") == ["Stockholm"]
    assert _values(objects["asn"], "asn") == ["1257"]
    assert _values(objects["asn"], "subnet-announced") == ["91.128.0.0/14"]
    intelligence = objects["ipgeolocation-ip"]
    assert _values(intelligence, "threat-score") == ["0"]
    assert _values(intelligence, "company-name") == ["Tele2 Sverige AB"]
    assert _values(intelligence, "abuse-email") == ["abuse@tele2.com"]
    assert not [a for a in intelligence["Attribute"] if a["object_relation"].startswith("is-")]
    assert _values(intelligence, "vpn-confidence-score") == []  # a score of 0 is left out
    assert intelligence["comment"] == "IPGeolocation.io API"
    # MISP only creates objects that carry their template, even when PyMISP does not ship it yet.
    assert intelligence["template_uuid"] == ipgeolocation.IPGEOLOCATION_TEMPLATE["uuid"]
    assert intelligence["meta-category"] == "network"
    assert result["results"]["Attribute"][0]["value"] == "91.128.103.196"


def test_api_flagged_ip_and_hostname():
    payload = copy.deepcopy(PAID)
    payload["hostname"] = "exit.example.net"
    payload["security"].update(
        threat_score=90, is_tor=True, is_vpn=True, vpn_provider_names=["Nord VPN", "Proton VPN"], is_anonymous=True
    )
    result, _ = _run([MockResponse(payload)])

    objects = _objects(result)
    intelligence = objects["ipgeolocation-ip"]
    assert _values(intelligence, "threat-score") == ["90"]
    for flag in ("is-tor", "is-vpn", "is-anonymous"):
        assert _values(intelligence, flag) == ["1"]
    assert _values(intelligence, "is-proxy") == []
    assert _values(intelligence, "vpn-provider") == ["Nord VPN", "Proton VPN"]
    assert _values(objects["domain-ip"], "hostname") == ["exit.example.net"]


def test_api_bot_and_corporate_gateway_fields():
    payload = copy.deepcopy(PAID)
    payload["security"].update(
        is_bot=True,
        is_known_good_bot=True,
        bot_operator_name="Google",
        bot_type="crawler",
        bot_confidence_score=97,
        is_corporate_gateway=True,
        corporate_gateway_provider_name="Zscaler",
    )
    result, _ = _run([MockResponse(payload)])

    intelligence = _objects(result)["ipgeolocation-ip"]
    for flag in ("is-bot", "is-known-good-bot", "is-corporate-gateway"):
        assert _values(intelligence, flag) == ["1"]
    assert _values(intelligence, "bot-operator") == ["Google"]
    assert _values(intelligence, "bot-type") == ["crawler"]
    assert _values(intelligence, "bot-confidence-score") == ["97"]
    assert _values(intelligence, "corporate-gateway-provider") == ["Zscaler"]


def test_api_free_plan_falls_back_to_base_lookup():
    result, get = _run([MockResponse(FREE_PLAN_INCLUDE, 401), MockResponse(FREE)], value="165.227.0.0")

    assert [c.kwargs["params"].get("include") for c in get.call_args_list] == ["security,abuse,hostname", None]
    assert set(_objects(result)) == {"geolocation", "asn"}

    # The plan is remembered, so the next lookup goes straight to the base request.
    _, get = _run([MockResponse(FREE)], value="165.227.0.1")
    assert get.call_count == 1
    assert "include" not in get.call_args.kwargs["params"]


def test_api_error_message_is_returned():
    result, get = _run([MockResponse(INVALID_KEY, 401), MockResponse(INVALID_KEY, 401)])
    assert get.call_count == 2
    assert result == {"error": "IPGeolocation.io API error 401: Provided API key is not valid."}

    result, _ = _run([MockResponse({"message": "You have exceeded the limit."}, 429)])
    assert result == {"error": "IPGeolocation.io API error 429: You have exceeded the limit."}

    result, _ = _run([MockResponse({"message": "Not found"}, 404)])
    assert result == {"error": "91.128.103.196 is not in the IPGeolocation.io database."}


def test_api_key_is_not_leaked_in_errors():
    error = requests.ConnectionError("Max retries exceeded with url: /v3/ipgeo?apiKey=secret-key&ip=91.128.103.196")
    result, _ = _run(error, config={"api_key": "secret-key"})
    assert "secret-key" not in result["error"]
    assert result["error"].startswith("Could not reach the IPGeolocation.io API")


def test_api_results_are_cached():
    session = Mock()
    session.get.return_value = MockResponse(PAID)
    with patch.object(ipgeolocation, "_session", return_value=session):
        first = ipgeolocation.handler(_query())
        second = ipgeolocation.handler(_query())
        ipgeolocation.handler(_query(config={"api_key": "k", "cache_ttl": "0"}))
        ipgeolocation.handler(_query(config={"api_key": "k", "cache_ttl": "0"}))
    assert session.get.call_count == 3
    assert _objects(first).keys() == _objects(second).keys()
    # Each answer gets fresh object UUIDs even when it comes from the cache.
    assert _objects(first)["asn"]["uuid"] != _objects(second)["asn"]["uuid"]


def test_api_include_setting():
    _, get = _run([MockResponse(FREE)], config={"api_key": "k", "include": "none"})
    assert "include" not in get.call_args.kwargs["params"]
    _, get = _run([MockResponse(PAID)], value="91.128.103.197", config={"api_key": "k", "include": "security"})
    assert get.call_args.kwargs["params"]["include"] == "security"
    _, get = _run([MockResponse(PAID)], value="91.128.103.198", config={"api_key": "k", "include": ""})
    assert get.call_args.kwargs["params"]["include"] == "security,abuse,hostname"


@pytest.mark.parametrize(
    "type_, value, expected",
    [
        ("ip-dst|port", "91.128.103.196|443", "91.128.103.196"),
        ("ip-src|port", "2a00:1450:4001::1|443", "2a00:1450:4001::1"),
        ("domain|ip", "example.com|91.128.103.196", "91.128.103.196"),
    ],
)
def test_composite_input_types(type_, value, expected):
    _, get = _run([MockResponse(PAID)], type_=type_, value=value)
    assert get.call_args.kwargs["params"]["ip"] == expected


@pytest.mark.parametrize(
    "query, error",
    [
        ({"value": "10.0.0.1"}, "10.0.0.1 is a private or reserved address and cannot be looked up."),
        ({"value": "not-an-ip"}, "not-an-ip does not contain a valid IP address."),
        ({"type_": "domain", "value": "example.com"}, "Wrong input attribute type."),
        ({"config": {"include": "security"}}, "Set api_key to use the IPGeolocation.io API, or mmdb_paths"),
        ({"config": {"api_key": "k", "cache_ttl": "soon"}}, "cache_ttl must be a number of seconds."),
    ],
)
def test_input_errors_do_not_call_the_api(query, error):
    result, get = _run([], **query)
    assert result["error"].startswith(error)
    get.assert_not_called()


def test_mmdb_layers_location_and_security(tmp_path):
    paths = _databases(tmp_path, {"db-ip-location.mmdb": "location", "db-ip-security.mmdb": "security-v4"})
    result, get = _run([], value="185.220.101.7", config={"mmdb_paths": paths, "api_key": "k"})

    get.assert_not_called()  # local databases are set, so nothing is sent to the API
    objects = _objects(result)
    assert _values(objects["geolocation"], "country") == ["Germany"]
    assert _values(objects["asn"], "asn") == ["208294"]
    intelligence = objects["ipgeolocation-ip"]
    assert _values(intelligence, "threat-score") == ["95"]
    for flag in ("is-tor", "is-known-attacker", "is-anonymous"):
        assert _values(intelligence, flag) == ["1"]
    assert _values(intelligence, "is-vpn") == []
    assert _values(intelligence, "vpn-confidence-score") == []
    assert "db-ip-location.mmdb (ipgeolocation.io Database, built 2026-09-30)" in intelligence["comment"]
    assert "db-ip-security.mmdb (ipgeolocation.io IP-Security Database, built 2026-09-30)" in intelligence["comment"]


def test_mmdb_file_list_and_ipv6(tmp_path):
    _databases(tmp_path, {"db-ip-location.mmdb": "location", "db-ip-security.mmdb": "security-v4"})
    config = {"mmdb_paths": f"{tmp_path / 'db-ip-location.mmdb'}, {tmp_path / 'db-ip-security.mmdb'}"}
    result, _ = _run([], value="2a00:1450:4001::1", config=config)  # the Security database is IPv4 only
    assert _values(_objects(result)["geolocation"], "city") == ["Dublin"]

    result, _ = _run([], value="91.128.103.196", config=config)
    objects = _objects(result)
    assert set(objects) == {"geolocation", "asn", "ipgeolocation-ip"}
    assert _values(objects["geolocation"], "region") == ["Stockholm County"]  # English from the per-language names
    assert _values(objects["geolocation"], "latitude") == [59.4051]
    intelligence = objects["ipgeolocation-ip"]
    assert _values(intelligence, "company-name") == ["Tele2 Sverige AB"]
    assert _values(intelligence, "abuse-email") == ["abuse@tele2.com", "hostmaster@tele2.com"]
    assert _values(intelligence, "abuse-phone") == ["+46856264210", "+46856264211"]


@pytest.mark.parametrize(
    "ip, expected",
    [
        ("45.80.0.7", {"is-vpn": ["1"], "is-proxy": ["1"], "vpn-provider": ["Nord VPN"], "proxy-provider": []}),
        ("45.81.0.7", {"is-vpn": [], "is-proxy": ["1"], "proxy-provider": ["FleetProxy"]}),
        (
            "1.0.141.172",
            {
                "is-residential-proxy": ["1"],
                "proxy-provider": ["ProxyShare"],
                "proxy-last-seen": ["2026-08-19T00:00:00"],
            },
        ),
        ("104.16.0.1", {"is-cloud-provider": ["1"], "cloud-provider": ["Cloudflare, Inc."]}),
    ],
)
def test_mmdb_single_purpose_and_older_layouts(tmp_path, ip, expected):
    paths = _databases(
        tmp_path,
        {
            "db-ip-security.mmdb": "security-v1",
            "db-residential-proxy.mmdb": "residential",
            "db-ip-hosting.mmdb": "hosting",
        },
    )
    result, _ = _run([], value=ip, config={"mmdb_paths": paths})
    intelligence = _objects(result)["ipgeolocation-ip"]
    for relation, values in expected.items():
        assert _values(intelligence, relation) == values, relation


def test_mmdb_errors(tmp_path):
    paths = _databases(tmp_path / "dbs", {"db-ip-location.mmdb": "location"})
    result, _ = _run([], value="8.8.8.8", config={"mmdb_paths": paths})
    assert result == {"error": "8.8.8.8 is not in the configured IPGeolocation.io databases."}

    result, _ = _run([], config={"mmdb_paths": "/nonexistent/db-ip-city.mmdb"})
    assert result["error"].startswith("Cannot read the IPGeolocation.io database /nonexistent/db-ip-city.mmdb")

    (tmp_path / "empty").mkdir()
    result, _ = _run([], config={"mmdb_paths": str(tmp_path / "empty")})
    assert result == {"error": "No .mmdb files found in mmdb_paths."}


def test_mmdb_reloads_a_replaced_file(tmp_path):
    paths = _databases(tmp_path, {"db-ip-city.mmdb": "location"})
    result, _ = _run([], value="185.220.101.7", config={"mmdb_paths": paths})
    assert "ipgeolocation-ip" not in _objects(result)

    (tmp_path / "update.tmp").write_text("security-v4")
    os.replace(tmp_path / "update.tmp", tmp_path / "db-ip-city.mmdb")  # how updaters install a new release
    with patch.object(ipgeolocation, "MMDB_RECHECK_SECONDS", -1):
        result, _ = _run([], value="185.220.101.7", config={"mmdb_paths": paths})
    assert _values(_objects(result)["ipgeolocation-ip"], "threat-score") == ["95"]


def test_version_and_introspection():
    assert ipgeolocation.version()["config"] == ["api_key", "mmdb_paths", "include", "cache_ttl"]
    assert "ip-src" in ipgeolocation.introspection()["input"]
