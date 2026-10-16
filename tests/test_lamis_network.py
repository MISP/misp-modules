"""Unit tests for the Lamis Network MISP expansion module.

All external HTTP calls are mocked with unittest.mock, ensuring tests run offline
without requiring API keys or network access.
"""

import json
from unittest.mock import MagicMock, patch

from requests.exceptions import RequestException, Timeout

from misp_modules.modules.expansion import lamis_network

MOCK_IP_ATTRIBUTE = {
    "type": "ip-src",
    "value": "185.220.101.5",
    "uuid": "a8c9e530-9b4e-4f11-8517-5e1281c9a123",
}

MOCK_CONFIG = {
    "api_key": "test_community_key_12345",
    "risk_threshold": "70",
    "timeout": "5",
}

SAMPLE_API_RESPONSE = {
    "ip": "185.220.101.5",
    "asn": {
        "asn": "AS205100",
        "name": "F3 Netze e.V.",
        "domain": "f3netze.de",
        "route": "185.220.101.0/24",
        "type": "hosting",
    },
    "geo": {
        "country_code": "DE",
        "country": "Germany",
        "city": "Frankfurt am Main",
    },
    "is_vpn": False,
    "is_tor": True,
    "is_proxy": False,
    "is_datacenter": True,
    "fraud_score": 85,
}


def _build_query(attribute, config=None):
    return json.dumps(
        {
            "attribute": attribute,
            "config": config if config is not None else MOCK_CONFIG,
        }
    )


def test_introspection():
    """Verify introspection returns supported input types."""
    info = lamis_network.introspection()
    assert "input" in info
    assert "ip-src" in info["input"]
    assert "ip-dst" in info["input"]
    assert info["format"] == "misp_standard"


def test_version():
    """Verify module metadata and configuration keys."""
    meta = lamis_network.version()
    assert meta["name"] == "Lamis Network Lookup"
    assert "api_key" in meta["config"]
    assert "risk_threshold" in meta["config"]


def test_missing_config():
    """Verify error when API key is missing."""
    query = json.dumps({"attribute": MOCK_IP_ATTRIBUTE, "config": {}})
    result = lamis_network.handler(query)
    assert "error" in result
    assert "Missing Lamis Network API key" in result["error"]


def test_malformed_json_query():
    """Verify error when input query is not valid JSON."""
    result = lamis_network.handler("{malformed")
    assert "error" in result
    assert "Malformed input query JSON" in result["error"]


def test_invalid_ip_format():
    """Verify error when IP value is invalid."""
    bad_attr = {"type": "ip-src", "value": "999.999.999.999", "uuid": "1234"}
    query = _build_query(bad_attr)
    result = lamis_network.handler(query)
    assert "error" in result
    assert "Invalid IP address format" in result["error"]


def test_unsupported_attribute_type():
    """Verify error when attribute is not an IP."""
    bad_attr = {"type": "domain", "value": "malicious.example", "uuid": "1234"}
    query = _build_query(bad_attr)
    result = lamis_network.handler(query)
    assert "error" in result
    assert "Unsupported input attribute type" in result["error"]


@patch("requests.get")
def test_successful_enrichment_with_tag_binding(mock_get):
    """Verify tags are physically present in serialized Attribute output."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_API_RESPONSE
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    query = _build_query(MOCK_IP_ATTRIBUTE)
    result = lamis_network.handler(query)

    assert "results" in result
    results = result["results"]
    assert "Object" in results
    assert "Attribute" in results

    # Verify original attribute has tags bound
    target_attr = next(
        a for a in results["Attribute"] if a.get("uuid") == MOCK_IP_ATTRIBUTE["uuid"]
    )
    assert "Tag" in target_attr
    tag_names = [t["name"] for t in target_attr["Tag"]]
    assert 'network:tor="exit-node"' in tag_names
    assert 'ioc:artifact-state="suspicious"' in tag_names

    # Verify objects created
    object_names = [obj["name"] for obj in results["Object"]]
    assert "asn" in object_names
    assert "geolocation" in object_names


@patch("requests.get")
def test_asn_and_geo_attributes_and_references(mock_get):
    """Verify object references and attribute values match MISP templates."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_API_RESPONSE
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    query = _build_query(MOCK_IP_ATTRIBUTE)
    result = lamis_network.handler(query)["results"]

    # Verify ASN object attributes and reference
    asn_obj = next(o for o in result["Object"] if o["name"] == "asn")
    assert any(
        ref.get("referenced_uuid") == MOCK_IP_ATTRIBUTE["uuid"]
        and ref.get("relationship_type") == "includes"
        for ref in asn_obj.get("ObjectReference", [])
    )
    asn_attrs = {a["object_relation"]: a["value"] for a in asn_obj["Attribute"]}
    assert asn_attrs["asn"] == "AS205100"
    assert asn_attrs["description"] == "F3 Netze e.V."

    # Verify Geolocation object attributes and reference
    geo_obj = next(o for o in result["Object"] if o["name"] == "geolocation")
    assert any(
        ref.get("referenced_uuid") == MOCK_IP_ATTRIBUTE["uuid"]
        and ref.get("relationship_type") == "locates"
        for ref in geo_obj.get("ObjectReference", [])
    )
    geo_attrs = {a["object_relation"]: a["value"] for a in geo_obj["Attribute"]}
    assert geo_attrs["countrycode"] == "DE"
    assert geo_attrs["country"] == "Germany"
    assert geo_attrs["city"] == "Frankfurt am Main"


@patch("requests.get")
def test_default_request_parameters_and_headers(mock_get):
    """Verify default timeout=10 and Bearer header when config is minimal."""
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"ip": "185.220.101.5"}
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    minimal_config = {"api_key": "my_secret_token"}
    query = _build_query(MOCK_IP_ATTRIBUTE, config=minimal_config)
    lamis_network.handler(query)

    mock_get.assert_called_once_with(
        "https://api.lamisnetwork.com/v1/ip/185.220.101.5",
        headers={
            "Authorization": "Bearer my_secret_token",
            "Accept": "application/json",
            "User-Agent": "MISP-Module-LamisNetwork/0.1",
        },
        timeout=10,
    )


@patch("requests.get")
def test_overflow_protection_in_config_and_score(mock_get):
    """Verify float inf (1e309) does not crash int parsing and falls back to defaults."""
    overflow_resp = {
        "ip": "185.220.101.5",
        "fraud_score": float("inf"),  # 1e309
    }
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = overflow_resp
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    overflow_config = {
        "api_key": "valid_key",
        "timeout": float("inf"),
        "risk_threshold": float("inf"),
    }
    query = _build_query(MOCK_IP_ATTRIBUTE, config=overflow_config)
    result = lamis_network.handler(query)

    # 1. Fallback timeout=10 was used in requests.get
    assert mock_get.call_args[1]["timeout"] == 10

    # 2. Risk score is N/A and no exceptions
    assert "results" in result
    comments = [
        a["value"] for a in result["results"]["Attribute"] if a.get("type") == "comment"
    ]
    assert any("Lamis Risk Score: N/A" in c for c in comments)

    # 3. Fallback risk_threshold=75: test with valid score 75 under overflow config
    mock_resp.json.return_value = {"ip": "185.220.101.5", "fraud_score": 75}
    res_thresh = lamis_network.handler(query)
    attr_thresh = next(
        a
        for a in res_thresh["results"]["Attribute"]
        if a.get("uuid") == MOCK_IP_ATTRIBUTE["uuid"]
    )
    tags_thresh = [t["name"] for t in attr_thresh.get("Tag", [])]
    assert 'ioc:artifact-state="suspicious"' in tags_thresh


@patch("requests.get")
def test_boolean_guard_regression(mock_get):
    """Verify boolean values in config and API response do not get treated as integers."""
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {
        "ip": "185.220.101.5",
        "fraud_score": True,  # True should NOT become score=1
    }
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    bool_config = {
        "api_key": "valid_key",
        "timeout": True,  # True should NOT become timeout=1s, should fallback to 10
        "risk_threshold": False,  # False should NOT become 0, should fallback to 75
    }
    query = _build_query(MOCK_IP_ATTRIBUTE, config=bool_config)
    result = lamis_network.handler(query)

    assert mock_get.call_args[1]["timeout"] == 10
    comments = [
        a["value"] for a in result["results"]["Attribute"] if a.get("type") == "comment"
    ]
    assert any("Lamis Risk Score: N/A" in c for c in comments)


@patch("requests.get")
def test_boolean_string_false_no_vpn_tag(mock_get):
    """Verify string 'false', 0, and 'no' are parsed as False with no indicator tags/comments."""
    resp = {
        "ip": "185.220.101.5",
        "is_vpn": "false",
        "is_tor": False,
        "is_proxy": 0,
        "is_datacenter": "no",
        "fraud_score": 10,
    }
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = resp
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    query = _build_query(MOCK_IP_ATTRIBUTE)
    result = lamis_network.handler(query)

    target_attr = next(
        a
        for a in result["results"]["Attribute"]
        if a.get("uuid") == MOCK_IP_ATTRIBUTE["uuid"]
    )
    tags = [t["name"] for t in target_attr.get("Tag", [])]
    assert 'network:vpn="active"' not in tags
    assert 'network:tor="exit-node"' not in tags

    comments = [
        a["value"] for a in result["results"]["Attribute"] if a.get("type") == "comment"
    ]
    assert not any(
        any(
            term in c for term in ["VPN", "Tor Exit Node", "Public Proxy", "Datacenter"]
        )
        for c in comments
    )


@patch("requests.get")
def test_ipv6_support(mock_get):
    """Verify valid IPv6 observable is parsed and enriched."""
    ipv6_attr = {
        "type": "ip-src",
        "value": "2001:db8::1",
        "uuid": "b2c3d4e5-1111-2222-3333-444455556666",
    }
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"ip": "2001:db8::1", "fraud_score": 20}
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    query = _build_query(ipv6_attr)
    result = lamis_network.handler(query)
    assert "results" in result
    mock_get.assert_called_once()
    assert "2001:db8::1" in mock_get.call_args[0][0]


@patch("requests.get")
def test_non_dict_api_response(mock_get):
    """Verify API returning a list instead of a dict returns a clean error."""
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = ["unexpected", "array"]
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    query = _build_query(MOCK_IP_ATTRIBUTE)
    result = lamis_network.handler(query)
    assert "error" in result
    assert "Invalid API response structure" in result["error"]


@patch("requests.get")
def test_response_without_objects(mock_get):
    """Verify graceful handling when API returns no ASN and no Geo."""
    minimal_resp = {
        "ip": "185.220.101.5",
        "asn": None,
        "geo": None,
        "is_vpn": False,
        "is_tor": False,
        "fraud_score": None,
    }
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = minimal_resp
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    query = _build_query(MOCK_IP_ATTRIBUTE)
    result = lamis_network.handler(query)

    assert "results" in result
    results = result["results"]
    assert results["Object"] == []
    comments = [a["value"] for a in results["Attribute"] if a.get("type") == "comment"]
    assert any("Lamis Risk Score: N/A" in c for c in comments)


@patch("requests.get")
def test_config_robustness_with_empty_and_invalid_values(mock_get):
    """Verify handler does not crash with empty or non-integer config strings."""
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = SAMPLE_API_RESPONSE
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    crazy_config = {
        "api_key": "valid_key",
        "timeout": "",
        "risk_threshold": "invalid_number",
    }
    query = _build_query(MOCK_IP_ATTRIBUTE, config=crazy_config)
    result = lamis_network.handler(query)
    assert "results" in result


@patch("requests.get")
def test_threshold_boundaries(mock_get):
    """Verify threshold boundary conditions (below, equal, above)."""
    mock_resp = MagicMock(status_code=200)
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    # 1. Score below threshold (50 < 75) -> no suspicious tag
    mock_resp.json.return_value = {"ip": "185.220.101.5", "fraud_score": 50}
    query = _build_query(
        MOCK_IP_ATTRIBUTE, config={"api_key": "k", "risk_threshold": 75}
    )
    res_below = lamis_network.handler(query)
    attr_below = next(
        a
        for a in res_below["results"]["Attribute"]
        if a.get("uuid") == MOCK_IP_ATTRIBUTE["uuid"]
    )
    tags_below = [t["name"] for t in attr_below.get("Tag", [])]
    assert 'ioc:artifact-state="suspicious"' not in tags_below

    # 2. Score equal to threshold (75 == 75) -> suspicious tag added
    mock_resp.json.return_value = {"ip": "185.220.101.5", "fraud_score": 75}
    res_equal = lamis_network.handler(query)
    attr_equal = next(
        a
        for a in res_equal["results"]["Attribute"]
        if a.get("uuid") == MOCK_IP_ATTRIBUTE["uuid"]
    )
    tags_equal = [t["name"] for t in attr_equal.get("Tag", [])]
    assert 'ioc:artifact-state="suspicious"' in tags_equal

    # 3. Score above threshold (90 > 75) -> suspicious tag added
    mock_resp.json.return_value = {"ip": "185.220.101.5", "fraud_score": 90}
    res_above = lamis_network.handler(query)
    attr_above = next(
        a
        for a in res_above["results"]["Attribute"]
        if a.get("uuid") == MOCK_IP_ATTRIBUTE["uuid"]
    )
    tags_above = [t["name"] for t in attr_above.get("Tag", [])]
    assert 'ioc:artifact-state="suspicious"' in tags_above


@patch("requests.get")
def test_http_errors_401_429_500(mock_get):
    """Verify HTTP error code handling."""
    # 401
    mock_resp_401 = MagicMock(status_code=401)
    mock_get.return_value = mock_resp_401
    assert (
        "Authentication failed"
        in lamis_network.handler(_build_query(MOCK_IP_ATTRIBUTE))["error"]
    )

    # 429
    mock_resp_429 = MagicMock(status_code=429)
    mock_get.return_value = mock_resp_429
    assert (
        "Rate limit or monthly quota exceeded"
        in lamis_network.handler(_build_query(MOCK_IP_ATTRIBUTE))["error"]
    )

    # 500
    mock_resp_500 = MagicMock(status_code=500)
    mock_resp_500.raise_for_status.side_effect = RequestException("Server Error")
    mock_get.return_value = mock_resp_500
    assert (
        "Error querying Lamis Network API"
        in lamis_network.handler(_build_query(MOCK_IP_ATTRIBUTE))["error"]
    )


@patch("requests.get", side_effect=Timeout("Connection timed out"))
def test_timeout(mock_get):
    """Verify timeout is caught and reported cleanly."""
    query = _build_query(MOCK_IP_ATTRIBUTE)
    result = lamis_network.handler(query)
    assert "error" in result
    assert "timed out" in result["error"].lower()


@patch("requests.get")
def test_invalid_json(mock_get):
    """Verify invalid JSON payload from server is caught."""
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.side_effect = json.JSONDecodeError("Expecting value", "doc", 0)
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    query = _build_query(MOCK_IP_ATTRIBUTE)
    result = lamis_network.handler(query)
    assert "error" in result
    assert "Invalid JSON response" in result["error"]
