import json
from copy import deepcopy
from unittest.mock import Mock, patch

import pytest
import requests
from pymisp import MISPObject

from misp_modules.modules.expansion import crowdsec

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
IP = "192.0.2.1"
PAYLOAD = {
    "ip": IP,
    "history": {"first_seen": "2023-05-01T00:00:00Z", "last_seen": "2023-05-22T00:00:00Z"},
    "reputation": "malicious",
    "ip_range": "192.0.2.0/24",
    "ip_range_score": 2,
    "location": {"country": "FR", "city": "Paris", "latitude": 0, "longitude": 0},
    "as_name": "Example network",
    "as_num": 64496,
    "reverse_dns": "host.example.org",
    "background_noise_score": 0,
    "behaviors": [{"name": "http:scan", "label": "HTTP Scan", "description": "HTTP vulnerability scanning"}],
    "mitre_techniques": [
        {"name": "T1595.002", "label": "Vulnerability Scanning", "description": "Scanning for vulnerabilities"},
        {"name": "TA0043", "label": "Reconnaissance", "description": "Gathering information"},
    ],
    "cves": ["CVE-2023-1234"],
    # Classification example from issue #614.
    "classifications": {
        "false_positives": [
            {
                "name": "seo:crawler",
                "label": "SEO crawler",
                "description": "IP belongs to a known SEO crawler and should not be flagged as a threat.",
            }
        ],
        "classifications": [
            {
                "name": "community-blocklist",
                "label": "CrowdSec Community Blocklist",
                "description": "IP belong to the CrowdSec Community Blocklist",
            }
        ],
    },
    "attack_details": [{"name": "http-scan", "label": "HTTP scan", "description": "Scanning a web server"}],
    "target_countries": {"US": 10, "FR": 5},
    "scores": {"overall": {"trust": 0, "aggressiveness": 4}, "last_day": {"threat": 3}},
}


def query(config=None, kind="ip-src", value=IP):
    return json.dumps(
        {
            "attribute": {"type": kind, "value": value, "uuid": UUID, "comment": "Original context"},
            "config": {"api_key": "test-key", **(config or {})},
        }
    )


def run(payload=None, **kwargs):
    response = Mock(status_code=200)
    response.json.return_value = deepcopy(PAYLOAD if payload is None else payload)
    with patch.object(crowdsec.requests, "get", return_value=response) as get:
        result = crowdsec.handler(query(**kwargs))
    return result, get


def context(result):
    assert "results" in result, result
    return result["results"]["Object"][0]


def attributes(result):
    relations = {}
    for attribute in context(result)["Attribute"]:
        relations.setdefault(attribute["object_relation"], []).append(attribute)
    return relations


def tags(result):
    return {tag["name"] for tag in attributes(result)["ip"][0].get("Tag", [])}


def test_issue_614_fields_use_the_misp_object_template():
    result, get = run()
    obj = context(result)
    attrs = attributes(result)

    assert obj["name"] == "crowdsec-ip-context"
    assert set(attrs) <= set(MISPObject("crowdsec-ip-context")._definition["attributes"])
    assert float(attrs["background-noise"][0]["value"]) == 0
    assert attrs["background-noise"][0]["type"] == "float"
    for field, relation in (("false_positives", "false-positives"), ("classifications", "classifications")):
        expected = PAYLOAD["classifications"][field][0]
        assert attrs[relation][0]["value"] == expected["label"]
        assert attrs[relation][0]["comment"] == expected["description"]
        assert attrs[relation][0]["type"] == "text"
        assert attrs[relation][0]["disable_correlation"] is True
    assert 'crowdsec:false-positive="seo-crawler"' in tags(result)
    assert 'crowdsec:classification="community-blocklist"' in tags(result)
    assert 'crowdsec:behavior="http-scan"' in tags(result)
    get.assert_called_once_with(
        f"https://cti.api.crowdsec.net/v2/smoke/{IP}",
        headers={"x-api-key": "test-key", "User-Agent": "crowdsec-misp/v2.2"},
        timeout=30,
        allow_redirects=False,
    )


def test_existing_enrichment_and_source_reference_are_preserved():
    result, _ = run()
    attrs = attributes(result)
    obj = context(result)
    source = result["results"]["Attribute"][0]
    assert source["uuid"] == UUID
    assert source["comment"] == "Original context"
    assert any(
        ref["referenced_uuid"] == UUID and ref["relationship_type"] == "related-to" for ref in obj["ObjectReference"]
    )
    assert obj["first_seen"] == "2023-05-01T00:00:00+00:00"
    assert obj["last_seen"] == "2023-05-22T00:00:00+00:00"
    for relation, value in {
        "ip-range": "192.0.2.0/24",
        "ip-range-score": "2",
        "country": "France",
        "city": "Paris",
        "latitude": "0",
        "longitude": "0",
        "as-name": "Example network",
        "as-num": "64496",
        "reverse-dns": "host.example.org",
        "trust": "0",
        "target-countries": "United States, France",
    }.items():
        assert attrs[relation][0]["value"] == value
    assert "Overall: Trust: 0 - Aggressiveness: 4" in attrs["scores"][0]["value"]
    assert "http-scan - HTTP scan (Scanning a web server)" == attrs["attack-details"][0]["value"]
    assert "https://attack.mitre.org/techniques/T1595/002" in attrs["mitre-techniques"][0]["comment"]
    assert "https://attack.mitre.org/tactics/TA0043" in attrs["mitre-techniques"][1]["comment"]
    assert attrs["cves"][0]["value"] == "CVE-2023-1234"


@pytest.mark.parametrize("enabled", [False, " off ", 0, True, "YES", 1])
@pytest.mark.parametrize("category", ["reputation", "behavior", "classification", "mitre_technique", "cve"])
def test_tag_settings_do_not_remove_enrichment(category, enabled):
    result, _ = run(config={f"add_{category}_tag": enabled})
    default, _ = run()
    prefix = f"crowdsec:{category.replace('_', '-')}="
    controlled = {tag for tag in tags(default) if tag.startswith(prefix)}
    if category == "classification":
        controlled.add('crowdsec:false-positive="seo-crawler"')
    expected = controlled if enabled in (True, "YES", 1) else set()
    assert tags(result) & controlled == expected
    assert tags(result) - controlled == tags(default) - controlled
    assert set(attributes(result)) == set(attributes(default))


@pytest.mark.parametrize("score", [0, 2.5, None])
def test_background_noise_is_optional_and_keeps_zero(score):
    result, _ = run({"ip": IP, "background_noise_score": score})
    attrs = attributes(result)
    if score is None:
        assert "background-noise" not in attrs
    else:
        assert float(attrs["background-noise"][0]["value"]) == score


@pytest.mark.parametrize("null_fields", [False, True])
def test_sparse_response(null_fields):
    payload = {key: None for key in PAYLOAD} if null_fields else {}
    payload["ip"] = IP
    result, _ = run(payload)
    assert set(attributes(result)) == {"ip", "reputation"}
    assert attributes(result)["reputation"][0]["value"] == "unknown"
    assert "first_seen" not in context(result)
    assert "last_seen" not in context(result)


def test_empty_classifications_and_unknown_country_do_not_break_lookup():
    payload = deepcopy(PAYLOAD)
    payload["classifications"] = {"false_positives": None, "classifications": [], "future_category": []}
    payload["location"]["country"] = "ZZ"
    payload["target_countries"] = {"ZZ": 4, "FR": 2}
    result, _ = run(payload)
    attrs = attributes(result)
    assert "false-positives" not in attrs
    assert "classifications" not in attrs
    assert "country" not in attrs
    assert attrs["country-code"][0]["value"] == "ZZ"
    assert attrs["target-countries"][0]["value"] == "France"


@pytest.mark.parametrize("kind", ["ip-src", "ip-dst"])
def test_ipv6_lookup(kind):
    ip = "2001:db8::1"
    result, get = run({"ip": ip}, kind=kind, value=ip)
    assert attributes(result)["ip"][0]["value"] == ip
    assert get.call_args.args[0].endswith(ip)


@pytest.mark.parametrize("value", ["invalid", "192.0.2.0/24", "fe80::1%eth0", "", None, 42, []])
def test_invalid_ip_does_not_call_api(value):
    with patch.object(crowdsec.requests, "get") as get:
        assert "error" in crowdsec.handler(query(value=value))
    get.assert_not_called()


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"config":{"api_key":"test-key"}}'])
def test_invalid_request(raw):
    with patch.object(crowdsec.requests, "get") as get:
        assert "error" in crowdsec.handler(raw)
    get.assert_not_called()


def test_missing_key_and_unsupported_type():
    with patch.object(crowdsec.requests, "get") as get:
        assert "error" in crowdsec.handler(query(config={"api_key": ""}))
        assert "error" in crowdsec.handler(query(kind="domain"))
    get.assert_not_called()


@pytest.mark.parametrize("status", [302, 401, 403, 404, 429, 500])
def test_api_http_errors(status):
    with patch.object(crowdsec.requests, "get", return_value=Mock(status_code=status)):
        assert str(status) in crowdsec.handler(query())["error"]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_network_errors(failure):
    with patch.object(crowdsec.requests, "get", side_effect=failure("test-key")):
        result = crowdsec.handler(query())
    assert "error" in result
    assert "test-key" not in result["error"]


def test_invalid_json_response():
    response = Mock(status_code=200)
    response.json.side_effect = ValueError("not JSON")
    with patch.object(crowdsec.requests, "get", return_value=response):
        assert "error" in crowdsec.handler(query())


@pytest.mark.parametrize("payload", [{}, [], "not an IP lookup", {"message": "error"}])
def test_invalid_lookup_response(payload):
    result, _ = run(payload)
    assert "error" in result


def test_discovery():
    assert crowdsec.handler(False) is False
    assert crowdsec.introspection()["input"] == ["ip-dst", "ip-src"]
    assert crowdsec.version()["config"] == crowdsec.moduleconfig
