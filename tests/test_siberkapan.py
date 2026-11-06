import json
from unittest.mock import MagicMock, patch

import requests

from misp_modules.modules.expansion import siberkapan

TARGET = "misp_modules.modules.expansion.siberkapan.requests.get"

LISTED = {
    "ip": "198.51.100.7",
    "score": 100,
    "country_code": "TR",
    "asn": "AS64500",
    "asn_org": "Example Networks",
    "first_seen": "2026-07-01T17:55:11",
    "last_seen": "2026-11-06T18:23:52",
    "report_count": 42,
    "sources": ["honeypot", "fail2ban"],
    "attack_types": ["honeypot_ssh", "fail2ban_ban"],
    "noise": {
        "noise_score": 60,
        "noise_class": "mass",
        "sensors": 2,
        "ports": 4056,
        "active_days": 87,
    },
    "siberkapan_url": "https://siberkapan.org/ip/198.51.100.7",
}


def _response(status, payload=None):
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload or {}
    return response


def _query(payload):
    return siberkapan.handler(json.dumps(payload))


def test_handler_without_query_returns_false():
    assert siberkapan.handler(False) is False


@patch(TARGET)
def test_listed_ip(mock_get):
    mock_get.return_value = _response(200, LISTED)
    result = _query({"attribute": {"type": "ip-src", "value": "198.51.100.7"}})
    values = result["results"][0]["values"]
    assert result["results"][0]["types"] == ["text"]
    assert values[0] == "SiberKapan threat score: 100/100"
    assert any(v.startswith("Background noise: 60/100 (mass scanning)") for v in values)
    assert "ASN: AS64500 Example Networks" in values
    assert "Details: https://siberkapan.org/ip/198.51.100.7" in values
    assert mock_get.call_args[0][0] == "https://siberkapan.org/api/v1/ip/198.51.100.7"


@patch(TARGET)
def test_ip_port_format_uses_ip_part(mock_get):
    mock_get.return_value = _response(200, LISTED)
    _query({"ip-dst|port": "198.51.100.7|22"})
    assert mock_get.call_args[0][0] == "https://siberkapan.org/api/v1/ip/198.51.100.7"


@patch(TARGET)
def test_unlisted_ip(mock_get):
    mock_get.return_value = _response(404)
    result = _query({"attribute": {"type": "ip-src", "value": "192.0.2.1"}})
    assert result["results"][0]["values"] == ["192.0.2.1 is not listed in SiberKapan"]


@patch(TARGET)
def test_unexpected_status_returns_error(mock_get):
    mock_get.return_value = _response(500)
    result = _query({"attribute": {"type": "ip-src", "value": "198.51.100.7"}})
    assert "error" in result
    assert "500" in result["error"]


@patch(TARGET)
def test_network_error_returns_error(mock_get):
    mock_get.side_effect = requests.ConnectionError("connection refused")
    result = _query({"attribute": {"type": "ip-src", "value": "198.51.100.7"}})
    assert "error" in result
    assert "unreachable" in result["error"]


def test_missing_value_returns_error():
    result = _query({"attribute": {"type": "ip-src"}})
    assert result["error"] == "Missing IP address"


def test_introspection_and_version():
    assert "ip-src" in siberkapan.introspection()["input"]
    info = siberkapan.version()
    assert "expansion" in info["module-type"]
    assert info["config"] == []
