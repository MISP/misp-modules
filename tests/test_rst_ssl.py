"""Unit tests for rst_ssl (mocked rstapi, no network)."""

import json
from unittest.mock import patch

from misp_modules.modules.expansion import rst_ssl


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    def GetSslCertificate(self, target):
        return self._payload


def _query(attribute, config=None):
    return json.dumps({
        "module": "rst_ssl",
        "attribute": attribute,
        "config": config if config is not None else {"api_key": "test-key", "port": "443"},
    })


def test_rst_ssl_returns_x509_object():
    attribute = {"type": "ip-dst", "value": "93.184.216.34", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    payload = {
        "subject_dn": "CN=example.com",
        "issuer_dn": "CN=DigiCert",
        "fingerprint_sha1": "a" * 40,
        "fingerprint_sha256": "b" * 64,
        "not_after": "2026-12-21T19:20:01Z",
        "serial_number": "01",
    }
    with patch.object(rst_ssl.rstapi, "scan", return_value=_FakeClient(payload)):
        result = rst_ssl.handler(_query(attribute))
    obj = result["results"]["Object"][0]
    assert obj["name"] == "x509"
    relations = {a["object_relation"]: a for a in obj["Attribute"]}
    assert relations["subject"]["value"] == "CN=example.com"
    assert relations["x509-fingerprint-sha256"]["value"] == "b" * 64


def test_rst_ssl_no_certificate():
    attribute = {"type": "ip-dst", "value": "1.2.3.4", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    with patch.object(rst_ssl.rstapi, "scan", return_value=_FakeClient({})):
        result = rst_ssl.handler(_query(attribute))
    assert any("no certificate" in a["value"].lower() for a in result["results"]["Attribute"])
