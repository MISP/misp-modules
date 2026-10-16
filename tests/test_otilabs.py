"""Unit tests for the OTI Labs Domain Intelligence MISP expansion module.

The API is mocked with unittest.mock, so the tests run offline without an API key. The sample
response is a trimmed copy of a real /lookup response for stripe.com.
"""

import copy
import json
from unittest.mock import MagicMock, patch

from requests.exceptions import ConnectionError as RequestsConnectionError

from misp_modules.modules.expansion import otilabs

MOCK_ATTRIBUTE = {"type": "domain", "value": "stripe.com", "uuid": "4f1d2b6e-2a51-4c3d-9a2f-6a7d3c9e1b20"}
MOCK_CONFIG = {"apikey": "test_rapidapi_key"}

SAMPLE_RESPONSE = {
    "domain": "stripe.com",
    "dns": {
        "A": ["198.137.150.41", "198.202.176.41"],
        "AAAA": [],
        "MX": ["10 aspmx.l.google.com.", "20 alt1.aspmx.l.google.com."],
        "TXT": [
            '"vercel-domain-verification-n462w8=JRePwTQbccpon6VAqYhidisHw"',
            (
                '"v=spf1 ip4:198.2.180.60/32 ip4:13.111.2.227/32 include:spf1.stripe.com'
                ' include:greenhouse-outbound-mail.stripe.com include:_spf.qualtrics.com ~all"'
            ),
        ],
        "NS": ["ns-1087.awsdns-07.org.", "ns-705.awsdns-24.net."],
        "CAA": ['0 issue "amazon.com"'],
        "SOA": ["ns-1882.awsdns-43.co.uk. awsdns-hostmaster.amazon.com. 1 900 900 1209600 3600"],
    },
    "ssl": {
        "issuer": "CN=DigiCert G5 TLS ECC SHA384 2021 CA1,O=DigiCert\\, Inc.,C=US",
        "subject": (
            "CN=stripe.com,O=Stripe\\, LLC,L=South San Francisco,ST=California,C=US,2.5.4.5=4675506,2.5.4.15=Private"
            " Organization,1.3.6.1.4.1.311.60.2.1.2=Delaware,1.3.6.1.4.1.311.60.2.1.3=US"
        ),
        "valid_from": "2026-09-24T00:00:00+00:00",
        "valid_to": "2026-12-10T23:59:59+00:00",
        "days_until_expiry": 67,
        "serial_number": "1939952089730671370756115214599670534",
        "sans": ["stripe.com", "www.stripe.com"],
        "signature_algorithm": "ecdsa-with-SHA384",
    },
    "whois": {
        "registrar": "SafeNames Ltd.",
        "created": "1995-09-12T04:00:00Z",
        "updated": "2025-10-01T01:39:51Z",
        "expires": "2027-09-11T04:00:00Z",
        "nameservers": ["NS-1087.AWSDNS-07.ORG", "NS-1882.AWSDNS-43.CO.UK"],
        "status": ["client delete prohibited", "client transfer prohibited"],
        "_source": "rdap.org",
    },
    "subdomains": {
        "count": 493,
        "live_count": 283,
        "returned": 3,
        "subdomains": ["58.email.stripe.com", "59.email.stripe.com", "access.stripe.com"],
        "live": [
            {"host": "58.email.stripe.com", "ip": "13.224.202.101"},
            {"host": "59.email.stripe.com", "ip": "13.35.107.110"},
            {"host": "access.stripe.com", "ip": "198.137.150.231"},
        ],
        "pools": [],
    },
    "email_security": {
        "spf": {
            "present": True,
            "records": [
                "v=spf1 ip4:198.2.180.60/32 ip4:13.111.2.227/32 include:spf1.stripe.com"
                " include:greenhouse-outbound-mail.stripe.com include:_spf.qualtrics.com ~all"
            ],
        },
        "dmarc": {
            "present": True,
            "records": [
                "v=DMARC1; p=reject; pct=100; fo=1; rua=mailto:dmarc-reports@stripe.com;"
                " ruf=mailto:dmarc-forensics@stripe.com;"
            ],
        },
        "dkim": {
            "found": ["google", "s1"],
            "records": [
                {"selector": "google", "records": ["v=DKIM1; k=rsa; p=MIGfMA0GCSq..."]},
                {"selector": "s1", "records": ["v=DKIM1; k=rsa; p=MIGfMA0GCSq..."]},
            ],
            "note": (
                "Probed common selectors (Google, Microsoft 365, Mailchimp, SendGrid, etc.). Custom or hash-based"
                " selectors aren't auto-discoverable."
            ),
        },
    },
}


def _query(attribute=None, config=None):
    return json.dumps(
        {
            "attribute": attribute if attribute is not None else MOCK_ATTRIBUTE,
            "config": config if config is not None else MOCK_CONFIG,
        }
    )


def _response(status_code=200, payload=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload if payload is not None else SAMPLE_RESPONSE
    return response


def _objects(result, name):
    return [o for o in result["results"]["Object"] if o["name"] == name]


def _values(misp_object, relation):
    return [a["value"] for a in misp_object["Attribute"] if a["object_relation"] == relation]


def test_introspection():
    info = otilabs.introspection()
    assert info["input"] == ["domain", "hostname"]
    assert info["format"] == "misp_standard"


def test_version():
    meta = otilabs.version()
    assert meta["name"] == "OTI Labs Domain Intelligence"
    assert meta["config"] == ["apikey", "subdomain_limit"]


def test_missing_apikey():
    result = otilabs.handler(_query(config={}))
    assert "API key" in result["error"]


def test_unsupported_attribute_type():
    attribute = {"type": "ip-src", "value": "198.51.100.1", "uuid": MOCK_ATTRIBUTE["uuid"]}
    result = otilabs.handler(_query(attribute=attribute))
    assert "Unsupported attribute type" in result["error"]


@patch("misp_modules.modules.expansion.otilabs.requests.get")
def test_domain_lookup(mock_get):
    mock_get.return_value = _response()
    result = otilabs.handler(_query())

    args, kwargs = mock_get.call_args
    assert args[0] == "https://domain-intelligence-api.p.rapidapi.com/lookup/stripe.com"
    assert kwargs["headers"]["X-RapidAPI-Key"] == "test_rapidapi_key"
    assert kwargs["headers"]["X-RapidAPI-Host"] == "domain-intelligence-api.p.rapidapi.com"

    (whois,) = _objects(result, "whois")
    assert _values(whois, "registrar") == ["SafeNames Ltd."]
    assert _values(whois, "nameserver") == ["ns-1087.awsdns-07.org", "ns-1882.awsdns-43.co.uk"]
    assert _values(whois, "creation-date")

    (x509,) = _objects(result, "x509")
    assert _values(x509, "serial-number") == ["1939952089730671370756115214599670534"]
    assert _values(x509, "dns_names") == ["stripe.com", "www.stripe.com"]

    (records,) = _objects(result, "dns-record")
    assert _values(records, "mx-record") == ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]
    assert _values(records, "soa-record") == ["ns-1882.awsdns-43.co.uk"]
    assert any(v.startswith("v=spf1 ") for v in _values(records, "txt-record"))

    domain_objects = _objects(result, "domain-ip")
    (apex,) = [o for o in domain_objects if _values(o, "domain") == ["stripe.com"]]
    assert _values(apex, "ip") == ["198.137.150.41", "198.202.176.41"]
    texts = _values(apex, "text")
    assert any(t.startswith("SPF: v=spf1") for t in texts)
    assert any("p=reject" in t for t in texts if t.startswith("DMARC:"))
    assert "DKIM: found on selector(s) google, s1" in texts

    subdomains = [o for o in domain_objects if _values(o, "hostname")]
    assert [_values(o, "hostname")[0] for o in subdomains] == [
        "58.email.stripe.com",
        "59.email.stripe.com",
        "access.stripe.com",
    ]
    assert _values(subdomains[2], "ip") == ["198.137.150.231"]

    summary = [a["value"] for a in result["results"]["Attribute"] if a["type"] == "text"]
    assert summary == ["OTI Labs found 493 subdomains of stripe.com, 283 of them resolving now"]


@patch("misp_modules.modules.expansion.otilabs.requests.get")
def test_subdomain_limit(mock_get):
    mock_get.return_value = _response()
    result = otilabs.handler(_query(config={"apikey": "test_rapidapi_key", "subdomain_limit": "1"}))
    subdomains = [o for o in _objects(result, "domain-ip") if _values(o, "hostname")]
    assert len(subdomains) == 1
    summary = [a["value"] for a in result["results"]["Attribute"] if a["type"] == "text"]
    assert summary[0].endswith("the first 1 live ones were added")


@patch("misp_modules.modules.expansion.otilabs.requests.get")
def test_live_check_still_running(mock_get):
    payload = copy.deepcopy(SAMPLE_RESPONSE)
    payload["subdomains"]["live_count"] = None
    payload["subdomains"]["live"] = []
    mock_get.return_value = _response(payload=payload)
    result = otilabs.handler(_query())
    assert not [o for o in _objects(result, "domain-ip") if _values(o, "hostname")]
    summary = [a["value"] for a in result["results"]["Attribute"] if a["type"] == "text"]
    assert "the live check is still running" in summary[0]


@patch("misp_modules.modules.expansion.otilabs.requests.get")
def test_failed_section_is_skipped(mock_get):
    payload = copy.deepcopy(SAMPLE_RESPONSE)
    payload["whois"] = {"error": "RDAP lookup failed"}
    mock_get.return_value = _response(payload=payload)
    result = otilabs.handler(_query())
    assert not _objects(result, "whois")
    assert _objects(result, "x509")


@patch("misp_modules.modules.expansion.otilabs.requests.get")
def test_free_text_whois_date_is_dropped(mock_get):
    payload = copy.deepcopy(SAMPLE_RESPONSE)
    payload["whois"]["created"] = "before Aug-1996"
    mock_get.return_value = _response(payload=payload)
    result = otilabs.handler(_query())
    (whois,) = _objects(result, "whois")
    assert not _values(whois, "creation-date")
    assert _values(whois, "registrar") == ["SafeNames Ltd."]


@patch("misp_modules.modules.expansion.otilabs.requests.get")
def test_rejected_key(mock_get):
    mock_get.return_value = _response(status_code=403)
    result = otilabs.handler(_query())
    assert "rejected the key" in result["error"]


@patch("misp_modules.modules.expansion.otilabs.requests.get")
def test_quota_reached(mock_get):
    mock_get.return_value = _response(status_code=429)
    result = otilabs.handler(_query())
    assert "429" in result["error"]


@patch("misp_modules.modules.expansion.otilabs.requests.get")
def test_network_error(mock_get):
    mock_get.side_effect = RequestsConnectionError("connection refused")
    result = otilabs.handler(_query())
    assert "Error while querying the OTI Labs API" in result["error"]


@patch("misp_modules.modules.expansion.otilabs.requests.get")
def test_no_usable_data(mock_get):
    payload = {name: {"error": "unavailable"} for name in ("whois", "ssl", "dns", "subdomains", "email_security")}
    mock_get.return_value = _response(payload=payload)
    result = otilabs.handler(_query())
    assert "no data" in result["error"]
