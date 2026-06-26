import json
from unittest.mock import patch

from misp_modules.modules.expansion import rdap


class MockResponse:
    def __init__(self, payload, status_code=200, reason="OK"):
        self.payload = payload
        self.status_code = status_code
        self.reason = reason

    def json(self):
        if self.payload is None:
            raise ValueError("No JSON")
        return self.payload


_DOMAIN_RDAP = {
    "objectClassName": "domain",
    "ldhName": "example.com",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:34Z"},
    ],
    "nameservers": [{"ldhName": "a.iana-servers.net"}, {"ldhName": "b.iana-servers.net"}],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "IANA"]]],
        },
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "John Doe"],
                    ["org", {}, "text", "Example Inc"],
                    ["email", {}, "text", "admin@example.com"],
                ],
            ],
        },
    ],
}


def _run(attribute, payload, status_code=200):
    query = json.dumps({"module": "rdap", "attribute": attribute, "config": {}})
    with patch("misp_modules.modules.expansion.rdap.requests.get") as mock_get:
        mock_get.return_value = MockResponse(payload, status_code=status_code)
        return rdap.handler(query), mock_get


def _whois_object(result):
    return next(obj for obj in result["results"]["Object"] if obj["name"] == "whois")


def test_domain_builds_whois_object():
    attribute = {"type": "domain", "value": "example.com", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, _DOMAIN_RDAP)
    assert "rdap.org/domain/example.com" in mock_get.call_args.args[0]

    whois = _whois_object(result)
    values = {(a["object_relation"], a["value"]) for a in whois["Attribute"]}
    assert ("registrar", "IANA") in values
    # pymisp normalises the datetime relations from "...Z" to an explicit offset
    assert ("creation-date", "1995-08-14T04:00:00+00:00") in values
    assert ("expiration-date", "2026-08-13T04:00:00+00:00") in values
    assert ("modification-date", "2024-08-14T07:01:34+00:00") in values
    assert ("registrant-org", "Example Inc") in values
    assert ("registrant-email", "admin@example.com") in values
    nameservers = {a["value"] for a in whois["Attribute"] if a["object_relation"] == "nameserver"}
    assert nameservers == {"a.iana-servers.net", "b.iana-servers.net"}


def test_ip_uses_ip_endpoint_and_relation():
    attribute = {"type": "ip-src", "value": "1.1.1.1", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, {"objectClassName": "ip network", "events": [], "entities": []})
    assert "rdap.org/ip/1.1.1.1" in mock_get.call_args.args[0]
    whois = _whois_object(result)
    assert ("ip-address", "1.1.1.1") in {(a["object_relation"], a["value"]) for a in whois["Attribute"]}


def test_url_resolves_to_host():
    attribute = {
        "type": "url",
        "value": "https://sub.example.com/path?q=1",
        "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b",
    }
    _, mock_get = _run(attribute, {"objectClassName": "domain", "events": [], "entities": []})
    assert "rdap.org/domain/sub.example.com" in mock_get.call_args.args[0]


def test_not_found_returns_error():
    attribute = {"type": "domain", "value": "nope.invalid", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, _ = _run(attribute, None, status_code=404)
    assert "error" in result


def test_wrong_attribute_type_returns_error():
    attribute = {
        "type": "md5",
        "value": "d41d8cd98f00b204e9800998ecf8427e",
        "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b",
    }
    result, _ = _run(attribute, _DOMAIN_RDAP)
    assert "error" in result


def test_introspection_and_version():
    assert rdap.introspection() == rdap.mispattributes
    assert rdap.version()["name"] == "RDAP Lookup"
