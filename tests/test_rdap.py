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


_EMPTY_DOMAIN_RDAP = {"objectClassName": "domain", "events": [], "entities": []}


def _relations(whois, relation):
    return [a["value"] for a in whois["Attribute"] if a["object_relation"] == relation]


def _asked(mock_get):
    assert mock_get.call_count == 1
    return mock_get.call_args.args[0]


def test_url_resolves_to_registered_domain_of_host():
    attribute = {
        "type": "url",
        "value": "https://sub.example.com/path?q=1",
        "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b",
    }
    result, mock_get = _run(attribute, _EMPTY_DOMAIN_RDAP)
    assert _asked(mock_get).endswith("rdap.org/domain/example.com")
    whois = _whois_object(result)
    assert _relations(whois, "domain") == ["example.com"]
    assert _relations(whois, "comment") == [
        "Registration data for example.com, the registered domain of sub.example.com."
    ]


def test_subdomain_is_looked_up_at_registered_domain():
    attribute = {"type": "hostname", "value": "login.example.com", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, _DOMAIN_RDAP)
    assert _asked(mock_get).endswith("rdap.org/domain/example.com")
    whois = _whois_object(result)
    assert _relations(whois, "domain") == ["example.com"]
    assert _relations(whois, "comment") == [
        "Registration data for example.com, the registered domain of login.example.com."
    ]


def test_registered_domain_has_no_comment():
    attribute = {"type": "domain", "value": "example.com", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, _DOMAIN_RDAP)
    assert _asked(mock_get).endswith("rdap.org/domain/example.com")
    whois = _whois_object(result)
    assert _relations(whois, "domain") == ["example.com"]
    assert _relations(whois, "comment") == []


def test_multi_label_public_suffix():
    attribute = {"type": "hostname", "value": "news.bbc.co.uk", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, _EMPTY_DOMAIN_RDAP)
    assert _asked(mock_get).endswith("rdap.org/domain/bbc.co.uk")
    assert _relations(_whois_object(result), "domain") == ["bbc.co.uk"]


def test_private_suffix_is_ignored():
    attribute = {"type": "hostname", "value": "foo.duckdns.org", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, _EMPTY_DOMAIN_RDAP)
    assert _asked(mock_get).endswith("rdap.org/domain/duckdns.org")
    assert _relations(_whois_object(result), "domain") == ["duckdns.org"]


def test_input_is_normalised():
    attribute = {"type": "domain", "value": " Login.Example.COM. ", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, _DOMAIN_RDAP)
    assert _asked(mock_get).endswith("rdap.org/domain/example.com")
    assert _relations(_whois_object(result), "comment") == [
        "Registration data for example.com, the registered domain of login.example.com."
    ]


def test_public_suffix_is_asked_as_given():
    attribute = {"type": "domain", "value": "co.uk", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, _EMPTY_DOMAIN_RDAP)
    assert _asked(mock_get).endswith("rdap.org/domain/co.uk")
    whois = _whois_object(result)
    assert _relations(whois, "domain") == ["co.uk"]
    assert _relations(whois, "comment") == []


def test_unknown_tld_uses_default_rule():
    attribute = {"type": "domain", "value": "foo.notatld", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, _EMPTY_DOMAIN_RDAP)
    assert _asked(mock_get).endswith("rdap.org/domain/foo.notatld")
    assert _relations(_whois_object(result), "comment") == []


def test_domain_relation_ignores_ldhname_case():
    attribute = {"type": "hostname", "value": "www.example.com", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, dict(_DOMAIN_RDAP, ldhName="EXAMPLE.COM"))
    assert _asked(mock_get).endswith("rdap.org/domain/example.com")
    assert _relations(_whois_object(result), "domain") == ["example.com"]


def test_bad_request_on_registered_domain_names_both():
    attribute = {"type": "hostname", "value": "login.example.org", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, None, status_code=400)
    assert _asked(mock_get).endswith("rdap.org/domain/example.org")
    assert result == {"error": "No RDAP record found for example.org (the registered domain of login.example.org)."}


def test_not_found_on_registered_domain_names_both():
    attribute = {"type": "hostname", "value": "x.github.io", "uuid": "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"}
    result, mock_get = _run(attribute, None, status_code=404)
    assert _asked(mock_get).endswith("rdap.org/domain/github.io")
    assert result == {"error": "No RDAP record found for github.io (the registered domain of x.github.io)."}


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
