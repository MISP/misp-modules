import json
import sys
import types
from unittest.mock import MagicMock, patch

# dnstrails is an optional dependency and is not installed in CI, so the module
# under test gets a stub to import.
if "dnstrails" not in sys.modules:
    _stub = types.ModuleType("dnstrails")

    class APIError(Exception):
        def __init__(self, value=""):
            super().__init__(value)
            self.value = value

    _stub.APIError = APIError
    _stub.DnsTrails = object
    sys.modules["dnstrails"] = _stub

from misp_modules.modules.expansion import securitytrails  # noqa: E402

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"

_DOMAIN = {
    "current_dns": {
        "a": {"first_seen": "2019-01-01", "values": [{"ip": "149.13.33.14"}, {"ip": "149.13.33.4"}]},
        "aaaa": {"first_seen": "2020-02-02", "values": [{"ipv6": "2001:db8::1"}]},
        "ns": {"first_seen": "2018-03-03", "values": [{"nameserver": "ns4.eurodns.com"}]},
        "mx": {"first_seen": "2018-04-04", "values": [{"hostname": "mx.circl.lu"}]},
        "soa": {"first_seen": "2018-05-05", "values": [{"email": "hostmaster@eurodns.com"}]},
    }
}

_WHOIS = {
    "contacts": [
        {
            "type": "registrant",
            "email": "hostmaster@eurodns.com",
            "telephone": "+352.123456",
            "name": "CIRCL",
            "registrarName": "EuroDNS",
            "createdDate": "2008-01-01",
        }
    ]
}

_HISTORY_A = {"records": [{"first_seen": "2015-01-01", "last_seen": "2018-12-31", "values": [{"ip": "149.13.33.4"}]}]}
_HISTORY_NS = {
    "records": [{"first_seen": "2014-01-01", "last_seen": "2017-12-31", "values": {"nameserver": "ns1.old.com"}}]
}
_HISTORY_WHOIS = {
    "result": {
        "items": [
            {
                "status": ["clientTransferProhibited"],
                "nameServers": ["ns1.old.com", "ns2.old.com"],
                "contact": [{"type": "registrant", "email": "old@eurodns.com"}],
            }
        ]
    }
}
_SEARCHING = {"records": [{"hostname": "circl.lu", "host_provider": ["EuroDNS"], "whois": {"registrar": "EuroDNS"}}]}


def _api(**overrides):
    api = MagicMock()
    api.domain.return_value = overrides.get("domain", _DOMAIN)
    api.subdomains.return_value = overrides.get("subdomains", {"subdomains": ["www"]})
    api.whois.return_value = overrides.get("whois", _WHOIS)
    api.history_dns_ipv4.return_value = overrides.get("history_ipv4", _HISTORY_A)
    api.history_dns_aaaa.return_value = {}
    api.history_dns_ns.return_value = overrides.get("history_ns", _HISTORY_NS)
    api.history_dns_soa.return_value = {}
    api.history_dns_mx.return_value = {}
    api.history_whois.return_value = overrides.get("history_whois", _HISTORY_WHOIS)
    api.searching_domains.return_value = overrides.get("searching", _SEARCHING)
    return api


def _run(attribute, api=None, config=None):
    query = json.dumps(
        {
            "module": "securitytrails",
            "attribute": attribute,
            "config": config if config is not None else {"apikey": "k"},
        }
    )
    with (
        patch.object(securitytrails, "DnsTrails", return_value=api or _api()),
        patch.object(securitytrails.time, "sleep"),
    ):
        return securitytrails.handler(query)


def _objects(result, name):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def test_current_dns_becomes_passive_dns_objects_with_first_seen():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    objects = _objects(_run(attribute), "passive-dns")
    a_records = [obj for obj in objects if ("rrtype", "A") in _values(obj)]
    # one object per value - the two current A records plus the historical one,
    # which shares a value with a current one
    assert {value for obj in a_records for relation, value in _values(obj) if relation == "rdata"} == {
        "149.13.33.14",
        "149.13.33.4",
    }
    assert len(a_records) == 3
    current = next(obj for obj in a_records if ("rdata", "149.13.33.14") in _values(obj))
    values = _values(current)
    assert ("rrname", "circl.lu") in values
    assert ("origin", "SecurityTrails") in values
    # the date that used to be glued into a comment string
    assert ("time_first", "2019-01-01T00:00:00") in values


def test_every_record_type_is_carried():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    objects = _objects(_run(attribute), "passive-dns")
    rrtypes = {value for obj in objects for relation, value in _values(obj) if relation == "rrtype"}
    assert {"A", "AAAA", "NS", "MX", "SOA"} <= rrtypes


def test_history_records_carry_first_and_last_seen():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    objects = _objects(_run(attribute), "passive-dns")
    historical = next(obj for obj in objects if ("rdata", "ns1.old.com") in _values(obj))
    values = _values(historical)
    assert ("time_first", "2014-01-01T00:00:00") in values
    assert ("time_last", "2017-12-31T00:00:00") in values


def test_whois_becomes_a_whois_object():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    whois_objects = _objects(_run(attribute), "whois")
    current = next(obj for obj in whois_objects if ("registrar", "EuroDNS") in _values(obj))
    values = _values(current)
    assert ("registrant-email", "hostmaster@eurodns.com") in values
    assert ("registrant-phone", "+352.123456") in values
    assert ("registrant-name", "CIRCL") in values
    assert ("domain", "circl.lu") in values


def test_whois_history_keeps_nameservers_and_status():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    whois_objects = _objects(_run(attribute), "whois")
    historical = next(obj for obj in whois_objects if ("registrant-email", "old@eurodns.com") in _values(obj))
    values = _values(historical)
    assert ("nameserver", "ns1.old.com") in values
    assert ("nameserver", "ns2.old.com") in values
    assert ("text", "status: clientTransferProhibited") in values


def test_subdomains_are_returned_as_domain_attributes():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    values = {a["value"] for a in _run(attribute)["results"]["Attribute"]}
    assert "www.circl.lu" in values


def test_ip_input_returns_domain_ip_objects():
    attribute = {"type": "ip-src", "value": "149.13.33.14", "uuid": UUID}
    result = _run(attribute)
    values = _values(_objects(result, "domain-ip")[0])
    assert ("domain", "circl.lu") in values
    assert ("ip", "149.13.33.14") in values
    assert ("text", "host provider: EuroDNS") in values


def test_every_object_references_the_input_attribute():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    for misp_object in _run(attribute)["results"]["Object"]:
        references = [(r["referenced_uuid"], r["relationship_type"]) for r in misp_object["ObjectReference"]]
        assert references == [(UUID, "related-to")]


def test_api_error_is_reported():
    api = _api()
    api.domain.side_effect = sys.modules["dnstrails"].APIError("You've exceeded the usage limits for your account.")
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    result = _run(attribute, api=api)
    assert result["error"] == "You've exceeded the usage limits for your account."


def test_missing_api_key_returns_error():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    assert _run(attribute, config={})["error"] == "SecurityTrails authentication is missing"


def test_wrong_attribute_type_returns_error():
    attribute = {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "uuid": UUID}
    assert "error" in _run(attribute)


def test_introspection_and_version():
    assert securitytrails.introspection() == securitytrails.mispattributes
    assert securitytrails.mispattributes["format"] == "misp_standard"
    assert securitytrails.version()["name"] == "SecurityTrails Lookup"
