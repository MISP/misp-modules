import json
import socketserver
import threading
from unittest.mock import MagicMock

import dns.exception
import dns.message
import dns.resolver
import dns.rrset
import pytest
from pymisp import MISPObject

from misp_modules.modules.expansion import email_authentication as module

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


@pytest.fixture
def resolver(monkeypatch):
    mock = MagicMock()
    mock.resolve.side_effect = dns.resolver.NoAnswer
    factory = MagicMock(return_value=mock)
    monkeypatch.setattr(module.dns.resolver, "Resolver", factory)
    return mock


def _answers(resolver, records):
    def resolve(name, kind, *, search, lifetime):
        assert kind == "TXT" and search is False
        assert 0 < lifetime <= 10
        data = records.get(name, dns.resolver.NoAnswer())
        if isinstance(data, Exception):
            raise data
        if not isinstance(data, dns.rrset.RRset):
            data = dns.rrset.from_text(name, 300, "IN", "TXT", *data)
        return _Answer(data)

    resolver.resolve.side_effect = resolve


class _Answer:
    def __init__(self, rrset):
        self.rrset = rrset

    def __iter__(self):
        return iter(self.rrset)


def _run(value="example.org", kind="domain", config=None, **metadata):
    attribute = {"type": kind, "value": value, "uuid": UUID, **metadata}
    return module.handler(json.dumps({"attribute": attribute, "config": config}))


def _values(obj, relation):
    return [a["value"] for a in obj["Attribute"] if a["object_relation"] == relation]


def _objects(result, relation=None):
    objects = result["results"]["Object"]
    return objects if relation is None else [obj for obj in objects if _values(obj, relation)]


def test_records_are_linked_and_template_validates(resolver):
    _answers(
        resolver,
        {
            "example.org.": ('"v=spf1 include:mail.example.net " "-all"', '"unrelated TXT"'),
            "_dmarc.example.org.": ('"v=DMARC1; p=reject; rua=mailto:reports@example.org"',),
            "google._domainkey.example.org.": ('"v=DKIM1; k=rsa; " "p=ABCDEF"',),
        },
    )
    result = _run(comment="Source", to_ids=True, Tag=[{"name": "tlp:clear"}])
    assert len(_objects(result)) == 3
    source = result["results"]["Attribute"][0]
    assert (source["uuid"], source["comment"], source["to_ids"]) == (UUID, "Source", True)
    assert source["Tag"][0]["name"] == "tlp:clear"
    assert _values(_objects(result, "spf-record")[0], "spf-record") == ["v=spf1 include:mail.example.net -all"]
    assert _values(_objects(result, "dkim-record")[0], "dkim-selector") == ["google"]
    for obj in _objects(result):
        strict = MISPObject("email-authentication", strict=True, misp_objects_template_custom=module._object_template())
        strict.from_dict(**obj)
        strict._validate()
        assert obj["template_uuid"] == "7ab39b08-20d6-4be6-9ddd-d1bc37fe4b0a"
        assert obj["template_version"] == "2"
        assert obj["first_seen"] == obj["last_seen"]
        assert _values(obj, "domain") == ["example.org"]
        assert [str(v) for v in _values(obj, "dns-ttl")] == ["300"]
        assert all(a["to_ids"] is False for a in obj["Attribute"])
        assert not any(_values(obj, relation) for relation in ("spf", "dkim", "dmarc", "dkim-signature"))
        assert [(r["referenced_uuid"], r["relationship_type"]) for r in obj["ObjectReference"]] == [
            (UUID, "derived-from")
        ]
    names = {c.args[0] for c in resolver.resolve.call_args_list}
    assert names == {"example.org.", "_dmarc.example.org."} | {
        f"{selector}._domainkey.example.org." for selector in module.DEFAULT_SELECTORS
    }


def test_original_message_results_remain_valid():
    obj = MISPObject("email-authentication", strict=True, misp_objects_template_custom=module._object_template())
    obj.add_attribute("spf", "pass")
    obj.add_attribute("dkim", "fail")
    obj.add_attribute("dmarc", "fail")
    obj.add_attribute("dkim-domain", "example.org")
    obj._validate()
    assert all(a.to_ids is False for a in obj.attributes)


def test_selectors_alias_owners_and_multiple_records(resolver):
    target = dns.rrset.from_text("keys.provider.net.", 60, "IN", "TXT", '"k=rsa; p=ABC"', '"v=DKIM1; p="')
    _answers(
        resolver,
        {
            "example.org.": ('"v=spf1 -all"', '"v=spf1 ~all"'),
            "custom._domainkey.example.org.": target,
        },
    )
    result = _run(config={"dkim_selectors": "custom, custom, dotted.selector"})
    assert len(_objects(result, "spf-record")) == 2
    assert len(_objects(result, "dkim-record")) == 2
    for obj in _objects(result, "dkim-record"):
        assert _values(obj, "dns-owner") == ["keys.provider.net"]
        assert _values(obj, "dns-name") == ["custom._domainkey.example.org"]
        assert _values(obj, "dkim-selector") == ["custom"]
    assert resolver.resolve.call_count == 4


@pytest.mark.parametrize(
    "record,relation,expected",
    [
        ("v=spf1 -all", "spf-record", True),
        ("V=SPF1 -all", "spf-record", True),
        ("v=spf10 -all", "spf-record", False),
        ("text v=spf1 -all", "spf-record", False),
        ("v=DMARC1; p=reject", "dmarc-record", True),
        ("v=DMARC10; p=reject", "dmarc-record", False),
        ("v=DKIM1 ; k=rsa; p=ABC", "dkim-record", True),
        ("p=", "dkim-record", True),
        ("k=rsa; p=ABC", "dkim-record", True),
        ("k=rsa", "dkim-record", False),
        ("v=STSv1; p=ABC", "dkim-record", False),
        ("v=DKIM1; p=ABC; p=DEF", "dkim-record", False),
        ("text p=ABC", "dkim-record", False),
    ],
)
def test_record_detection(record, relation, expected):
    assert module._matches(record, relation) is expected


def test_partial_errors_preserve_success_and_are_distinct_from_absence(resolver):
    _answers(
        resolver,
        {
            "example.org.": ('"v=spf1 -all"',),
            "_dmarc.example.org.": dns.exception.Timeout(),
            "s1._domainkey.example.org.": dns.resolver.NoNameservers(),
        },
    )
    result = _run(config={"dkim_selectors": "s1,s2", "nameserver": "2001:db8::53", "query_timeout": "1"})
    assert len(_objects(result)) == 1
    comment = _objects(result)[0]["comment"]
    assert "_dmarc.example.org: Timeout" in comment
    assert "s1._domainkey.example.org: NoNameservers" in comment
    assert "s2._domainkey" not in comment
    assert resolver.nameservers == ["2001:db8::53"] and resolver.timeout == 1


@pytest.mark.parametrize("error", [dns.resolver.NoAnswer(), dns.resolver.NXDOMAIN(), dns.exception.Timeout()])
def test_no_results_does_not_claim_authentication_failure(resolver, error):
    resolver.resolve.side_effect = error
    result = _run()
    assert "No email-authentication DNS records found" in result["error"]
    assert "configured selectors" in result["error"]
    assert ("Timeout" in result["error"]) == isinstance(error, dns.exception.Timeout)


@pytest.mark.parametrize(
    "value,kind",
    [("BÜCHER.example.", "hostname"), ("Mail.BÜCHER.example.", "domain")],
)
def test_exact_hostname_and_idna_are_used_without_parent_fallback(resolver, value, kind):
    result = _run(value, kind, config={"dkim_selectors": "s1"})
    assert "error" in result  # No matching records.
    domain = value.removesuffix(".").encode("idna").decode().lower()
    assert {c.args[0] for c in resolver.resolve.call_args_list} == {
        domain + ".",
        f"_dmarc.{domain}.",
        f"s1._domainkey.{domain}.",
    }


@pytest.mark.parametrize(
    "value,kind,metadata",
    [
        ("example.org", "md5", {}),
        ("bad..example", "domain", {}),
        ("example.org..", "hostname", {}),
        ("example.org/path", "hostname", {}),
        ("-bad.example", "domain", {}),
        ("bad name", "domain", {}),
        ("example.org\n", "domain", {}),
        ("127.0.0.1", "domain", {}),
        (None, "domain", {}),
        (12, "hostname", {}),
        ("example.org", "domain", {"uuid": "invalid"}),
        ("example.org", "domain", {"uuid": None}),
    ],
)
def test_invalid_input_sends_no_queries(resolver, value, kind, metadata):
    assert "error" in _run(value, kind, **metadata)
    resolver.resolve.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [
        [],
        {"nameserver": "dns.invalid"},
        {"dkim_selectors": []},
        {"dkim_selectors": "s1,,s2"},
        {"dkim_selectors": ",".join(f"s{i}" for i in range(33))},
        {"query_timeout": "nan"},
        {"query_timeout": True},
        {"query_timeout": 0},
        {"max_time": 26},
        {"max_time": "inf"},
    ],
)
def test_invalid_config_sends_no_queries(resolver, config):
    assert "error" in _run(config=config)
    resolver.resolve.assert_not_called()


@pytest.mark.parametrize("payload", ["{", "null", "[]", "1", "{}", '{"attribute": []}'])
def test_malformed_requests(resolver, payload):
    assert "error" in module.handler(payload)
    resolver.resolve.assert_not_called()


def test_deadline_bounds_queries(resolver, monkeypatch):
    monkeypatch.setattr(module.time, "monotonic", lambda: 99.5)
    query = ("example.org", "spf-record", None)
    module._lookup(resolver, query, 100, 2)
    assert resolver.resolve.call_args.kwargs["lifetime"] == 0.5
    resolver.reset_mock()
    _, records, warning = module._lookup(resolver, query, 99, 2)
    assert not records and "budget exhausted" in warning
    resolver.resolve.assert_not_called()


def test_limits_and_bad_encoding_preserve_success(resolver, monkeypatch):
    monkeypatch.setattr(module, "MAX_RECORDS_PER_QUERY", 1)
    _answers(resolver, {"example.org.": (r'"\255"', '"v=spf1 -all"', '"v=spf1 ~all"')})
    obj = _objects(_run())[0]
    assert "non-UTF-8" in obj["comment"]
    assert "record limit of 1" in obj["comment"]


def test_settings_and_metadata():
    assert module._settings({k: "" for k in module.moduleconfig}, "example.org") == module._settings({}, "example.org")
    assert module.handler() is False
    assert module.introspection() == {"input": ["hostname", "domain"], "format": "misp_standard"}
    assert module.version()["config"] == module.moduleconfig
    assert "config" not in module.moduleinfo


def test_real_dns_with_cname_and_split_txt(monkeypatch):
    queries = []

    class DNSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            wire, sock = self.request
            query = dns.message.from_wire(wire)
            name = query.question[0].name.to_text()
            queries.append(name)
            response = dns.message.make_response(query)
            if name == "s1._domainkey.example.org.":
                response.answer.append(dns.rrset.from_text(name, 60, "IN", "CNAME", "keys.provider.net."))
                response.answer.append(
                    dns.rrset.from_text("keys.provider.net.", 123, "IN", "TXT", '"v=DKIM1; " "p=ABC"')
                )
            else:
                record = '"v=spf1 " "-all"' if name == "example.org." else '"v=DMARC1; p=reject"'
                response.answer.append(dns.rrset.from_text(name, 300, "IN", "TXT", record))
            sock.sendto(response.to_wire(), self.client_address)

    with socketserver.ThreadingUDPServer(("127.0.0.1", 0), DNSHandler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["127.0.0.1"]
        resolver.port = server.server_address[1]
        monkeypatch.setattr(module.dns.resolver, "Resolver", lambda: resolver)
        try:
            result = _run(config={"dkim_selectors": "s1"})
        finally:
            server.shutdown()
            thread.join(timeout=2)
    assert len(queries) == 3
    assert len(_objects(result)) == 3
    obj = _objects(result, "dkim-record")[0]
    assert _values(obj, "dkim-record") == ["v=DKIM1; p=ABC"]
    assert _values(obj, "dns-owner") == ["keys.provider.net"]
    assert [str(v) for v in _values(obj, "dns-ttl")] == ["123"]
