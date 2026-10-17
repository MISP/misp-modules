import json
import socketserver
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import dns.exception
import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest
from pymisp import MISPObject

from misp_modules.modules.expansion import dns_query

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


@pytest.fixture
def resolver(monkeypatch):
    mock = MagicMock()
    mock.resolve.side_effect = dns.resolver.NoAnswer
    monkeypatch.setattr(dns_query.dns.resolver, "Resolver", lambda: mock)
    return mock


def _answers(resolver, answers):
    def resolve(name, kind, *, search, lifetime):
        assert search is False
        assert 0 < lifetime <= 10
        answer = answers.get((name, kind), dns.resolver.NoAnswer())
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, list):
            rrsets = answer
        else:
            rrsets = [dns.rrset.from_text(name, 300, "IN", kind, *answer)]
        return SimpleNamespace(response=SimpleNamespace(answer=rrsets))

    resolver.resolve.side_effect = resolve


def _run(value="example.org", kind="domain", config=None, **metadata):
    source = {"type": kind, "value": value, "uuid": UUID, **metadata}
    return dns_query.handler(json.dumps({"attribute": source, "config": config}))


def _objects(result, kind=None):
    objects = result["results"]["Object"]
    return objects if kind is None else [obj for obj in objects if _values(obj, "rrtype") == [kind]]


def _values(obj, relation):
    return [str(a["value"]) for a in obj["Attribute"] if a["object_relation"] == relation]


def test_all_types_are_queried_explicitly_and_templates_validate(resolver):
    _answers(resolver, {("example.org.", "A"): ("192.0.2.1", "192.0.2.2")})
    result = _run(comment="Original source", to_ids=True, Tag=[{"name": "tlp:clear"}])
    queried = {(c.args[0], c.args[1]) for c in resolver.resolve.call_args_list}
    assert {kind for name, kind in queried if name == "example.org."} == set(dns_query.DEFAULT_TYPES)
    assert {"SOA", "TXT", "CAA", "TLSA", "DNSKEY", "SVCB", "HTTPS"} <= set(dns_query.DEFAULT_TYPES)
    assert not set(dns_query.DEFAULT_TYPES) & {"ANY", "AXFR", "IXFR", "OPT", "TKEY", "TSIG", "TYPE0"}
    assert {(f"{prefix}.example.org.", "TXT") for prefix in ("_dmarc", "_mta-sts", "_smtp._tls")} <= queried
    assert len(_objects(result)) == 2
    source = result["results"]["Attribute"][0]
    assert (source["uuid"], source["comment"], source["to_ids"]) == (UUID, "Original source", True)
    assert source["Tag"][0]["name"] == "tlp:clear"
    for obj in _objects(result):
        strict = MISPObject(
            "dns-resource-record", strict=True, misp_objects_template_custom=dns_query._object_template()
        )
        strict.from_dict(**obj)
        strict._validate()
        assert _values(obj, "ttl") == ["300"]
        assert _values(obj, "rrclass") == ["IN"]
        assert obj["first_seen"] == obj["last_seen"]
        assert all(a["to_ids"] is False for a in obj["Attribute"])
        assert [(r["referenced_uuid"], r["relationship_type"]) for r in obj["ObjectReference"]] == [
            (UUID, "derived-from")
        ]


def test_soa_preserves_full_rdata_and_decodes_mailbox(resolver):
    soa = r"ns.example.net. first\.last.example.org. 2026101701 3600 600 86400 300"
    _answers(resolver, {("example.org.", "SOA"): (soa,)})
    obj = _objects(_run(config={"max_pivots": 0}), "SOA")[0]
    assert _values(obj, "rdata") == [soa]
    assert _values(obj, "domain") == ["ns.example.net"]
    assert _values(obj, "soa-email") == ["first.last@example.org"]
    assert [_values(obj, field)[0] for field in ("serial", "refresh", "retry", "expire", "minimum")] == [
        "2026101701",
        "3600",
        "600",
        "86400",
        "300",
    ]


@pytest.mark.parametrize(
    "kind,data,expected",
    [
        ("MX", "10 mail.example.net.", {"domain": ["mail.example.net"], "priority": ["10"]}),
        (
            "SRV",
            "1 20 443 service.example.net.",
            {"domain": ["service.example.net"], "port": ["443"], "weight": ["20"]},
        ),
        ("NS", "ns.example.net.", {"domain": ["ns.example.net"]}),
        ("PTR", "host.example.net.", {"domain": ["host.example.net"]}),
        ("DNAME", "other.example.net.", {"domain": ["other.example.net"]}),
        ("NAPTR", '1 1 "S" "SIP+D2U" "" _sip._udp.example.net.', {"domain": ["_sip._udp.example.net"]}),
        ("CAA", '0 issue "ca.example.net; accounturi=123"', {"domain": ["ca.example.net"]}),
        ("CAA", '0 iodef "mailto:security@example.net"', {"email": ["security@example.net"]}),
        ("URI", '1 2 "https://service.example.net/path"', {"url": ["https://service.example.net/path"]}),
        (
            "RP",
            "security.example.net. info.example.net.",
            {"email": ["security@example.net"], "domain": ["info.example.net"]},
        ),
        (
            "HTTPS",
            "1 svc.example.net. port=8443 ipv4hint=192.0.2.1 ipv6hint=2001:db8::1",
            {"domain": ["svc.example.net"], "port": ["8443"], "ip": ["192.0.2.1", "2001:db8::1"]},
        ),
        ("TLSA", "3 1 1 aabbccdd", {}),
        ("TYPE65400", r"\# 4 aabbccdd", {}),
    ],
)
def test_record_pivots_and_uncommon_records_are_retained(resolver, kind, data, expected):
    _answers(resolver, {("example.org.", kind): (data,)})
    obj = _objects(_run(config={"record_types": kind, "mail_policy": False, "max_pivots": 0}), kind)[0]
    record = dns.rrset.from_text("example.org.", 300, "IN", kind, data)[0]
    assert _values(obj, "rdata") == [record.to_text()]
    for relation, values in expected.items():
        assert _values(obj, relation) == values


def test_txt_chunks_spf_networks_and_mail_policy_pivots(resolver):
    text = '"v=spf1 ip4:192.0.2.0/24 " "ip6:2001:db8::/32 include:mail.example.net redirect=other.example.net -all"'
    _answers(
        resolver,
        {
            ("example.org.", "TXT"): (text,),
            ("_dmarc.example.org.", "TXT"): ('"v=DMARC1; p=reject; rua=mailto:reports@example.net"',),
            ("_smtp._tls.example.org.", "TXT"): ('"v=TLSRPTv1; rua=https://reports.example.net/tls"',),
        },
    )
    result = _run(config={"record_types": "TXT", "max_pivots": 0})
    obj = next(o for o in _objects(result) if _values(o, "rrname") == ["example.org"])
    assert _values(obj, "rdata") == [text]
    assert _values(obj, "text") == [
        "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:mail.example.net redirect=other.example.net -all"
    ]
    assert _values(obj, "ip") == ["192.0.2.0/24", "2001:db8::/32"]
    assert set(_values(obj, "domain")) == {"mail.example.net", "other.example.net"}
    assert any(_values(o, "email") == ["reports@example.net"] for o in _objects(result))
    assert any(_values(o, "url") == ["https://reports.example.net/tls"] for o in _objects(result))


def test_alias_owners_deduplication_and_bounded_followups(resolver):
    cname = dns.rrset.from_text("example.org.", 60, "IN", "CNAME", "target.example.net.")
    target = dns.rrset.from_text("target.example.net.", 120, "IN", "A", "192.0.2.1")
    _answers(
        resolver,
        {
            ("example.org.", "A"): [cname, target],
            ("example.org.", "CNAME"): [cname],
            ("target.example.net.", "A"): [target],
            ("target.example.net.", "AAAA"): [
                dns.rrset.from_text("target.example.net.", 120, "IN", "CNAME", "third.example.net.")
            ],
        },
    )
    result = _run(config={"record_types": "A,CNAME", "mail_policy": False})
    assert len(_objects(result, "A")) == 1
    obj = _objects(result, "A")[0]
    assert _values(obj, "rrname") == ["target.example.net"]
    assert _values(obj, "queried-name") == ["example.org", "target.example.net"]
    queries = {(c.args[0], c.args[1]) for c in resolver.resolve.call_args_list}
    assert ("target.example.net.", "AAAA") in queries
    assert not any(name == "third.example.net." for name, _ in queries)


@pytest.mark.parametrize(
    "kind,value,name",
    [
        ("domain|ip", "Example.org|192.0.2.1", "example.org."),
        ("hostname|port", "_sip._tcp.Example.org|443", "_sip._tcp.example.org."),
        ("url", "https://Example.org:443/path", "example.org."),
        ("email-src", "alice@Example.org", "example.org."),
        ("email-dst", "bob@example.org", "example.org."),
        ("dns-soa-email", "hostmaster@example.org", "example.org."),
        ("hostname", "BÜCHER.example.", "xn--bcher-kva.example."),
        ("ip-src", "192.0.2.1", "1.2.0.192.in-addr.arpa."),
        (
            "ip-dst|port",
            "2001:db8::1|443",
            ipaddress_name := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ),
        ("url", "https://[2001:db8::1]/", ipaddress_name),
    ],
)
def test_inputs_normalize_to_absolute_dns_names(resolver, kind, value, name):
    _answers(resolver, {(name, "TXT"): ('"ok"',)})
    assert "results" in _run(value, kind, config={"record_types": "TXT", "mail_policy": False})
    assert resolver.resolve.call_args.args == (name, "TXT")


@pytest.mark.parametrize(
    "kind,value",
    [
        ("md5", "a" * 32),
        ("ip-src", "not-ip"),
        ("domain", "bad..example.org"),
        ("hostname", "-bad.example"),
        ("domain", "bad name"),
        ("domain", ""),
        ("domain", None),
        ("domain", 1),
        ("domain", "example.org\n"),
        ("url", "example.org/path"),
        ("url", "http://example.org:invalid/"),
        ("url", "http://%65xample.org/"),
        ("domain|ip", "example.org|invalid"),
        ("hostname|port", "example.org|65536"),
        ("email", "missing-at"),
    ],
)
def test_invalid_inputs_do_not_send_queries(resolver, kind, value):
    assert "error" in _run(value, kind)
    resolver.resolve.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [
        [],
        {"record_types": []},
        {"record_types": "ANY"},
        {"record_types": "AXFR"},
        {"record_types": "IXFR"},
        {"record_types": "OPT"},
        {"record_types": "TSIG"},
        {"record_types": "TYPE0"},
        {"record_types": "TYPO"},
        {"nameserver": "invalid"},
        {"max_time": 0},
        {"max_time": 121},
        {"max_time": "nan"},
        {"query_timeout": "inf"},
        {"max_pivots": -1},
        {"max_pivots": 1.5},
        {"mail_policy": "maybe"},
    ],
)
def test_invalid_config_does_not_send_queries(resolver, config):
    assert "error" in _run(config=config)
    resolver.resolve.assert_not_called()


def test_partial_failures_preserve_records_and_resolver_configuration(resolver):
    _answers(
        resolver,
        {
            ("example.org.", "A"): ("192.0.2.1",),
            ("example.org.", "AAAA"): dns.exception.Timeout(),
            ("example.org.", "TXT"): dns.resolver.NoNameservers(),
        },
    )
    result = _run(
        config={"record_types": "A,AAAA,TXT", "nameserver": "2001:db8::53", "query_timeout": "1", "mail_policy": False}
    )
    assert len(_objects(result)) == 1
    assert "AAAA: Timeout" in _objects(result)[0]["comment"]
    assert "TXT: NoNameservers" in _objects(result)[0]["comment"]
    assert resolver.nameservers == ["2001:db8::53"]
    assert resolver.timeout == 1


@pytest.mark.parametrize("error", [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer(), dns.exception.Timeout()])
def test_no_results_has_clear_error(resolver, error):
    resolver.resolve.side_effect = error
    result = _run(config={"record_types": "A", "mail_policy": False})
    assert "No DNS records returned" in result["error"]
    if not isinstance(error, dns.resolver.NoAnswer):
        assert type(error).__name__ in result["error"]


def test_expired_deadline_sends_no_query(resolver, monkeypatch):
    monkeypatch.setattr(dns_query.time, "monotonic", lambda: 100)
    _, rrsets, warning = dns_query._lookup(resolver, "example.org.", "TXT", 99, 2)
    assert not rrsets and "budget exhausted" in warning
    resolver.resolve.assert_not_called()


def test_query_lifetime_is_limited_to_remaining_budget(resolver, monkeypatch):
    monkeypatch.setattr(dns_query.time, "monotonic", lambda: 99.5)
    dns_query._lookup(resolver, "example.org.", "TXT", 100, 2)
    assert resolver.resolve.call_args.kwargs["lifetime"] == 0.5


def test_record_and_pivot_limits_are_reported(resolver, monkeypatch):
    _answers(resolver, {("example.org.", "NS"): ("ns1.example.net.", "ns2.example.net.", "ns3.example.net.")})
    result = _run(config={"record_types": "NS", "max_pivots": 1, "mail_policy": False})
    assert "limited to 1 of 3" in _objects(result)[0]["comment"]
    assert len(resolver.resolve.call_args_list) == 3  # NS plus one A/AAAA pair.
    monkeypatch.setattr(dns_query, "MAX_RECORDS", 2)
    result = _run(config={"record_types": "NS", "mail_policy": False})
    assert len(_objects(result)) == 2
    assert "Result limit of 2" in _objects(result)[0]["comment"]


@pytest.mark.parametrize(
    "payload", ["{", "null", "[]", "1", "{}", '{"attribute": []}', '{"attribute": {"type": "domain"}}']
)
def test_malformed_requests(resolver, payload):
    assert "error" in dns_query.handler(payload)
    resolver.resolve.assert_not_called()


def test_invalid_uuid_and_metadata(resolver):
    assert "error" in _run(uuid="invalid")
    assert "error" in _run(uuid=None)
    resolver.resolve.assert_not_called()


def test_introspection_and_version():
    assert dns_query.handler() is False
    assert dns_query.introspection()["format"] == "misp_standard"
    assert dns_query.version()["config"] == dns_query.moduleconfig
    assert "config" not in dns_query.moduleinfo


def test_empty_misp_config_fields_use_defaults():
    assert dns_query._settings({key: "" for key in dns_query.moduleconfig}) == dns_query._settings({})


def test_alias_in_noanswer_is_retained(resolver):
    response = dns.message.make_response(dns.message.make_query("example.org.", "A"))
    response.answer.append(dns.rrset.from_text("example.org.", 60, "IN", "CNAME", "target.example.net."))
    resolver.resolve.side_effect = dns.resolver.NoAnswer(response=response)
    obj = _objects(_run(config={"record_types": "A", "max_pivots": 0, "mail_policy": False}), "CNAME")[0]
    assert _values(obj, "domain") == ["target.example.net"]


@pytest.mark.parametrize("nxdomain", [False, True])
def test_negative_responses_preserve_authority_and_glue(resolver, nxdomain):
    response = dns.message.make_response(dns.message.make_query("empty.example.org.", "TXT"))
    response.authority.append(
        dns.rrset.from_text("example.org.", 300, "IN", "SOA", "ns.example.org. admin.example.org. 1 3600 600 86400 300")
    )
    response.additional.append(dns.rrset.from_text("ns.example.org.", 300, "IN", "A", "192.0.2.53"))
    if nxdomain:
        response.set_rcode(3)
        name = dns_query.dns.name.from_text("empty.example.org.")
        error = dns.resolver.NXDOMAIN(qnames=[name], responses={name: response})
    else:
        error = dns.resolver.NoAnswer(response=response)
    resolver.resolve.side_effect = error
    result = _run("empty.example.org", config={"record_types": "TXT", "mail_policy": False, "max_pivots": 0})
    soa = _objects(result, "SOA")[0]
    glue = _objects(result, "A")[0]
    assert _values(soa, "rrname") == ["example.org"]
    assert _values(soa, "queried-name") == ["empty.example.org"]
    assert _values(soa, "section") == ["authority"]
    assert _values(glue, "section") == ["additional"]
    assert _values(glue, "ip") == ["192.0.2.53"]


def test_root_authority_owner_is_preserved(resolver):
    response = dns.message.make_response(dns.message.make_query("missing.invalid.", "TXT"))
    response.authority.append(
        dns.rrset.from_text(".", 300, "IN", "SOA", "a.root-servers.net. nstld.verisign-grs.com. 1 3600 600 86400 300")
    )
    resolver.resolve.side_effect = dns.resolver.NoAnswer(response=response)
    obj = _objects(_run("missing.invalid", config={"record_types": "TXT", "mail_policy": False, "max_pivots": 0}))[0]
    assert _values(obj, "rrname") == ["."]


def test_invalid_repeated_root_dot_sends_no_query(resolver):
    assert "error" in _run("example.org..")
    resolver.resolve.assert_not_called()


def test_real_dns_wire_responses_over_local_udp(monkeypatch):
    """Exercise dnspython Answer/RRset parsing and EDNS without public DNS."""
    requests = []

    class DNSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            wire, sock = self.request
            query = dns.message.from_wire(wire)
            requests.append(query)
            response = dns.message.make_response(query)
            question = query.question[0]
            kind = dns.rdatatype.to_text(question.rdtype)
            records = {
                "A": "192.0.2.1",
                "SOA": "ns.example.org. admin.example.org. 1 3600 600 86400 300",
                "TXT": '"hello " "world"',
            }
            response.answer.append(dns.rrset.from_text(question.name, 123, "IN", kind, records[kind]))
            sock.sendto(response.to_wire(), self.client_address)

    with socketserver.ThreadingUDPServer(("127.0.0.1", 0), DNSHandler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        real_resolver = dns.resolver.Resolver(configure=False)
        real_resolver.nameservers = ["127.0.0.1"]
        real_resolver.port = server.server_address[1]
        monkeypatch.setattr(dns_query.dns.resolver, "Resolver", lambda: real_resolver)
        try:
            result = _run(config={"record_types": "A,SOA,TXT", "max_pivots": 0, "mail_policy": False})
        finally:
            server.shutdown()
            thread.join(timeout=2)
    assert len(_objects(result)) == 3
    assert _values(_objects(result, "TXT")[0], "text") == ["hello world"]
    assert _values(_objects(result, "SOA")[0], "soa-email") == ["admin@example.org"]
    assert all(_values(obj, "ttl") == ["123"] for obj in _objects(result))
    assert len(requests) == 3
    assert all(query.edns == 0 and query.ednsflags & dns_query.dns.flags.DO for query in requests)
