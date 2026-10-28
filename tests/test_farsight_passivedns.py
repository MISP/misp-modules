import json
from copy import deepcopy
from unittest.mock import Mock

import pytest
from pymisp import MISPObject

from misp_modules.modules.expansion import farsight_passivedns as module

SOURCE = {"type": "domain", "value": "example.com", "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"}


def soa(mailbox):
    return f"ns.example.com. {mailbox} 2026102801 3600 600 86400 300"


def record(rdata, rrtype="SOA"):
    return {"rrname": "example.com.", "rrtype": rrtype, "rdata": rdata, "count": 1}


def parse(response):
    parser = module.FarsightDnsdbParser(SOURCE)
    parser.parse_passivedns_results(response)
    return parser.get_results()["results"]


def emails(result):
    return [attribute for attribute in result["Attribute"] if attribute["type"] == "dns-soa-email"]


@pytest.mark.parametrize(
    "mailbox,expected",
    [
        ("foo.bar.tld.", "foo@bar.tld"),
        ("foo.bar.hello.tld", "foo.bar@hello.tld"),
        ("hostmaster.example.com.", "hostmaster@example.com"),
        ("first.last.example.com.", "first.last@example.com"),
        ("first.last.example.co.uk.", "first.last@example.co.uk"),
        ("first.last.tenant.blogspot.com.", "first.last@tenant.blogspot.com"),
        ("First.Last.Example.COM.", "First.Last@Example.COM"),
        (r"first\.last.example.com.", "first.last@example.com"),
        (r"first\046last.example.com.", "first.last@example.com"),
        (r"first\.last.mail.example.com.", "first.last@mail.example.com"),
        ("hostmaster.localdomain.internal.", "hostmaster@localdomain.internal"),
        ("hostmaster+dns.example.com.", "hostmaster+dns@example.com"),
    ],
)
def test_soa_email_is_returned_without_changing_the_raw_record(mailbox, expected):
    raw = soa(mailbox)
    response = {"rrset": [record([raw])]}
    original = deepcopy(response)
    result = parse(response)
    assert response == original
    (email,) = emails(result)
    assert email["value"] == expected
    assert email["to_ids"] is False
    assert email["distribution"] == str(module.DEFAULT_DISTRIBUTION_SETTING)
    assert "heuristic" in email["comment"]
    assert "rrset lookup on DNSDB" in email["comment"]
    assert result["Attribute"][0]["uuid"] == SOURCE["uuid"]
    (obj,) = result["Object"]
    assert [a["value"] for a in obj["Attribute"] if a["object_relation"] == "rdata"] == [raw]
    assert {r["referenced_uuid"] for r in obj["ObjectReference"]} == {SOURCE["uuid"], email["uuid"]}
    strict = MISPObject("passive-dns", strict=True)
    strict.from_dict(**obj)
    strict._validate()


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not an SOA record",
        "ns.example.com. hostmaster.example.com.",
        "ns.example.com. hostmaster.example.com. invalid 3600 600 86400 300",
        soa("."),
        soa("hostmaster."),
        soa("hostmaster.local."),
        soa("bad..example.com."),
        soa(r"foo\032bar.example.com."),
        soa(r"\032foobar.example.com."),
        soa(r"foo\009bar.example.com."),
        soa(r"foo\010bar.example.com."),
        soa(r"foo\000bar.example.com."),
        soa(r"foo\127bar.example.com."),
        soa(r"foo\255bar.example.com."),
        soa(r"foo\064bar.example.com."),
        soa(r"foo\"bar.example.com."),
        soa(r"foo\\bar.example.com."),
        soa(r"\.foo.example.com."),
        soa(r"foo\..example.com."),
        soa(r"foo\.\.bar.example.com."),
        soa(r"first\.last.bad\032domain.com."),
        soa(r"hostmaster.bad\064domain.com."),
        soa(r"first\.last.-example.com."),
        soa(r"first\.last.example-.com."),
        soa("hostmaster.domain_with_underscore.com."),
        soa(f"{'a' * 40}.{'b' * 40}.example.com."),
    ],
)
def test_invalid_or_missing_mailbox_preserves_raw_data_without_an_email(raw):
    result = parse({"rrset": [record([raw])]})
    assert not emails(result)
    (obj,) = result["Object"]
    assert [a["value"] for a in obj["Attribute"] if a["object_relation"] == "rdata"] == ([raw] if raw else [])


def test_multiple_rdata_values_and_lookups_share_email_attributes():
    first = soa("first.last.example.com.")
    second = soa("admin.example.co.uk.")
    result = parse({"rrset": [record([first, second])], "rdata": [record(first)]})
    assert {a["value"] for a in emails(result)} == {"first.last@example.com", "admin@example.co.uk"}
    first_email = next(a for a in emails(result) if a["value"] == "first.last@example.com")
    for obj in result["Object"]:
        assert first_email["uuid"] in {r["referenced_uuid"] for r in obj["ObjectReference"]}


def test_non_soa_records_do_not_produce_emails():
    response = {"rrset": [record([soa("first.last.example.com.")], "TXT"), record(["192.0.2.1"], "A")]}
    result = parse(response)
    assert not emails(result)
    assert len(result["Object"]) == 2


@pytest.mark.parametrize("query_type", ["rrset", "rdata", "flex_rdata", "flex_rrnames"])
def test_handler_extracts_emails_from_each_lookup_type(monkeypatch, query_type):
    client = Mock()
    client.lookup_rrset.return_value = []
    client.lookup_rdata_name.return_value = []
    client.flex_rdata_regex.return_value = []
    client.flex_rrnames_regex.return_value = []
    method = {
        "rrset": "lookup_rrset",
        "rdata": "lookup_rdata_name",
        "flex_rdata": "flex_rdata_regex",
        "flex_rrnames": "flex_rrnames_regex",
    }[query_type]
    getattr(client, method).return_value = [record([soa("first.last.example.co.uk.")])]
    monkeypatch.setattr(module.dnsdb2, "Client", lambda **kwargs: client)
    result = module.handler(json.dumps({"attribute": SOURCE, "config": {"apikey": "test-key", "flex_queries": True}}))[
        "results"
    ]
    assert [a["value"] for a in emails(result)] == ["first.last@example.co.uk"]
