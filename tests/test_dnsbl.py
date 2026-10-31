import json
from unittest.mock import patch

import dns.resolver
from dns.name import LabelTooLong

from misp_modules.modules.expansion import btc_scam_check, dbl_spamhaus, rbl

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


def _objects(result, name="reputation"):
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


# --------------------------------------------------------------------- rbl


def _rbl_run(attribute, resolve):
    query = json.dumps({"module": "rbl", "attribute": attribute, "config": {}})
    with patch.object(rbl.dns.resolver, "Resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = resolve
        return rbl.handler(query)


def test_rbl_emits_one_object_per_listing_zone():
    listed = {"8.8.8.8.zen.spamhaus.org": ['"listed, see https://x"'], "8.8.8.8.bl.spamcop.net": ['"blocked"']}

    def resolve(name, rdtype):
        if name in listed:
            return listed[name]
        raise dns.resolver.NXDOMAIN

    attribute = {"type": "ip-src", "value": "8.8.8.8", "uuid": UUID}
    objects = _objects(_rbl_run(attribute, resolve))
    assert len(objects) == 2
    zones = {value for obj in objects for relation, value in _values(obj) if relation == "list-name"}
    assert zones == {"zen.spamhaus.org", "bl.spamcop.net"}
    spamhaus = next(obj for obj in objects if ("list-name", "zen.spamhaus.org") in _values(obj))
    assert ("classification", "suspicious") in _values(spamhaus)
    assert ("text", '"listed, see https://x"') in _values(spamhaus)


def test_rbl_objects_reference_the_input_attribute():
    def resolve(name, rdtype):
        if name.endswith("zen.spamhaus.org"):
            return ['"listed"']
        raise dns.resolver.NXDOMAIN

    attribute = {"type": "ip-src", "value": "8.8.8.8", "uuid": UUID}
    references = _objects(_rbl_run(attribute, resolve))[0]["ObjectReference"]
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in references] == [(UUID, "related-to")]


def test_rbl_clean_negative_says_no_data():
    def resolve(name, rdtype):
        raise dns.resolver.NXDOMAIN

    attribute = {"type": "ip-src", "value": "8.8.8.8", "uuid": UUID}
    assert _rbl_run(attribute, resolve)["error"] == "No data found by querying known RBLs"


def test_rbl_resolver_failure_is_not_reported_as_a_clean_negative():
    def resolve(name, rdtype):
        raise AttributeError("Resolver has no attribute 'query'")

    attribute = {"type": "ip-src", "value": "8.8.8.8", "uuid": UUID}
    error = _rbl_run(attribute, resolve)["error"]
    assert error.startswith("Not able to query the RBLs")
    assert "No data found" not in error


# ------------------------------------------------------------- dbl_spamhaus


def _dbl_run(attribute, resolve):
    query = json.dumps({"module": "dbl_spamhaus", "attribute": attribute, "config": {}})
    with patch.object(dbl_spamhaus.resolver, "resolve", side_effect=resolve):
        return dbl_spamhaus.handler(query)


def test_dbl_maps_the_return_code_to_a_verdict_and_keeps_the_wording():
    attribute = {"type": "domain", "value": "totalmateria.net", "uuid": UUID}
    values = _values(_objects(_dbl_run(attribute, lambda *a: ["127.0.1.4"]))[0])
    assert ("classification", "malicious") in values
    assert ("text", "phish domain") in values
    assert ("source", "Spamhaus") in values
    assert ("list-name", "dbl.spamhaus.org") in values


def test_dbl_abused_legitimate_domains_are_only_suspicious():
    attribute = {"type": "domain", "value": "totalmateria.net", "uuid": UUID}
    values = _values(_objects(_dbl_run(attribute, lambda *a: ["127.0.1.104"]))[0])
    assert ("classification", "suspicious") in values
    assert ("text", "abused legit phish") in values


def test_dbl_unknown_return_code_is_not_reported_as_unreachable():
    attribute = {"type": "domain", "value": "totalmateria.net", "uuid": UUID}
    error = _dbl_run(attribute, lambda *a: ["127.0.1.42"])["error"]
    assert "unknown return code 127.0.1.42" in error
    assert "Not able to reach" not in error


def test_dbl_prohibited_query_produces_no_object():
    attribute = {"type": "domain", "value": "8.8.8.8", "uuid": UUID}
    result = _dbl_run(attribute, lambda *a: ["127.0.1.255"])
    assert "IP queries prohibited" in result["error"]


def test_dbl_not_listed_returns_a_clean_negative():
    def resolve(*args):
        raise dns.resolver.NXDOMAIN

    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    assert "is not listed on" in _dbl_run(attribute, resolve)["error"]


def test_dbl_composite_attribute_queries_the_domain():
    attribute = {"type": "domain|ip", "value": "totalmateria.net|1.2.3.4", "uuid": UUID}
    with patch.object(dbl_spamhaus.resolver, "resolve", return_value=["127.0.1.2"]) as mock_resolve:
        dbl_spamhaus.handler(json.dumps({"module": "dbl_spamhaus", "attribute": attribute, "config": {}}))
    assert mock_resolve.call_args.args[0] == "totalmateria.net.dbl.spamhaus.org"


# ------------------------------------------------------------ btc_scam_check


def _btc_run(attribute, resolve):
    query = json.dumps({"module": "btc_scam_check", "attribute": attribute, "config": {}})
    with patch.object(btc_scam_check.resolver, "resolve", side_effect=resolve):
        return btc_scam_check.handler(query)


def test_btc_scam_check_emits_a_malicious_reputation_object():
    attribute = {"type": "btc", "value": "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA", "uuid": UUID}
    values = _values(_objects(_btc_run(attribute, lambda *a: ['"fraudolent bitcoin address"']))[0])
    assert ("classification", "malicious") in values
    assert ("source", "btcblack.it") in values
    assert ("text", "fraudolent bitcoin address") in values


def test_btc_scam_check_unknown_address_produces_no_object():
    def resolve(*args):
        raise dns.resolver.NXDOMAIN

    attribute = {"type": "btc", "value": "1ES14c7qLb5CYhLMUekctxLgc1FV2Ti9DA", "uuid": UUID}
    assert "is not known as a scam address" in _btc_run(attribute, resolve)["error"]


def test_btc_scam_check_invalid_address_returns_error():
    def resolve(*args):
        raise LabelTooLong

    attribute = {"type": "btc", "value": "x" * 100, "uuid": UUID}
    assert "probably not a valid BTC address" in _btc_run(attribute, resolve)["error"]


def test_all_three_are_misp_standard():
    for module in (rbl, dbl_spamhaus, btc_scam_check):
        assert module.introspection() == module.mispattributes
        assert module.mispattributes["format"] == "misp_standard"
        assert "config" in module.version()
