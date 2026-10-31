import json
from unittest.mock import patch

from misp_modules.modules.expansion import dns as dns_module
from misp_modules.modules.expansion import reversedns

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"


def _run(module, attribute, answer, config=None):
    """`answer` is a list for reversedns, or a {rdtype: list} map for dns, which
    queries A and AAAA."""
    query = json.dumps({"module": "dns", "attribute": attribute, "config": config or {}})
    with patch.object(module.resolver if module is reversedns else module.dns.resolver, "Resolver") as mock_resolver:
        if isinstance(answer, dict):

            def resolve(name, rdtype):
                if rdtype not in answer:
                    raise dns_module.dns.resolver.NoAnswer
                return answer[rdtype]

            mock_resolver.return_value.resolve.side_effect = resolve
        else:
            mock_resolver.return_value.resolve.return_value = answer
        return module.handler(query), mock_resolver


def _object(result, name):
    return next(obj for obj in result["results"]["Object"] if obj["name"] == name)


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def test_dns_emits_the_whole_rrset():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    result, _ = _run(dns_module, attribute, {"A": ["149.13.33.14", "149.13.33.4"]})
    values = _values(_object(result, "dns-record"))
    assert ("queried-domain", "circl.lu") in values
    assert ("a-record", "149.13.33.14") in values
    assert ("a-record", "149.13.33.4") in values


def test_dns_also_queries_aaaa():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    result, mock_resolver = _run(dns_module, attribute, {"A": ["149.13.33.14"], "AAAA": ["2001:db8::1"]})
    values = _values(_object(result, "dns-record"))
    assert ("a-record", "149.13.33.14") in values
    assert ("aaaa-record", "2001:db8::1") in values
    assert [call.args[1] for call in mock_resolver.return_value.resolve.call_args_list] == ["A", "AAAA"]


def test_dns_ipv6_only_name_is_not_an_error():
    attribute = {"type": "domain", "value": "v6.circl.lu", "uuid": UUID}
    result, _ = _run(dns_module, attribute, {"AAAA": ["2001:db8::1"]})
    values = _values(_object(result, "dns-record"))
    assert ("aaaa-record", "2001:db8::1") in values
    assert "a-record" not in {relation for relation, _ in values}


def test_dns_name_with_neither_record_returns_error():
    attribute = {"type": "domain", "value": "nothing.circl.lu", "uuid": UUID}
    result, _ = _run(dns_module, attribute, {})
    assert result["error"].startswith("No A or AAAA record")


def test_dns_references_the_input_attribute():
    attribute = {"type": "domain", "value": "circl.lu", "uuid": UUID}
    result, _ = _run(dns_module, attribute, {"A": ["149.13.33.14"]})
    references = _object(result, "dns-record")["ObjectReference"]
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in references] == [(UUID, "related-to")]


def test_dns_composite_queries_the_domain():
    attribute = {"type": "domain|ip", "value": "circl.lu|149.13.33.14", "uuid": UUID}
    result, mock_resolver = _run(dns_module, attribute, {"A": ["149.13.33.14"]})
    assert mock_resolver.return_value.resolve.call_args.args[0] == "circl.lu"
    assert ("queried-domain", "circl.lu") in _values(_object(result, "dns-record"))


def test_dns_nxdomain_returns_error():
    attribute = {"type": "domain", "value": "nope.invalid", "uuid": UUID}
    query = json.dumps({"module": "dns", "attribute": attribute, "config": {}})
    with patch.object(dns_module.dns.resolver, "Resolver") as mock_resolver:
        mock_resolver.return_value.resolve.side_effect = dns_module.dns.resolver.NXDOMAIN
        result = dns_module.handler(query)
    assert result["error"] == "NXDOMAIN"


def test_reversedns_emits_ptr_records():
    attribute = {"type": "ip-src", "value": "8.8.8.8", "uuid": UUID}
    result, _ = _run(reversedns, attribute, ["dns.google."])
    values = _values(_object(result, "dns-record"))
    assert ("queried-domain", "8.8.8.8.in-addr.arpa") in values
    assert ("ptr-record", "dns.google") in values


def test_reversedns_rejects_a_non_ip():
    attribute = {"type": "domain|ip", "value": "circl.lu|not-an-ip", "uuid": UUID}
    result, _ = _run(reversedns, attribute, ["dns.google."])
    assert "error" in result


def test_wrong_attribute_type_returns_error():
    attribute = {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "uuid": UUID}
    result, _ = _run(dns_module, attribute, {"A": ["149.13.33.14"]})
    assert "error" in result


def test_introspection_and_version():
    for module in (dns_module, reversedns):
        assert module.introspection() == module.mispattributes
        assert module.mispattributes["format"] == "misp_standard"
        assert "config" in module.version()
