import base64
import json
from pathlib import Path
from xml.sax.saxutils import escape

import pytest

from misp_modules.modules.import_mod import openiocimport

FIXTURES = Path(__file__).parent


def request(data, **kwargs):
    return json.dumps({"data": base64.b64encode(data).decode(), **kwargs})


def document(items, operator="OR"):
    return (
        f'<ioc><definition><Indicator operator="{operator}" id="root">{items}</Indicator></definition></ioc>'.encode()
    )


def item(path="FileItem/FileName", value="legacy.exe", condition="is", **attrs):
    attributes = " ".join(f'{key}="{value}"' for key, value in attrs.items())
    return (
        f'<IndicatorItem condition="{condition}" {attributes}>'
        f'<Context search="{path}"/><Content type="string">{escape(value)}</Content></IndicatorItem>'
    )


def attributes(data, **kwargs):
    result = openiocimport.handler(request(data, **kwargs))
    assert "error" not in result, result
    return result["results"]["Attribute"]


def observable(data, **kwargs):
    return [a for a in attributes(data, **kwargs) if a["type"] not in {"attachment", "comment"}]


def test_existing_openioc_10_fixture():
    source = (FIXTURES / "openioc.xml").read_bytes()
    result = openiocimport.handler(request(source, filename="stuxnet.ioc"))["results"]
    assert result["info"] == "STUXNET VIRUS (METHODOLOGY)"
    attrs = result["Attribute"]
    filenames = [a["value"] for a in attrs if a["type"] == "filename"]
    assert "mrxcls.sys" in filenames
    assert "mdmcpq3.PNF" in filenames
    # All 17 leaves survive, including repeated values in different groups.
    assert len([a for a in attrs if a.get("comment", "").startswith("OpenIOC:")]) == 17
    assert all(a["to_ids"] is False for a in attrs)
    assert "authored_date: 0001-01-01T00:00:00" in attrs[0]["value"]
    attachment = next(a for a in attrs if a["type"] == "attachment")
    assert attachment["value"] == "stuxnet.ioc"
    assert base64.b64decode(attachment["data"]) == source


def test_openioc_11_metadata_and_rule_provenance():
    source = (FIXTURES / "openioc_11.xml").read_bytes()
    result = openiocimport.handler(request(source))["results"]
    assert result["info"] == "Legacy OpenIOC 1.1 example"
    attrs = {a["value"]: a for a in result["Attribute"] if a["type"] != "attachment"}
    digest = attrs["d41d8cd98f00b204e9800998ecf8427e"]
    assert digest["type"] == "md5"
    assert digest["disable_correlation"] is False
    assert "id=hash" in digest["comment"]
    name = attrs["legacy.exe"]
    assert name["disable_correlation"] is True
    assert "logic=OR[root] > AND[group]" in name["comment"]
    assert "condition=contains" in name["comment"]
    assert "preserve-case=true" in name["comment"]
    assert "Only meaningful with the other group member." in name["comment"]
    host = attrs["trusted.example"]
    assert host["disable_correlation"] is True
    assert "negate=true" in host["comment"]
    unknown = attrs["^custom.*$"]
    assert unknown["type"] == "other"
    assert unknown["disable_correlation"] is True
    assert "CustomItem/Pattern" in unknown["comment"]


@pytest.mark.parametrize(
    "path,value,expected_type",
    [
        ("fileitem/filename", "legacy.exe", "filename"),
        ("FileItem/Sha1sum", "a" * 40, "sha1"),
        ("FileItem/Sha256sum", "b" * 64, "sha256"),
        ("PortItem/remoteIP", "192.0.2.1", "ip-dst"),
        ("PortItem/localIP", "2001:db8::1", "ip-src"),
        ("DnsEntryItem/Host", "example.test", "domain"),
        ("UrlHistoryItem/URL", "https://example.test/", "url"),
        ("Email/From", "sender@example.test", "email-src"),
        ("Email/To", "recipient@example.test", "email-dst"),
        ("RegistryItem/Path", "HKLM\\Software\\Example", "regkey"),
        ("ProcessItem/Mutex", "MutexName", "mutex"),
        ("ServiceItem/name", "LegacyService", "windows-service-name"),
        ("CustomItem/Unknown", "unmapped value", "other"),
    ],
)
def test_common_field_mappings(path, value, expected_type):
    attr = observable(document(item(path, value)))[0]
    assert (attr["type"], attr["value"]) == (expected_type, value)
    assert attr["to_ids"] is False


@pytest.mark.parametrize("condition", ["contains", "isnot", "matches", "greater-than", "unknown"])
def test_partial_negative_and_unsupported_conditions_do_not_correlate(condition):
    attr = observable(document(item(condition=condition)))[0]
    assert attr["disable_correlation"] is True
    assert f"condition={condition}" in attr["comment"]


def test_exact_and_terms_do_not_become_independent_correlations():
    attrs = observable(document(item() + item("FileItem/Md5sum", "a" * 32), operator="AND"))
    assert len(attrs) == 2
    assert all(a["disable_correlation"] for a in attrs)


def test_negated_exact_or_term_does_not_correlate():
    assert observable(document(item(negate="true")))[0]["disable_correlation"] is True


@pytest.mark.parametrize(
    "path,value",
    [("FileItem/Md5sum", "abc"), ("PortItem/remoteIP", "192.0.2.*"), ("PortItem/remotePort", ">80")],
)
def test_patterns_and_partial_values_survive_as_other(path, value):
    attr = observable(document(item(path, value, condition="contains")))[0]
    assert (attr["type"], attr["value"]) == ("other", value)
    assert attr["disable_correlation"] is True


def test_legacy_ipv4_with_port():
    attr = observable(document(item("PortItem/remoteIP", "192.0.2.1:443")))[0]
    assert (attr["type"], attr["value"]) == ("ip-dst|port", "192.0.2.1|443")


@pytest.mark.parametrize("condition", ["is", "contains", "matches"])
@pytest.mark.parametrize("path", ["DnsEntryItem/Host", "SystemInfoItem/HostName"])
def test_invalid_domain_and_hostname_strings_survive_as_other(path, condition):
    value = r"^.*example\.com$"
    attr = observable(document(item(path, value, condition=condition)))[0]
    assert (attr["type"], attr["value"]) == ("other", value)
    assert attr["disable_correlation"] is True
    assert f"condition={condition}" in attr["comment"]
    assert path in attr["comment"]


@pytest.mark.parametrize(
    "path,value",
    [
        ("DnsEntryItem/Host", "*.example.test"),
        ("SystemInfoItem/HostName", "host name.example.test"),
        ("Email/From", "partial-address"),
        ("Email/To", "@example"),
        ("ServiceItem/name", r"Legacy\Service"),
        ("ServiceItem/descriptiveName", "name/with/slashes"),
        ("ServiceItem/name", "x" * 257),
        ("ServiceItem/descriptiveName", "é" * 129),
    ],
)
def test_other_strict_mapped_strings_survive_as_other(path, value):
    attr = observable(document(item(path, value)))[0]
    assert (attr["type"], attr["value"]) == ("other", value)
    assert attr["disable_correlation"] is True


@pytest.mark.parametrize("port", ["0", "000", "65536", "-1", "١"])
@pytest.mark.parametrize("path", ["PortItem/remotePort", "PortItem/localPort", "PortItem/remoteIP"])
def test_invalid_ports_are_retained_as_other(path, port):
    value = "192.0.2.1:" + port if path.endswith("IP") else port
    attr = observable(document(item(path, value)))[0]
    assert (attr["type"], attr["value"]) == ("other", value)
    assert attr["disable_correlation"] is True


@pytest.mark.parametrize("port", ["1", "443", "65535"])
@pytest.mark.parametrize("path", ["PortItem/remotePort", "PortItem/localPort", "PortItem/remoteIP"])
def test_valid_ports_keep_their_misp_types(path, port):
    composite = path.endswith("IP")
    value = "192.0.2.1:" + port if composite else port
    attr = observable(document(item(path, value)))[0]
    assert attr["type"] == ("ip-dst|port" if composite else "port")
    assert attr["value"] == ("192.0.2.1|" + port if composite else port)
    assert attr["disable_correlation"] is False


def test_zero_remains_valid_for_file_size():
    attr = observable(document(item("FileItem/SizeInBytes", "0")))[0]
    assert (attr["type"], attr["value"]) == ("size-in-bytes", "0")


@pytest.mark.parametrize("enabled", [True, 1, "1", "true", "yes", "on"])
def test_attachment_can_be_disabled(enabled):
    attrs = attributes(document(item()), config={"not save ioc": enabled})
    assert all(a["type"] != "attachment" for a in attrs)


@pytest.mark.parametrize("disabled", [False, 0, "0", "false", None])
def test_attachment_retained_for_false_options(disabled):
    attrs = attributes(document(item()), config={"not save ioc": disabled})
    attachment = next(a for a in attrs if a["type"] == "attachment")
    assert attachment["value"] == "openioc.ioc"
    assert base64.b64decode(attachment["data"]) == document(item())


def test_default_tags_are_trimmed_and_applied_to_every_attribute():
    attrs = attributes(document(item()), config={"default tag": " tlp:clear, ,legacy, "})
    assert all({tag["name"] for tag in a["Tag"]} == {"tlp:clear", "legacy"} for a in attrs)


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "iso-8859-1"])
def test_xml_encoding_and_original_bytes_are_preserved(encoding):
    xml = (
        document(item(value="café.exe")).decode().replace("<ioc>", '<ioc xmlns="http://schemas.mandiant.com/2010/ioc">')
    )
    source = (f'<?xml version="1.0" encoding="{encoding.replace("-sig", "")}"?>' + xml).encode(encoding)
    attrs = attributes(source)
    assert any(a["value"] == "café.exe" for a in attrs)
    assert base64.b64decode(next(a["data"] for a in attrs if a["type"] == "attachment")) == source


def test_prefixed_namespaces_and_xml_escaping():
    xml = (
        '<o:ioc xmlns:o="http://schemas.mandiant.com/2010/ioc"><o:definition><o:Indicator operator="OR">'
        '<o:IndicatorItem condition="is"><o:Context search="ProcessItem/Mutex"/>'
        "<o:Content>A&amp;B</o:Content></o:IndicatorItem></o:Indicator></o:definition></o:ioc>"
    ).encode()
    assert observable(xml)[0]["value"] == "A&B"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
@pytest.mark.parametrize(
    "declaration",
    [
        '<!DOCTYPE ioc [<!ENTITY secret SYSTEM "file:///etc/passwd">]>',
        '<!DOCTYPE ioc [<!ENTITY secret "expanded">]>',
        '<!DOCTYPE ioc SYSTEM "https://example.test/external.dtd">',
    ],
)
def test_rejects_dtd_and_entities_including_utf16(encoding, declaration):
    source = f'<?xml version="1.0" encoding="{encoding}"?>{declaration}' + document(item()).decode()
    response = openiocimport.handler(request(source.encode(encoding)))
    assert "document type declarations" in response["error"]
    assert "results" not in response


@pytest.mark.parametrize(
    "source",
    [
        b"",
        b"not XML",
        b"<ioc>",
        b"<html/>",
        b'<ioc xmlns="urn:unrelated"/>',
        b"<ioc/>",
        b"<ioc><definition/></ioc>",
        document("<IndicatorItem><Content>x</Content></IndicatorItem>"),
        document('<IndicatorItem><Context search="FileItem/FileName"/></IndicatorItem>'),
        document(item(value="")),
    ],
)
def test_invalid_files_return_structured_errors(source):
    response = openiocimport.handler(request(source))
    assert "error" in response
    assert "results" not in response


@pytest.mark.parametrize(
    "query",
    ["not JSON", "null", "[]", "{}", '{"data":null}', '{"data":123}', '{"data":"%%%"}', '{"data":"é"}'],
)
def test_bad_requests_return_structured_errors(query):
    assert "error" in openiocimport.handler(query)


@pytest.mark.parametrize("kwargs", [{"config": [1]}, {"config": {"default tag": [1]}}, {"filename": 123}])
def test_invalid_options_return_structured_errors(kwargs):
    assert "error" in openiocimport.handler(request(document(item()), **kwargs))


def test_wrapped_base64_is_accepted():
    query = json.loads(request(document(item())))
    query["data"] = "\n".join(query["data"][i : i + 64] for i in range(0, len(query["data"]), 64))
    assert "results" in openiocimport.handler(json.dumps(query))


def test_introspection_and_version():
    assert openiocimport.handler() is False
    introspection = openiocimport.introspection()
    assert introspection["inputSource"] == ["file"]
    assert introspection["format"] == "misp_standard"
    assert {"not save ioc", "default tag"} <= introspection["userConfig"].keys()
    assert openiocimport.version()["module-type"] == ["import"]
