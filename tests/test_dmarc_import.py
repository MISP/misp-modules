import base64
import gzip
import json
import struct
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
from pymisp import MISPEvent

from misp_modules import is_valid_module
from misp_modules.modules.import_mod import dmarc_import

REPORT = (Path(__file__).parent / "dmarc_report.xml").read_bytes()


def _request(data):
    return json.dumps({"data": base64.b64encode(data).decode()})


def _zip(files):
    data = BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files:
            archive.writestr(name, content)
    return data.getvalue()


def _attributes(obj, relation):
    return [a for a in obj["Attribute"] if a["object_relation"] == relation]


def _values(obj, relation):
    return [a["value"] for a in _attributes(obj, relation)]


@pytest.mark.parametrize("container", [lambda x: x, gzip.compress, lambda x: _zip([("report.xml", x)])])
def test_aggregate_report(container):
    result = dmarc_import.handler(_request(container(REPORT)))
    assert "error" not in result
    report, ipv4, ipv6 = result["results"]["Object"]
    assert [o["name"] for o in (report, ipv4, ipv6)] == ["annotation", "domain-ip", "domain-ip"]
    assert base64.b64decode(_attributes(report, "attachment")[0]["data"]) == REPORT
    metadata = json.loads(_values(report, "text")[0])
    assert metadata["report_metadata"][0]["org_name"] == ["Example Receiver"]
    assert metadata["report_metadata"][0]["report_id"] == ["example-report-001"]
    assert metadata["report_metadata"][0]["error"] == ["Example diagnostic"]
    assert metadata["policy_published"][0]["domain"] == ["example.org"]
    assert metadata["policy_published"][0]["p"] == ["reject"]
    assert metadata["policy_published"][0]["pct"] == ["100"]
    assert "record" not in metadata
    assert _values(ipv4, "ip") == ["192.0.2.10"]
    assert _attributes(ipv4, "ip")[0]["type"] == "ip-src"
    assert _values(ipv6, "ip") == ["2001:db8::20"]
    assert {"example.org", "bounce.example.org", "recipient.example", "mailer.example"} == set(_values(ipv4, "domain"))
    assert _values(ipv4, "first-seen") == ["2024-01-01T00:00:00+00:00"]
    assert _values(ipv4, "last-seen") == ["2024-01-01T23:59:59+00:00"]
    record = json.loads(_values(ipv4, "text")[0])
    assert record["row"][0]["count"] == ["42"]
    policy = record["row"][0]["policy_evaluated"][0]
    assert policy["dkim"] == ["pass"]
    assert policy["spf"] == ["fail"]
    assert record["auth_results"][0]["spf"][0]["result"] == ["pass"]  # Distinct from alignment failure.
    assert [(d["domain"], d["selector"], d["result"]) for d in record["auth_results"][0]["dkim"]] == [
        (["example.org"], ["mail"], ["pass"]),
        (["mailer.example"], ["other"], ["fail"]),
    ]
    assert [r["type"] for r in policy["reason"]] == [["forwarded"], ["local_policy"]]
    assert json.loads(_values(ipv6, "text")[0])["row"][0]["policy_evaluated"][0]["disposition"] == ["reject"]
    assert {r["referenced_uuid"] for r in report["ObjectReference"]} == {ipv4["uuid"], ipv6["uuid"]}
    assert all(r["relationship_type"] == "contains" for r in report["ObjectReference"])
    assert all(a["to_ids"] is False for o in (report, ipv4, ipv6) for a in o["Attribute"])
    event = MISPEvent()
    event.from_dict(info="Existing event", **result["results"])
    assert len(event.objects) == 3
    assert all(obj._validate() for obj in event.objects)


@pytest.mark.parametrize("namespace", ["", ' xmlns="urn:ietf:params:xml:ns:dmarc-2.0"'])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_namespaces_and_xml_encodings(namespace, encoding):
    xml = (
        REPORT.decode()
        .replace("<feedback>", f"<feedback{namespace}>")
        .replace('encoding="UTF-8"', f'encoding="{encoding}"')
    )
    assert "results" in dmarc_import.handler(_request(xml.encode(encoding)))


@pytest.mark.parametrize("namespace", ["", ' xmlns="urn:ietf:params:xml:ns:dmarc-2.0"'])
def test_pass_disposition_under_enforcing_policy(namespace):
    xml = REPORT.replace(b"<disposition>none</disposition>", b"<disposition>pass</disposition>")
    xml = xml.replace(b"<feedback>", f"<feedback{namespace}>".encode())
    result = dmarc_import.handler(_request(xml))
    assert "error" not in result
    report, passing, rejected = result["results"]["Object"]
    assert json.loads(_values(report, "text")[0])["policy_published"][0]["p"] == ["reject"]
    assert json.loads(_values(passing, "text")[0])["row"][0]["policy_evaluated"][0]["disposition"] == ["pass"]
    assert json.loads(_values(rejected, "text")[0])["row"][0]["policy_evaluated"][0]["disposition"] == ["reject"]
    assert all(a["to_ids"] is False for obj in (report, passing, rejected) for a in obj["Attribute"])


def test_same_ip_with_different_results_keeps_separate_records():
    xml = REPORT.replace(b"2001:db8::20", b"192.0.2.10")
    objects = dmarc_import.handler(_request(xml))["results"]["Object"]
    assert len(objects) == 3
    assert _values(objects[1], "ip") == _values(objects[2], "ip")
    assert _values(objects[1], "text") != _values(objects[2], "text")


def test_preserves_extension_fields():
    xml = REPORT.replace(
        b"</record>", b'<extension xmlns="urn:example"><note>extra context</note></extension></record>', 1
    )
    objects = dmarc_import.handler(_request(xml))["results"]["Object"]
    assert json.loads(_values(objects[1], "text")[0])["{urn:example}extension"][0]["{urn:example}note"] == [
        "extra context"
    ]


def test_missing_dkim_selector_keeps_signatures_associated():
    xml = REPORT.replace(b"<selector>mail</selector>", b"")
    objects = dmarc_import.handler(_request(xml))["results"]["Object"]
    signatures = json.loads(_values(objects[1], "text")[0])["auth_results"][0]["dkim"]
    assert "selector" not in signatures[0]
    assert signatures[1]["selector"] == ["other"]
    assert signatures[1]["domain"] == ["mailer.example"]


def test_prefixed_namespace():
    from xml.etree import ElementTree

    root = ElementTree.fromstring(REPORT)
    for node in root.iter():
        node.tag = "{urn:example:dmarc}" + node.tag
    assert "results" in dmarc_import.handler(_request(ElementTree.tostring(root)))


def test_no_records():
    from xml.etree import ElementTree

    root = ElementTree.fromstring(REPORT)
    for record in root.findall("record"):
        root.remove(record)
    assert "error" in dmarc_import.handler(_request(ElementTree.tostring(root)))


def test_xml_depth_limit():
    xml = REPORT.replace(b"</feedback>", b"<extra>" * 40 + b"deep" + b"</extra>" * 40 + b"</feedback>")
    assert "nesting" in dmarc_import.handler(_request(xml))["error"]


def test_unsupported_encoding():
    xml = REPORT.replace(b"UTF-8", b"not-an-encoding")
    assert "error" in dmarc_import.handler(_request(xml))


@pytest.mark.parametrize(
    "old,new",
    [
        (b"192.0.2.10", b"invalid-ip"),
        (b"2001:db8::20", b"2001:db8::20%eth0"),
        (b"<count>42</count>", b"<count>-1</count>"),
        (b"<count>42</count>", b"<count>0</count>"),
        (b"<count>42</count>", b"<count>1.5</count>"),
        (b"<count>42</count>", b""),
        (b"<header_from>example.org</header_from>", b""),
        (b"<report_id>example-report-001</report_id>", b""),
        (b"<domain>example.org</domain>", b"<domain/>"),
        (b"<begin>1704067200</begin>", b"<begin>-1</begin>"),
        (b"<begin>1704067200</begin>", b"<begin>1704153600</begin>"),
        (b"<end>1704153599</end>", b"<end>99999999999999999999</end>"),
        (b"<p>reject</p>", b"<p>unknown</p>"),
        (b"<disposition>reject</disposition>", b"<disposition>unknown</disposition>"),
        (b"<spf>fail</spf>", b"<spf>softfail</spf>"),
    ],
)
def test_invalid_report_rejects_entire_import(old, new):
    result = dmarc_import.handler(_request(REPORT.replace(old, new)))
    assert "error" in result
    assert "results" not in result


@pytest.mark.parametrize(
    "query", ["{", "null", "[]", "{}", '{"data": null}', '{"data": 1}', '{"data": ""}', '{"data": "!!!"}']
)
def test_invalid_requests(query):
    assert "error" in dmarc_import.handler(query)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not xml",
        b"<feedback>",
        b"<unrelated/>",
        b"<feedback/>",
        b"\x1f\x8bgarbage",
        gzip.compress(REPORT)[:-8],
        b"PKgarbage",
        _zip([]),
        _zip([("a.xml", REPORT), ("b.xml", REPORT)]),
        _zip([("a.txt", REPORT)]),
        _zip([("a.xml", gzip.compress(REPORT))]),
    ],
)
def test_invalid_uploads(data):
    assert "error" in dmarc_import.handler(_request(data))


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
@pytest.mark.parametrize(
    "declaration",
    [
        "<!DOCTYPE feedback>",
        '<!DOCTYPE feedback SYSTEM "file:///etc/passwd">',
        '<!DOCTYPE feedback [<!ENTITY example "expanded entity">]>',
    ],
)
def test_rejects_dtds_and_entities(encoding, declaration):
    xml = REPORT.decode().split("\n", 1)[1]
    result = dmarc_import.handler(_request((declaration + xml).encode(encoding)))
    assert "DTDs" in result["error"]


def test_input_and_decompression_limits(monkeypatch):
    monkeypatch.setattr(dmarc_import, "MAX_REPORT_SIZE", len(REPORT) - 1)
    for data in (REPORT, gzip.compress(REPORT), _zip([("report.xml", REPORT)])):
        assert "size limit" in dmarc_import.handler(_request(data))["error"]


def test_record_limit(monkeypatch):
    monkeypatch.setattr(dmarc_import, "MAX_RECORDS", 1)
    assert "error" in dmarc_import.handler(_request(REPORT))


def test_encrypted_zip():
    data = bytearray(_zip([("report.xml", REPORT)]))
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        position = data.index(signature) + offset
        flags = struct.unpack_from("<H", data, position)[0]
        struct.pack_into("<H", data, position, flags | 1)
    assert "Encrypted" in dmarc_import.handler(_request(data))["error"]


def test_discovery():
    assert is_valid_module(Path(dmarc_import.__file__))
    assert dmarc_import.handler() is False
    assert dmarc_import.introspection()["format"] == "misp_standard"
    assert dmarc_import.introspection()["inputSource"] == ["file", "paste"]
    assert dmarc_import.version()["module-type"] == ["import"]
    assert dmarc_import.version()["config"] == []
