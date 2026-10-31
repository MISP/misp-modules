import base64
import copy
import json
import os
import re
import shutil
import socket
import struct
import subprocess

import pytest
from pymisp import MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import zeek_intel_export as export

EVENT_UUID = "f1ef0409-c80a-4012-b401-b7d1050f4ed4"


def attribute(kind="domain", value="example.org", **metadata):
    return {"type": kind, "value": value, "to_ids": True, "uuid": "attribute-1", **metadata}


def event(attributes=None, objects=None, **metadata):
    return {"uuid": EVENT_UUID, "Attribute": attributes or [], "Object": objects or [], **metadata}


def run(data=None, **config):
    result = export.handler(json.dumps({"data": event([attribute()]) if data is None else data, "config": config}))
    assert "error" not in result, result
    return result


def decode_field(field):
    if field == b"-":
        return None
    return re.sub(rb"\\x([0-9a-fA-F]{2})", lambda match: bytes([int(match[1], 16)]), field).decode("utf-8")


def rows(result):
    lines = base64.b64decode(result["data"]).splitlines()
    assert lines[0] == b"#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url"
    assert all(len(line.split(b"\t")) == 5 for line in lines[1:])
    return [dict(zip(export.FIELDS, map(decode_field, line.split(b"\t")))) for line in lines[1:]]


@pytest.mark.parametrize(
    "kind,value,intel_type,indicator",
    [
        ("ip-src", "192.0.2.1", "ADDR", "192.0.2.1"),
        ("ip-dst", "2001:0DB8:0000::1", "ADDR", "2001:db8::1"),
        ("ip-dst", "::ffff:c000:201", "ADDR", "192.0.2.1"),
        ("ip-src", "::ffff:c000:200/120", "SUBNET", "192.0.2.0/24"),
        ("ip-src", "192.0.2.7/24", "SUBNET", "192.0.2.0/24"),
        ("ip-dst", "2001:db8:1::1/48", "SUBNET", "2001:db8:1::/48"),
        ("domain", "EXAMPLE.org.", "DOMAIN", "example.org"),
        ("hostname", "bücher.example", "DOMAIN", "xn--bcher-kva.example"),
        ("url", "HTTP://Example.org/Case?q=One#fragment", "URL", "example.org/case?q=one"),
        ("url", "https://example.org:8443/A?b=C", "URL", {"example.org:8443/a?b=c", "example.org:8443:8443/a?b=c"}),
        ("url", "https://example.org", "URL", {"example.org:443/", "example.org:443:443/"}),
        ("url", "http://example.org?x=1", "URL", "example.org/?x=1"),
        ("url", "http://[2001:db8::1]:8080/Path", "URL", {"[2001:db8::1]:8080/path", "[2001:db8::1]:8080:8080/path"}),
        *[(kind, "A" * length, "FILE_HASH", "a" * length) for kind, length in export.HASH_LENGTHS.items()],
        *[
            (f"filename|{kind}", "a|b.exe|" + "A" * length, "FILE_HASH", "a" * length)
            for kind, length in export.HASH_LENGTHS.items()
        ],
        ("malware-sample", "file.exe|" + "A" * 32, "FILE_HASH", "a" * 32),
        *[(kind, "User@EXAMPLE.org", "EMAIL", "user@example.org") for kind in export.EMAIL_TYPES],
        ("email-src", "person@bücher.example", "EMAIL", "person@xn--bcher-kva.example"),
        *[(kind, "MyFile.EXE", "FILE_NAME", "myfile.exe") for kind in export.FILENAME_TYPES],
        ("x509-fingerprint-sha1", "AB" * 20, "CERT_HASH", "ab" * 20),
        ("x509-fingerprint-sha1", ":".join(["AB"] * 20), "CERT_HASH", "ab" * 20),
        ("ssh-fingerprint", "AB" * 16, "PUBKEY_HASH", ":".join(["ab"] * 16)),
        ("ssh-fingerprint", "MD5:" + ":".join(["AB"] * 16), "PUBKEY_HASH", ":".join(["ab"] * 16)),
    ],
)
def test_supported_types_and_normalization(kind, value, intel_type, indicator):
    result = run(event([attribute(kind, value)]))
    expected = {indicator} if isinstance(indicator, str) else indicator
    output_rows = rows(result)
    assert {row["indicator"] for row in output_rows} == expected
    for row in output_rows:
        assert row["indicator_type"] == "Intel::" + intel_type
        assert row["meta.source"] == "misp-modules" and row["meta.url"] is None
        assert json.loads(row["meta.desc"])[0]["original_value"] == value
    assert result["summary"] == {"count": len(expected), "skipped": {}}


def test_domain_ip_emits_two_independent_indicators():
    result = run(event([attribute("domain|ip", "EXAMPLE.org|192.0.2.1")]))
    assert {(row["indicator_type"], row["indicator"]) for row in rows(result)} == {
        ("Intel::DOMAIN", "example.org"),
        ("Intel::ADDR", "192.0.2.1"),
    }
    assert all(json.loads(row["meta.desc"])[0]["misp_type"] == "domain|ip" for row in rows(result))


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://example.org/a%2Fb?x=%41+%2B", {"example.org/a/b?x=a++"}),
        ("http://example.org/a%252Fb", {"example.org/a%2fb"}),
        ("http://example.org/a%20b", {"example.org/a b"}),
        ("http://example.org/a%23b?x=%3F", {"example.org/a#b?x=?"}),
        ("http://example.org/a?", {"example.org/a?"}),
        ("http://example.org:8080/a", {"example.org:8080/a", "example.org:8080:8080/a"}),
        ("http://example.org:80/a", {"example.org/a", "example.org:80/a"}),
        ("https://example.org/a", {"example.org:443/a", "example.org:443:443/a"}),
        ("http://[2001:db8::1]:8080/a", {"[2001:db8::1]:8080/a", "[2001:db8::1]:8080:8080/a"}),
    ],
)
def test_url_keys_match_decoded_targets_and_host_header_port_forms(url, expected):
    result = run(event([attribute("url", url)]))
    assert {row["indicator"] for row in rows(result)} == expected
    assert all(json.loads(row["meta.desc"])[0]["original_value"] == url for row in rows(result))


@pytest.mark.parametrize(
    "target,expected",
    [
        ("/%FF%00%09%5C", b"example.org/\xff\x00\t\\"),
        ("/%%41", b"example.org/a"),
        ("/%u0041%u00FF", b"example.org/a\xff"),
        ("/%GG%a%", b"example.org/%gg%a%"),
        ("/jump?next=http%3A%2F%2Fother.example", b"/jump?next=http://other.example"),
    ],
)
def test_url_escape_decoding_preserves_native_bytes_without_injecting_rows(target, expected):
    result = run(event([attribute("url", "http://example.org" + target)]))
    raw = base64.b64decode(result["data"])
    assert len(raw.splitlines()) == 2
    fields = raw.splitlines()[1].split(b"\t")
    assert len(fields) == 5
    decoded = re.sub(rb"\\x([0-9a-fA-F]{2})", lambda match: bytes([int(match[1], 16)]), fields[0])
    assert decoded == expected
    # API provenance remains JSON-serializable even when the native key is not UTF-8.
    json.dumps(result, ensure_ascii=False).encode("utf-8")


def _http_trace(requests):
    """Build an offline Ethernet/IPv4/TCP trace without extra test dependencies."""
    trace = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def checksum(data):
        if len(data) % 2:
            data += b"\x00"
        total = sum(struct.unpack(f"!{len(data) // 2}H", data))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    index = 0

    def packet(source_port, port, seq, ack, flags, payload=b"", reply=False):
        nonlocal index
        source, destination = socket.inet_aton("192.0.2.1"), socket.inet_aton("198.51.100.1")
        if reply:
            source, destination = destination, source
            source_port, port = port, source_port
        tcp = struct.pack("!HHIIBBHHH", source_port, port, seq, ack, 5 << 4, flags, 65535, 0, 0)
        pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), index, 0, 64, 6, 0, source, destination
        )
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        ethernet = bytes.fromhex("00112233445566778899aabb0800")
        frame = ethernet + ip + tcp + payload
        trace.extend(struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame)) + frame)
        index += 1

    for connection, (port, host, target) in enumerate(requests):
        source_port = 40000 + connection
        request = f"GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii")
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        packet(source_port, port, 1000, 0, 0x02)
        packet(source_port, port, 2000, 1001, 0x12, reply=True)
        packet(source_port, port, 1001, 2001, 0x10)
        packet(source_port, port, 1001, 2001, 0x18, request)
        packet(source_port, port, 2001, 1001 + len(request), 0x18, response, reply=True)
        packet(source_port, port, 1001 + len(request), 2001 + len(response), 0x11)
        packet(source_port, port, 2001 + len(response), 1002 + len(request), 0x11, reply=True)
        packet(source_port, port, 1002 + len(request), 2002 + len(response), 0x10)
    return trace


def test_native_zeek_http_observer_matches_percent_encoding_and_nondefault_ports(tmp_path):
    zeek = os.getenv("ZEEK") or shutil.which("zeek")
    if not zeek:
        pytest.skip("Set ZEEK to exercise the native HTTP analyzer and Intel URL observer.")
    cases = [
        (80, "example.org", "/a%2Fb?x=%41+%2B", b"example.org/a/b?x=a++"),
        (80, "example.org", "/a%252Fb", b"example.org/a%2fb"),
        (80, "example.org", "/a%20b", b"example.org/a b"),
        (80, "example.org", "/a%23b?x=%3F", b"example.org/a#b?x=?"),
        (80, "example.org", "/a?", b"example.org/a?"),
        (8080, "example.org:8080", "/port", b"example.org:8080:8080/port"),
        (8080, "example.org", "/port", b"example.org:8080/port"),
        (80, "example.org:80", "/default", b"example.org:80/default"),
        (80, "example.org", "/default", b"example.org/default"),
    ]
    urls = [
        "http://example.org/a%2Fb?x=%41+%2B",
        "http://example.org/a%252Fb",
        "http://example.org/a%20b",
        "http://example.org/a%23b?x=%3F",
        "http://example.org/a?",
        "http://example.org:8080/port",
        "http://example.org:80/default",
    ]
    for target, expected in [
        ("/bytes%FF%00%09%5C", b"example.org/bytes\xff\x00\t\\"),
        ("/double%%41", b"example.org/doublea"),
        ("/legacy%u0041%u00FF", b"example.org/legacya\xff"),
        ("/bad%GG%a%", b"example.org/bad%gg%a%"),
        ("/jump?next=http%3A%2F%2Fother.example", b"/jump?next=http://other.example"),
    ]:
        urls.append("http://example.org" + target)
        cases.append((80, "example.org", target, expected))
    result = run(event([attribute("url", url, uuid=f"url-{index}") for index, url in enumerate(urls)]))
    (tmp_path / "feed.intel").write_bytes(base64.b64decode(result["data"]))
    (tmp_path / "http.pcap").write_bytes(_http_trace([(port, host, target) for port, host, target, _ in cases]))
    script = tmp_path / "http.zeek"
    script.write_text(r"""
@load base/frameworks/intel
@load frameworks/intel/seen
redef InputAscii::fail_on_invalid_lines = T;
redef InputAscii::fail_on_file_problem = T;
redef Intel::read_files = { "FEED_PATH" };
event zeek_init()
    {
    suspend_processing();
    }
event Input::end_of_data(name: string, source: string)
    {
    continue_processing();
    }
hook Intel::seen_policy(s: Intel::Seen, found: bool)
    {
    if ( s?$indicator_type && s$indicator_type == Intel::URL )
        print fmt("OBS %s %s", encode_base64(s$indicator), found);
    }
""".replace("FEED_PATH", str(tmp_path / "feed.intel")))
    process = subprocess.run(
        [zeek, "-r", str(tmp_path / "http.pcap"), str(script)], cwd=tmp_path, text=True, capture_output=True, timeout=40
    )
    assert process.returncode == 0, process.stdout + process.stderr
    observations = [line.split() for line in process.stdout.splitlines() if line.startswith("OBS ")]
    assert len(observations) == len(cases), process.stdout + process.stderr
    assert [base64.b64decode(parts[1]).lower() for parts in observations] == [expected for _, _, _, expected in cases]
    assert all(parts[2] == "T" for parts in observations), process.stdout


def test_ipv4_mapped_aliases_share_zeek_identity_and_keep_all_provenance():
    result = run(
        event(
            [
                attribute("ip-dst", "192.0.2.1"),
                attribute("ip-dst", "::ffff:c000:201", uuid="attribute-2"),
                attribute("ip-src", "192.0.2.0/24", uuid="attribute-3"),
                attribute("ip-src", "::ffff:c000:200/120", uuid="attribute-4"),
            ]
        )
    )
    assert result["summary"]["count"] == 2
    assert all(len(json.loads(row["meta.desc"])) == 2 for row in rows(result))


def test_standard_legacy_bare_objects_and_provenance_are_not_mutated():
    obj = {
        "uuid": "object-1",
        "name": "domain-ip",
        "Attribute": [attribute(uuid="object-attribute", object_relation="domain")],
    }
    standard = event([attribute()], [obj])
    legacy = {"Event": {"uuid": "event-2"}, "Attribute": [attribute(uuid="legacy-attribute")]}
    data = [{"Event": standard}, standard, legacy]
    before = copy.deepcopy(data)
    result = run(data)
    assert result["summary"]["count"] == 1
    refs = json.loads(rows(result)[0]["meta.desc"])
    assert len(refs) == 3 and any(
        ref.get("object") == "object-1" and ref["object_relation"] == "domain" for ref in refs
    )
    assert refs == result["sources"][0]["sources"] and before == data


@pytest.mark.parametrize(
    "template,relation,value",
    [
        ("file", "sha256", "a" * 64),
        ("domain-ip", "domain", "example.org"),
        ("x509", "x509-fingerprint-sha1", "a" * 40),
    ],
)
def test_existing_misp_object_templates_suffice(template, relation, value):
    obj = MISPObject(template, strict=True)
    obj.add_attribute(relation, value=value, to_ids=True)
    obj._validate()
    result = run(event(objects=[json.loads(obj.to_json())]))
    assert result["summary"]["count"] == 1
    assert result["sources"][0]["sources"][0]["object"] == obj.uuid


def test_case_insensitive_keys_aggregate_provenance_instead_of_overwriting_metadata():
    data = event(
        [
            attribute("filename", "File.EXE"),
            attribute("filename", "file.exe", uuid="attribute-2"),
            attribute("url", "http://example.org/Case", uuid="attribute-3"),
            attribute("url", "http://EXAMPLE.org/case#fragment", uuid="attribute-4"),
        ]
    )
    result = run(data)
    assert result["summary"]["count"] == 2
    assert all(len(json.loads(row["meta.desc"])) == 2 for row in rows(result))


def test_order_is_deterministic_across_event_and_attribute_order():
    first, second = event([attribute(), attribute("ip-dst", "192.0.2.1")]), event(
        [attribute(uuid="other")], uuid="event-2"
    )
    reversed_first = event(list(reversed(first["Attribute"])))
    assert run([first, second])["data"] == run([second, reversed_first])["data"]


@pytest.mark.parametrize(
    "value",
    [
        r"C:\Temp\literal\x09.exe",
        "#fields\tindicator\n#separator\x00file",
        "-",
        "(empty)",
        "файл.txt",
        "file\r\nname.exe",
        'quote"comma,name.exe',
    ],
)
def test_ascii_escaping_preserves_filenames_and_cannot_inject_rows_or_headers(value):
    result = run(event([attribute("filename", value)]), source="source\\literal\ttab\nnewline")
    raw = base64.b64decode(result["data"])
    raw.decode("ascii")
    assert len(raw.splitlines()) == 2 and b"\x00" not in raw
    row = rows(result)[0]
    assert row["indicator"] == value.translate(export.ASCII_LOWER)
    assert row["meta.source"] == "source\\literal\ttab\nnewline"
    assert json.loads(row["meta.desc"])[0]["original_value"] == value


def test_source_sentinels_are_literal_strings_not_unset_values():
    for source in ["-", "(empty)", "#source", "源"]:
        assert rows(run(source=source))[0]["meta.source"] == source


def test_links_use_only_one_valid_event_identifier_and_allow_misp_subpaths():
    assert (
        rows(run(misp_url="https://misp.example/misp/"))[0]["meta.url"]
        == f"https://misp.example/misp/events/view/{EVENT_UUID}"
    )
    assert rows(run(event([attribute()], uuid=None, id="42"), misp_url="https://misp.example"))[0]["meta.url"].endswith(
        "/events/view/42"
    )
    for identifier in ["unknown", "../admin", "42?x=1", "//evil.example"]:
        assert rows(run(event([attribute()], uuid=identifier), misp_url="https://misp.example"))[0]["meta.url"] is None
    result = run([event([attribute()]), event([attribute()], uuid="event-2")], misp_url="https://misp.example")
    assert rows(result)[0]["meta.url"] is None


def test_free_text_metadata_and_samples_are_not_copied_into_feed():
    data = event(
        [attribute(comment="private-comment", data="private-sample", Tag=[{"name": "private-tag"}])],
        info="private-title",
    )
    raw = base64.b64decode(run(data)["data"])
    assert not any(value in raw for value in [b"private-comment", b"private-sample", b"private-tag", b"private-title"])


def test_deleted_and_context_attributes_are_excluded_even_with_override():
    data = [
        event(
            [
                attribute(to_ids="false"),
                attribute(deleted="1"),
                attribute("ip-dst|port", "192.0.2.1|443"),
            ],
            [{"deleted": "true", "Attribute": [attribute()]}],
        ),
        event([attribute()], deleted=True),
    ]
    result = run(data)
    assert rows(result) == []
    assert result["summary"]["skipped"] == {"deleted or non-IDS": 2, "unsupported": 1}
    assert len(rows(run(data, include_non_ids="true"))) == 1


@pytest.mark.parametrize(
    "kind,value",
    [
        ("domain", "bad..example"),
        ("domain", "example.org.."),
        ("domain", "a" * 64 + ".example"),
        ("domain", ".".join(["a" * 63] * 4)),
        ("domain", "wild*.example"),
        ("domain", "bad\ud800.example"),
        ("ip-dst", "999.1.2.3"),
        ("ip-src", "fe80::1%eth0"),
        ("ip-dst", "192.0.2.1/33"),
        ("ip-dst", "2001:db8::1/129"),
        ("url", "ftp://example.org/file"),
        ("url", "example.org/path"),
        ("url", "http://user:password@example.org/"),
        ("url", "http://example.org:bad/"),
        ("url", "http://example.org:65536/"),
        ("url", "http://example.org/a b"),
        ("url", "http://example.org/a\n"),
        ("email", "Display Name <person@example.org>"),
        ("email-src", "two@@example.org"),
        ("md5", "bad"),
        ("sha256", "g" * 64),
        ("filename|sha1", "file.exe|bad"),
        ("domain|ip", "example.org|not-ip"),
        ("domain|ip", "bad..example|192.0.2.1"),
        ("ssh-fingerprint", "SHA256:" + "A" * 43),
        ("x509-fingerprint-sha1", "ab::" * 20),
        ("filename", ""),
        ("filename", "\ud800"),
        ("domain", None),
    ],
)
def test_malformed_supported_values_are_counted_and_skipped(kind, value):
    result = run(event([attribute(kind, value)]))
    assert result["summary"] == {"count": 0, "skipped": {"malformed": 1}}
    assert rows(result) == [] and "warnings" in result


@pytest.mark.parametrize(
    "kind",
    [
        "ip-src|port",
        "ip-dst|port",
        "hostname|port",
        "ja3-fingerprint-md5",
        "user-agent",
        "x509-fingerprint-sha256",
        "imphash",
        "yara",
    ],
)
def test_unsupported_types_are_not_mapped_to_misleading_intel_types(kind):
    assert run(event([attribute(kind, "unmapped")]))["summary"]["skipped"] == {"unsupported": 1}


@pytest.mark.parametrize(
    "config",
    [
        [],
        {"source": []},
        {"source": False},
        {"source": " "},
        {"source": "a" * 129},
        {"source": "\ud800"},
        {"include_non_ids": "maybe"},
        {"include_non_ids": 2},
        {"misp_url": False},
        *[
            {"misp_url": url}
            for url in [
                "http://misp.example",
                "https://user:secret@misp.example",
                "https://@misp.example",
                "https://misp.example/?q=x",
                "https://misp.example/#x",
                "https://misp.example:bad",
                "https://misp.example\n",
            ]
        ],
    ],
)
def test_invalid_configuration_returns_error_without_file(config):
    result = export.handler(json.dumps({"data": [], "config": config}))
    assert "error" in result and "data" not in result


@pytest.mark.parametrize(
    "data", [None, "bad", [1], {"Event": "bad"}, {"Attribute": {}}, {"Object": [1]}, event([attribute(to_ids="maybe")])]
)
def test_invalid_input_returns_error(data):
    assert "error" in export.handler(json.dumps({"data": data}))


def test_empty_input_is_a_valid_header_only_feed_and_request_contract_is_stable():
    assert rows(run([])) == [] and run([])["summary"]["count"] == 0
    assert export.handler() is False
    for payload in ["invalid JSON", "[]", "null"]:
        assert "error" in export.handler(payload)
    assert export.introspection()["outputFileExtension"] == "intel"
    assert export.introspection()["responseType"] == "text/plain"
    assert export.version()["module-type"] == ["export"]


def test_native_zeek_loads_and_matches_exported_indicators(tmp_path):
    zeek = os.getenv("ZEEK") or shutil.which("zeek")
    if not zeek:
        pytest.skip("Set ZEEK to a Zeek executable to exercise the native reader and Intel matcher.")
    samples = [
        ("ip-dst", "192.0.2.1"),
        ("ip-src", "2001:db8::1"),
        ("ip-dst", "198.51.100.5/24"),
        ("domain", "EXAMPLE.org."),
        ("url", "http://example.org/Case?q=One#fragment"),
        ("email-src", "Person@example.org"),
        ("md5", "a" * 32),
        ("sha256", "b" * 64),
        ("filename", r"C:\Temp\Bad\x09.exe"),
        ("filename", "\t#fields\nmyfile.exe"),
        ("filename", "-"),
        ("filename", "(empty)"),
        ("filename", "файл.txt"),
        ("x509-fingerprint-sha1", "ab" * 20),
        ("ssh-fingerprint", "ab" * 16),
    ]
    source = "MISP\\literal\ttab\nnewline"
    result = run(
        event([attribute(kind, value, uuid=f"attribute-{index}") for index, (kind, value) in enumerate(samples)]),
        source=source,
    )
    expected = rows(result)
    feed = tmp_path / "feed.intel"
    feed.write_bytes(base64.b64decode(result["data"]))
    script = tmp_path / "check.zeek"
    script.write_text("""
@load base/frameworks/intel
@load frameworks/intel/seen
redef exit_only_after_terminate = T;
redef InputAscii::fail_on_invalid_lines = T;
redef InputAscii::fail_on_file_problem = T;
redef Intel::read_files = { "FEED_PATH" };
global matched: count = 0;
global loaded_file: file;
event zeek_init() &priority=10
    {
    loaded_file = open("loaded.jsonl");
    enable_raw_output(loaded_file);
    }
event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item) &priority=-5
    {
    print loaded_file, fmt("%s\\n", to_json(item));
    if ( item$indicator_type == Intel::ADDR )
        Intel::seen([$host=to_addr(item$indicator), $where=Intel::IN_ANYWHERE]);
    else if ( item$indicator_type == Intel::SUBNET )
        {
        local parts = split_string(item$indicator, /\\//);
        Intel::seen([$host=to_addr(parts[0]), $where=Intel::IN_ANYWHERE]);
        }
    else
        Intel::seen([$indicator=item$indicator, $indicator_type=item$indicator_type, $where=Intel::IN_ANYWHERE]);
    }
event Intel::match(s: Intel::Seen, items: set[Intel::Item])
    {
    ++matched;
    }
event Input::end_of_data(name: string, source: string)
    {
    terminate();
    }
event zeek_done()
    {
    close(loaded_file);
    print fmt("MATCHED %d", matched);
    }
""".replace("FEED_PATH", str(feed)))
    process = subprocess.run([zeek, "-b", str(script)], cwd=tmp_path, text=True, capture_output=True, timeout=40)
    assert process.returncode == 0, process.stdout + process.stderr
    assert "error" not in process.stderr.lower() and "warning" not in process.stderr.lower(), process.stderr
    loaded = [json.loads(line) for line in (tmp_path / "loaded.jsonl").read_text().splitlines()]
    assert len(loaded) == len(expected) == len(samples), repr(process.stdout)
    assert f"MATCHED {len(samples)}" in process.stdout
    for actual, wanted in zip(sorted(loaded, key=lambda item: (item["indicator_type"], item["indicator"])), expected):
        assert actual["indicator"] == wanted["indicator"] and actual["indicator_type"] == wanted["indicator_type"]
        assert actual["meta"]["source"] == source
        assert json.loads(actual["meta"]["desc"]) == json.loads(wanted["meta.desc"])


class TestZeekExportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"zeek_intel_export": export, "type:zeek_intel_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_query(self):
        descriptor = json.loads(self.fetch("/modules").body)[0]
        assert descriptor["name"] == "zeek_intel_export" and descriptor["type"] == "export_mod"
        result = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"module": "zeek_intel_export", "data": [event([attribute()])]}),
        )
        assert result.code == 200 and rows(json.loads(result.body))[0]["indicator_type"] == "Intel::DOMAIN"

    def test_percent_encoded_binary_url_has_a_valid_json_api_response(self):
        result = self.fetch(
            "/query",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(
                {"module": "zeek_intel_export", "data": event([attribute("url", "http://example.org/%ff%00")])}
            ),
        )
        assert result.code == 200
        body = json.loads(result.body)
        assert body["sources"][0]["indicator"] == "example.org/\\xff\x00"
        assert b"example.org/\\xff\\x00\tIntel::URL" in base64.b64decode(body["data"])
