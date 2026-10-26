"""Small synthetic captures exercise the real dissector, without live traffic."""

import base64
import hashlib
import ipaddress
import json
import shutil
import struct
import subprocess
from email.message import EmailMessage

import pytest

from misp_modules.modules.import_mod import pcap_import


def _request(data, **config):
    return json.dumps({"data": base64.b64encode(data).decode(), "config": config})


def _checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535


def _frame(payload, protocol, source="192.0.2.10", destination="198.51.100.20"):
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    ethernet = bytes.fromhex("00112233445566778899aabb")
    if src.version == 6:
        header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), protocol, 64, src.packed, dst.packed)
        return ethernet + b"\x86\xdd" + header + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(payload) + 20, 0, 0, 64, protocol, 0, src.packed, dst.packed)
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return ethernet + b"\x08\x00" + header + payload


def _pcap(frames):
    output = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        output += struct.pack("<IIII", 1700000000 + i, 0, len(frame), len(frame)) + frame
    return output


def _pcapng(frames):
    def block(kind, body):
        body += b"\0" * (-len(body) % 4)
        size = len(body) + 12
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)

    output = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    output += block(1, struct.pack("<HHI", 1, 0, 65535))
    for i, frame in enumerate(frames):
        output += block(6, struct.pack("<IIIII", 0, 0, i * 1000000, len(frame), len(frame)) + frame)
    return output


class _TCP:
    def __init__(self, port):
        self.port = port
        self.sequences = [1000, 5000]
        self.frames = []
        self.send(b"", flags=2)
        self.send(b"", server=True, flags=18)
        self.send(b"", flags=16)

    def send(self, data, server=False, flags=24):
        side = int(server)
        source, destination = ("198.51.100.20", "192.0.2.10") if server else ("192.0.2.10", "198.51.100.20")
        ports = (self.port, 49152) if server else (49152, self.port)
        header = struct.pack(
            "!HHIIBBHHH", *ports, self.sequences[side], self.sequences[1 - side], 0x50, flags, 65535, 0, 0
        )
        pseudo = ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed
        checksum = _checksum(pseudo + struct.pack("!BBH", 0, 6, len(header) + len(data)) + header + data)
        header = header[:16] + struct.pack("!H", checksum) + header[18:]
        self.frames.append(_frame(header + data, 6, source, destination))
        self.sequences[side] += len(data) + bool(flags & 3)


def _dns_frames(ipv6=False):
    name = b"\x07example\x04test\0"
    query = struct.pack("!HHHHHH", 123, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    answer = struct.pack("!HHHHHH", 123, 0x8180, 1, 1, 0, 0) + query[12:]
    answer += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ipaddress.ip_address("203.0.113.42").packed
    addresses = ("2001:db8::1", "2001:db8::53") if ipv6 else ("192.0.2.10", "192.0.2.53")
    return [
        _frame(struct.pack("!HHHH", 49153, 53, len(query) + 8, 0) + query, 17, *addresses),
        _frame(struct.pack("!HHHH", 53, 49153, len(answer) + 8, 0) + answer, 17, *reversed(addresses)),
    ]


@pytest.fixture
def tshark():
    executable = shutil.which("tshark")
    if executable is None:
        pytest.skip("TShark is required for real capture integration tests")
    return executable


def _values(result, attribute_type):
    return [a["value"] for a in result["results"].get("Attribute", []) if a["type"] == attribute_type]


def _objects(result, name):
    return [obj for obj in result["results"].get("Object", []) if obj["name"] == name]


def _relation(obj, relation):
    return [a for a in obj["Attribute"] if a["object_relation"] == relation]


@pytest.mark.parametrize("container", [_pcap, _pcapng])
@pytest.mark.parametrize("ipv6", [False, True])
def test_dns_and_endpoints(tshark, container, ipv6):
    frames = _dns_frames(ipv6)
    result = pcap_import.handler(_request(container(frames + frames)))
    assert _values(result, "domain") == ["example.test"]
    assert "203.0.113.42" in _values(result, "ip-dst")
    assert ("2001:db8::1" if ipv6 else "192.0.2.10") in _values(result, "ip-src")
    assert all(a["to_ids"] is False for a in result["results"]["Attribute"])


@pytest.mark.parametrize("out_of_order", [False, True])
def test_http_file_reassembly(tshark, out_of_order):
    tcp = _TCP(80)
    tcp.send(b"GET /download.bin HTTP/1.1\r\nHost: example.test\r\nUser-Agent: CaptureTest/1\r\n\r\n")
    body = b"File from multiple TCP segments.\x00\xff"
    response = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
    response += str(len(body)).encode() + b"\r\n\r\n" + body
    tcp.send(response[:45], server=True)
    tcp.send(response[45:-8], server=True)
    tcp.send(response[-8:], server=True)
    if out_of_order:
        tcp.frames[-2], tcp.frames[-1] = tcp.frames[-1], tcp.frames[-2]
    # Include a retransmission to verify it does not duplicate the exported bytes.
    tcp.frames.append(tcp.frames[-1])
    result = pcap_import.handler(_request(_pcap(tcp.frames)))
    assert _values(result, "url") == ["http://example.test/download.bin"]
    assert _values(result, "user-agent") == ["CaptureTest/1"]
    files = _objects(result, "file")
    assert len(files) == 1
    assert _relation(files[0], "sha256")[0]["value"] == hashlib.sha256(body).hexdigest()
    assert base64.b64decode(_relation(files[0], "malware-sample")[0]["data"]) == body


def test_smtp_email_and_attachment_reassembly(tshark):
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "recipient@example.test"
    message["Subject"] = "PCAP email test"
    message.set_content("See <https://example.test/path?download=1&name=evidence%20file#sample>\n")
    attachment = b"An attachment recovered from SMTP."
    message.add_attachment(attachment, maintype="application", subtype="octet-stream", filename="evidence.bin")
    mail = message.as_bytes().replace(b"\n", b"\r\n")
    tcp = _TCP(25)
    tcp.send(b"220 mail.example.test ESMTP\r\n", server=True)
    tcp.send(b"EHLO example.test\r\n")
    tcp.send(b"250 mail.example.test\r\n", server=True)
    tcp.send(b"MAIL FROM:<sender@example.test>\r\n")
    tcp.send(b"250 OK\r\n", server=True)
    tcp.send(b"RCPT TO:<recipient@example.test>\r\n")
    tcp.send(b"250 OK\r\n", server=True)
    tcp.send(b"DATA\r\n")
    tcp.send(b"354 End data with <CR><LF>.<CR><LF>\r\n", server=True)
    tcp.send(mail[:100])
    tcp.send(mail[100:] + b"\r\n.\r\n")
    tcp.send(b"250 Accepted\r\n", server=True)
    result = pcap_import.handler(_request(_pcap(tcp.frames)))
    emails = _objects(result, "email")
    assert len(emails) == 1
    assert _relation(emails[0], "subject")[0]["value"] == "PCAP email test"
    assert _relation(emails[0], "from")[0]["value"] == "sender@example.test"
    files = _objects(result, "file")
    assert len(files) == 1
    assert _relation(files[0], "sha256")[0]["value"] == hashlib.sha256(attachment).hexdigest()
    assert any(ref["referenced_uuid"] == files[0]["uuid"] for ref in emails[0]["ObjectReference"])
    urls = _objects(result, "url")
    # URLObject normalises percent-encoded characters while retaining the path, query and fragment.
    assert _relation(urls[0], "url")[0]["value"] == "https://example.test/path?download=1&name=evidence file#sample"


def test_tls_sni_without_payload_decryption(tshark):
    hostname = b"secure.example.test"
    entry = b"\0" + struct.pack("!H", len(hostname)) + hostname
    sni = struct.pack("!H", len(entry)) + entry
    extensions = struct.pack("!HH", 0, len(sni)) + sni
    hello = b"\x03\x03" + bytes(32) + b"\0\0\x02\x00\x2f\x01\0" + struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    tcp = _TCP(443)
    tcp.send(b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake)
    result = pcap_import.handler(_request(_pcap(tcp.frames)))
    assert _values(result, "hostname") == ["secure.example.test"]
    assert _objects(result, "file") == []


@pytest.mark.parametrize("data", [None, "", "%%%", "dGVzdA==", 123])
def test_invalid_upload(data):
    assert "error" in pcap_import.dict_handler({"data": data})


@pytest.mark.parametrize("query", ["bad json", "null", "[]", "1"])
def test_invalid_request(query):
    assert "error" in pcap_import.handler(query)


@pytest.mark.parametrize("timeout", [-1, 0, "NaN", "inf", 301, True, [], "no"])
def test_invalid_timeout(timeout):
    assert "timeout" in pcap_import.handler(_request(_pcap([]), timeout=timeout))["error"]


def test_missing_tshark(monkeypatch):
    monkeypatch.setattr(pcap_import.shutil, "which", lambda _: None)
    assert "Install tshark" in pcap_import.handler(_request(_pcap([])))["error"]


def test_size_limit(monkeypatch):
    monkeypatch.setattr(pcap_import, "MAX_CAPTURE_SIZE", 10)
    assert "50 MiB" in pcap_import.handler(_request(_pcap([])))["error"]


def test_tshark_timeout_and_cleanup(monkeypatch):
    paths = []

    def run(command, **kwargs):
        paths.append(kwargs["cwd"])
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert "-n" in command and "-r" in command
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(pcap_import.shutil, "which", lambda _: "/usr/bin/tshark")
    monkeypatch.setattr(pcap_import.subprocess, "run", run)
    assert "timeout" in pcap_import.handler(_request(_pcap([])))["error"]
    assert paths and not paths[0].exists()


def test_truncated_capture(tshark):
    assert "error" in pcap_import.handler(_request(b"\xd4\xc3\xb2\xa1truncated"))


def test_empty_capture(tshark):
    result = pcap_import.handler(_request(_pcap([])))
    assert "results" in result
    assert not result["results"].get("Attribute")


def test_malformed_email_preserved_as_file(tmp_path):
    from pymisp import MISPEvent

    folder = tmp_path / "imf"
    folder.mkdir()
    data = b"Malformed message without any mail headers.\r\n"
    (folder / "message.eml").write_bytes(data)
    event = MISPEvent()
    pcap_import._exported_objects(event, tmp_path)
    files = _objects({"results": json.loads(event.to_json())}, "file")
    assert len(files) == 1
    assert "email parsing failed" in files[0]["comment"]
    assert base64.b64decode(_relation(files[0], "malware-sample")[0]["data"]) == data


def test_export_size_limit(tmp_path, monkeypatch):
    from pymisp import MISPEvent

    folder = tmp_path / "http"
    folder.mkdir()
    (folder / "download").write_bytes(b"1234567890")
    monkeypatch.setattr(pcap_import, "MAX_OUTPUT_SIZE", 5)
    with pytest.raises(ValueError, match="exported files"):
        pcap_import._exported_objects(MISPEvent(), tmp_path)


def test_metadata():
    assert pcap_import.handler() is False
    assert pcap_import.introspection()["format"] == "misp_standard"
    assert pcap_import.version()["module-type"] == ["import"]
