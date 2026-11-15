"""Capture and stream provenance through the real offline TShark pipeline."""

import base64
import gzip
import hashlib
import json
import struct

import pytest
from pymisp import MISPEvent

from misp_modules.modules.import_mod import pcap_import
from tests.test_pcap_import import _TCP, _dns_frames, _objects, _pcap, _pcapng, _relation, _request, fake_tshark, tshark


def _value(obj, relation):
    return _relation(obj, relation)[0]["value"]


def _http_streams(bodies):
    frames = []
    for index, body in enumerate(bodies):
        tcp = _TCP(80, source_port=49152 + index)
        tcp.send(b"GET /same.bin HTTP/1.1\r\nHost: example.test\r\n\r\n")
        response = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
        tcp.send(response + str(len(body)).encode() + b"\r\n\r\n" + body, server=True)
        frames.extend(tcp.frames)
    return frames


@pytest.mark.parametrize("container,format_", [(_pcap, "PCAP"), (_pcapng, "PCAPNG")])
@pytest.mark.parametrize("ipv6", [False, True])
def test_capture_hashes_metadata_and_udp_endpoints(tshark, container, format_, ipv6):
    raw = container(_dns_frames(ipv6) * 2)
    result = pcap_import.dict_handler({"data": base64.b64encode(raw).decode(), "filename": "evidence.capture"})
    metadata = _objects(result, "pcap-metadata")[0]
    assert _value(metadata, "file-name") == "evidence.capture"
    assert _value(metadata, "file-format") == format_
    assert int(_value(metadata, "file-size-in-bytes")) == len(raw)
    assert int(_value(metadata, "captured-packets")) == 4
    for algorithm in ("md5", "sha1", "sha256"):
        assert _value(metadata, "file-hash-" + algorithm) == hashlib.new(algorithm, raw).hexdigest()
    flow = _objects(result, "network-connection")[0]
    assert _value(flow, "layer4-protocol") == "UDP"
    assert _value(flow, "ip-src") == ("2001:db8::1" if ipv6 else "192.0.2.10")
    assert _value(flow, "ip-dst") == ("2001:db8::53" if ipv6 else "192.0.2.53")
    assert _value(flow, "layer3-protocol") == ("IPv6" if ipv6 else "IPv4")
    assert int(_value(flow, "src-port")) == 49153
    assert int(_value(flow, "dst-port")) == 53
    assert int(_value(flow, "src-packets-count")) == int(_value(flow, "dst-packets-count")) == 2
    assert all(a["to_ids"] is False for obj in (metadata, flow) for a in obj["Attribute"])
    packet_context = json.loads(flow["comment"])
    assert packet_context["transport"] == "udp"
    assert packet_context["stream_id"] == "0"
    assert [packet["frame_number"] for packet in packet_context["packets"]] == ["1", "2", "3", "4"]
    assert packet_context["packets"][0]["time_epoch"] == (
        "1700000000.000000000" if format_ == "PCAP" else "0.000000000"
    )
    assert any(ref["referenced_uuid"] == metadata["uuid"] for ref in flow["ObjectReference"])
    domain = next(a for a in result["results"]["Attribute"] if a["type"] == "domain")
    assert domain["first_seen"] == _value(flow, "first-packet-seen")
    assert domain["last_seen"] == _value(flow, "last-packet-seen")
    reference = next(ref for ref in flow["ObjectReference"] if ref["referenced_uuid"] == domain["uuid"])
    assert json.loads(reference["comment"])["frames"] == ["1", "2", "3", "4"]


def test_same_filename_in_two_streams_keeps_correct_content_sources(tshark):
    bodies = [b"first stream content", b"second stream content"]
    result = pcap_import.handler(_request(_pcap(_http_streams(bodies))))
    flows = {flow["uuid"]: json.loads(flow["comment"])["stream_id"] for flow in _objects(result, "network-connection")}
    assert len(flows) == 2
    files = _objects(result, "file")
    assert len(files) == 2
    for index, body in enumerate(bodies):
        obj = next(obj for obj in files if _value(obj, "sha256") == hashlib.sha256(body).hexdigest())
        references = [ref for ref in obj["ObjectReference"] if ref["referenced_uuid"] in flows]
        assert len(references) == 1
        assert flows[references[0]["referenced_uuid"]] == str(index)
        evidence = json.loads(references[0]["comment"])
        assert evidence["completion_frames"] == [str(5 * index + 5)]
    url = next(a for a in result["results"]["Attribute"] if a["type"] == "url")
    assert url["first_seen"] == "2023-11-14T22:13:23+00:00"
    # Some versions also expose the generated request URI on the response.
    assert url["last_seen"] in ("2023-11-14T22:13:28+00:00", "2023-11-14T22:13:29+00:00")
    for flow in _objects(result, "network-connection"):
        reference = next(ref for ref in flow["ObjectReference"] if ref["referenced_uuid"] == url["uuid"])
        observed_frames = set(json.loads(reference["comment"])["frames"])
        flow_frames = {packet["frame_number"] for packet in json.loads(flow["comment"])["packets"]}
        assert observed_frames and observed_frames <= flow_frames
    assert not result.get("warnings")


def test_identical_payloads_share_content_object_and_retain_all_source_streams(tshark):
    result = pcap_import.handler(_request(_pcap(_http_streams([b"identical", b"identical"]))))
    files = _objects(result, "file")
    assert len(files) == 1
    sources = {obj["uuid"] for obj in _objects(result, "network-connection")}
    assert {
        ref["referenced_uuid"] for ref in files[0]["ObjectReference"] if ref["referenced_uuid"] in sources
    } == sources
    assert len(_relation(files[0], "filename")) == 2  # Keep both exporter-generated filenames.
    assert all("first_seen" in attribute and "last_seen" in attribute for attribute in files[0]["Attribute"])
    observed = _relation(files[0], "sha256")[0]
    assert observed["first_seen"] == "2023-11-14T22:13:24+00:00"
    assert observed["last_seen"] == "2023-11-14T22:13:29+00:00"


def test_stream_identity_is_scoped_to_capture_hash(tshark):
    flows = []
    for body in (b"one", b"two"):
        result = pcap_import.handler(_request(_pcap(_http_streams([body]))))
        flow = _objects(result, "network-connection")[0]
        assert json.loads(flow["comment"])["stream_id"] == "0"
        flows.append(flow["uuid"])
    assert flows[0] != flows[1]


def test_nanosecond_packet_times_and_out_of_order_capture_intervals(tshark):
    raw = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    for frame, (seconds, nanos) in zip(_dns_frames(), [(1700000001, 999999999), (1700000000, 123456789)]):
        raw += struct.pack("<IIII", seconds, nanos, len(frame), len(frame)) + frame
    result = pcap_import.handler(_request(raw))
    metadata = _objects(result, "pcap-metadata")[0]
    assert _value(metadata, "first-packet-seen") == "2023-11-14T22:13:20.123456+00:00"
    assert _value(metadata, "last-packet-seen") == "2023-11-14T22:13:21.999999+00:00"
    packets = json.loads(_objects(result, "network-connection")[0]["comment"])["packets"]
    assert [packet["time_epoch"] for packet in packets] == ["1700000001.999999999", "1700000000.123456789"]


def test_no_timestamp_or_transport_does_not_invent_observation_context():
    event = MISPEvent()
    packet = {"_source": {"layers": {"frame.number": ["1"], "dns.qry.name": ["example.test"]}}}
    pcap_import._CaptureContext(event, _pcap([]), [packet])
    result = {"results": json.loads(event.to_json())}
    assert not _objects(result, "network-connection")
    attribute = result["results"]["Attribute"][0]
    assert "first_seen" not in attribute and "last_seen" not in attribute
    metadata = _objects(result, "pcap-metadata")[0]
    assert not _relation(metadata, "first-packet-seen")
    assert json.loads(_value(metadata, "text"))["unassigned_packets"] == [{"frame_number": "1", "time_epoch": None}]


def test_unmatched_export_keeps_capture_reference_without_guessing_a_stream(tmp_path):
    event = MISPEvent()
    packet = {
        "_source": {
            "layers": {
                "frame.number": ["1"],
                "frame.time_epoch": ["1700000000"],
                "tcp.stream": ["0"],
            }
        }
    }
    context = pcap_import._CaptureContext(event, _pcap([]), [packet])
    (tmp_path / "http").mkdir()
    (tmp_path / "http" / "unmatched").write_bytes(b"unmatched content")
    pcap_import._exported_objects(event, tmp_path, context)
    result = {"results": json.loads(event.to_json())}
    obj = _objects(result, "file")[0]
    assert {ref["referenced_uuid"] for ref in obj["ObjectReference"]} == {context.capture.uuid}
    assert "No unambiguous source stream" in context.warnings[0]


def test_metadata_budget_includes_both_tshark_passes(tmp_path, monkeypatch):
    monkeypatch.setattr(pcap_import, "MAX_OUTPUT_SIZE", 100)
    (tmp_path / "packets.json").write_bytes(b"x" * 60)
    report = tmp_path / "imf-packets.json"
    report.write_bytes(b"x" * 60)
    errors = tmp_path / "stderr.txt"
    errors.write_bytes(b"")
    with pytest.raises(ValueError, match="JSON metadata exceeds"):
        pcap_import._check_output_sizes(tmp_path, report, errors)


@pytest.mark.parametrize("encoding", ["gzip", "chunked"])
def test_decoded_http_payloads_keep_exact_stream_provenance(tshark, encoding):
    body = b"Decoded content from the stream.\x00\xff"
    tcp = _TCP(80)
    tcp.send(b"GET /download HTTP/1.1\r\nHost: example.test\r\n\r\n")
    if encoding == "gzip":
        payload = gzip.compress(body)
        headers = b"Content-Encoding: gzip\r\nContent-Length: " + str(len(payload)).encode()
    else:
        payload = b""
        for chunk in (body[:10], body[10:]):
            payload += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
        payload += b"0\r\n\r\n"
        headers = b"Transfer-Encoding: chunked"
    tcp.send(b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n\r\n" + payload, server=True)
    result = pcap_import.handler(_request(_pcap(tcp.frames)))
    obj = _objects(result, "file")[0]
    assert _value(obj, "sha256") == hashlib.sha256(body).hexdigest()
    flow = _objects(result, "network-connection")[0]
    assert any(ref["referenced_uuid"] == flow["uuid"] for ref in obj["ObjectReference"])
    assert not result.get("warnings")


def test_stream_id_without_timestamps_or_endpoints_is_retained_without_invalid_flow():
    event = MISPEvent()
    packet = {"_source": {"layers": {"frame.number": ["1"], "tcp.stream": ["0"]}}}
    pcap_import._CaptureContext(event, _pcap([]), [packet])
    result = {"results": json.loads(event.to_json())}
    assert not _objects(result, "network-connection")
    metadata = _objects(result, "pcap-metadata")[0]
    assert json.loads(_value(metadata, "text"))["unassigned_packets"][0]["streams"] == [
        {"transport": "tcp", "stream_id": "0"}
    ]


def test_smtp_metadata_pass_shares_timeout_and_cleanup(fake_tshark, monkeypatch):
    children = fake_tshark(
        "import time\nfrom pathlib import Path\nif not Path('started').exists():\n Path('started').touch();"
        " Path('imf').mkdir(); Path('imf/message.eml').write_bytes(b'From: a@example.org\\r\\n\\r\\n')\n"
        " time.sleep(0.08); print('[]')\nelse:\n while True: time.sleep(0.01)\n"
    )
    run = pcap_import._run_tshark
    timeouts = []

    def record_timeout(executable, capture, directory, timeout, **kwargs):
        timeouts.append(timeout)
        return run(executable, capture, directory, timeout, **kwargs)

    monkeypatch.setattr(pcap_import, "_run_tshark", record_timeout)
    result = pcap_import.handler(_request(_pcap([]), timeout=0.4))
    assert "timeout" in result["error"]
    assert len(children) == len(timeouts) == 2
    assert 0 < timeouts[1] < timeouts[0] - 0.08
    assert all(child.returncode is not None and not directory.exists() for child, directory in children)
