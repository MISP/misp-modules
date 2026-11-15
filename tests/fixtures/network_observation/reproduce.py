"""Generate benign offline Zeek 9.0.1 / Suricata 8.0.8 fixtures in Docker.

Requires the pinned images below. Containers have no network and receive only
the synthetic PCAP, Zeek policy and local Suricata rule written by this script.
"""

import hashlib
import json
import os
import struct
import subprocess
from pathlib import Path

IMAGES = {
    "zeek": "zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0",
    "suricata": "jasonish/suricata@sha256:d5a3a1785299ab40918d465e54fedf8e3afeeedba76bb64b0cc74dbc20bda2c3",
}


def checksum(data):
    data += b"\x00" * (len(data) % 2)
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def packet(src, dst, sport, dport, payload=b"", seq=0, ack=0, flags=None):
    src, dst = bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))
    proto = 17 if flags is None else 6
    if flags is None:
        header = struct.pack("!HHHH", sport, dport, len(payload) + 8, 0)
        check_offset = 6
    else:
        header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 80, flags, 65535, 0, 0)
        check_offset = 16
    pseudo = src + dst + struct.pack("!BBH", 0, proto, len(header) + len(payload))
    check = checksum(pseudo + header + payload) or 65535
    header = header[:check_offset] + struct.pack("!H", check) + header[check_offset + 2 :]
    ip = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(header) + len(payload), 1, 16384, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return bytes.fromhex("0200000000020200000000010800") + ip + header + payload


def make_pcap(path):
    client, server = "192.0.2.1", "198.51.100.2"
    req = b"GET /misp-fixture HTTP/1.1\r\nHost: example.test\r\nUser-Agent: fixture-agent\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    packets = [
        packet(client, server, 12345, 80, seq=1, flags=2),
        packet(server, client, 80, 12345, seq=100, ack=2, flags=18),
        packet(client, server, 12345, 80, seq=2, ack=101, flags=16),
        packet(client, server, 12345, 80, req, seq=2, ack=101, flags=24),
        packet(server, client, 80, 12345, resp, seq=101, ack=2 + len(req), flags=24),
        packet(client, server, 12345, 80, seq=2 + len(req), ack=101 + len(resp), flags=17),
        packet(server, client, 80, 12345, seq=101 + len(resp), ack=3 + len(req), flags=17),
        packet(client, server, 12345, 80, seq=3 + len(req), ack=102 + len(resp), flags=16),
    ]
    question = b"\x07example\x04test\x00\x00\x01\x00\x01"
    dns = struct.pack("!HHHHHH", 0x1234, 256, 1, 0, 0, 0) + question
    answer = (
        struct.pack("!HHHHHH", 0x1234, 33152, 1, 1, 0, 0) + question + bytes.fromhex("c00c000100010000003c0004cb007107")
    )
    packets += [packet(client, "198.51.100.53", 53000, 53, dns), packet("198.51.100.53", client, 53, 53000, answer)]
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, data in enumerate(packets):
            stream.write(struct.pack("<IIII", 1791633600, 123456 + index * 10000, len(data), len(data)))
            stream.write(data)


def run_container(image, inputs, command, output):
    cid = subprocess.check_output(
        ["docker", "create", "--network", "none", "--entrypoint", "/bin/sh", image, "-c", command], text=True
    ).strip()
    try:
        subprocess.run(["docker", "cp", str(inputs), cid + ":/work"], check=True)
        subprocess.run(["docker", "start", "--attach", cid], check=True)
        state = json.loads(subprocess.check_output(["docker", "inspect", cid], text=True))[0]["State"]
        if state["ExitCode"]:
            raise RuntimeError(state)
        output.mkdir(parents=True, exist_ok=True)
        subprocess.run(["docker", "cp", cid + ":/work/.", str(output)], check=True)
    finally:
        subprocess.run(["docker", "rm", "-f", cid], check=True, stdout=subprocess.DEVNULL)


def main():
    root = Path(os.environ.get("NETWORK_FIXTURE_WORK", "/workspace/work/network-native"))
    inputs = root / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    make_pcap(inputs / "synthetic.pcap")
    (inputs / "fixture.zeek").write_text("""@load base/frameworks/notice
@load policy/protocols/conn/community-id-logging
module Fixture;
export { redef enum Notice::Type += { HTTP_Observed }; }
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    { NOTICE([$note=HTTP_Observed, $msg="Synthetic HTTP observation", $conn=c]); }
""")
    (inputs / "fixture.rules").write_text(
        'alert http any any -> any any (msg:"Synthetic MISP fixture HTTP observation"; flow:established,to_server;'
        ' http.uri; content:"/misp-fixture"; sid:1000001; rev:1;)\n'
    )
    fixture = Path(__file__).parent
    for format_ in ("json", "tsv"):
        output = root / ("zeek-" + format_)
        command = "cd /work && zeek -Cr synthetic.pcap fixture.zeek" + (
            " LogAscii::use_json=T" if format_ == "json" else ""
        )
        run_container(IMAGES["zeek"], inputs, command, output)
        for name in ("conn", "dns", "http", "notice"):
            (fixture / ("zeek-" + name + "." + ("jsonl" if format_ == "json" else "log"))).write_bytes(
                (output / (name + ".log")).read_bytes()
            )
    output = root / "suricata"
    command = (
        "cd /work && suricata -r synthetic.pcap -S fixture.rules -c /etc/suricata/suricata.yaml -l /work --runmode"
        " single --set outputs.1.eve-log.community-id=true --set sensor-name=fixture-sensor"
    )
    run_container(IMAGES["suricata"], inputs, command, output)
    (fixture / "suricata-eve.jsonl").write_bytes((output / "eve.json").read_bytes())
    manifest = {
        "zeek_version": "9.0.1",
        "suricata_version": "8.0.8",
        "capture_file": "/work/synthetic.pcap",
        "capture_sha256": hashlib.sha256((inputs / "synthetic.pcap").read_bytes()).hexdigest(),
        "images": IMAGES,
    }
    (fixture / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
