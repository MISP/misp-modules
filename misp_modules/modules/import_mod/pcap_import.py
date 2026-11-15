"""Import indicators and reassembled HTTP/SMTP objects from an offline capture."""

import base64
import binascii
import hashlib
import json
import math
import os
import shutil
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import ROUND_FLOOR, Decimal, InvalidOperation
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import NAMESPACE_URL, UUID, uuid5

from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError
from pymisp.tools import FileObject

from . import email_import

misperrors = {"error": "Error"}
mispattributes = {"inputSource": ["file"], "output": ["MISP attributes", "MISP objects"], "format": "misp_standard"}
moduleconfig = ["timeout"]
moduleinfo = {
    "version": "1.1",
    "author": "MISP Project",
    "description": "Import a PCAP or PCAPNG capture, including reassembled files, emails and network indicators.",
    "module-type": ["import"],
    "name": "PCAP Import",
    "logo": "",
    "requirements": [
        "TShark >= 4.0 on the service user's PATH (Debian/Ubuntu: apt install tshark)",
        "PyMISP with email and fileobjects extras (included in misp-modules[all])",
    ],
    "features": (
        "Parses captures offline with TShark, without capture privileges or network lookups. Extracts IPv4/IPv6"
        " endpoints, DNS names and answers, HTTP URLs, hosts and user agents, and TLS SNI hostnames. Reassembles"
        " HTTP files and SMTP messages; reuses email_import for email objects, attachments and body URLs."
        " Requires complete, unencrypted application traffic for payload extraction; HTTPS yields visible TLS"
        " metadata only. Other file-transfer protocols and TLS decryption are not supported. Observed network"
        " attributes have to_ids disabled for analyst review. Captures are limited to 50 MiB, exported data and"
        " JSON metadata to 100 MiB each. timeout is a positive number of seconds, at most 300 (default 60)."
        " Output sizes, including diagnostics, are checked every 50 ms while TShark runs; exceeding a limit"
        " kills the process. Bursts can overshoot between checks; these checks are not filesystem quotas."
        " Adds capture hashes and pcap-metadata, capture-scoped TCP/UDP network-connection objects, packet"
        " timestamps and observation intervals. Reconstructed content links to streams by exact payload hashes;"
        " identical content retains all observed sources. SMTP provenance uses a targeted second pass within the"
        " same timeout and combined metadata limit. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/pcap_import.md)."
    ),
    "references": [
        "https://github.com/MISP/misp-modules/issues/397",
        "https://www.wireshark.org/docs/man-pages/tshark.html",
    ],
    "input": "Base64-encoded PCAP or PCAPNG file",
    "output": (
        "MISP network attributes, pcap-metadata, network-connection, file and email objects with capture/stream"
        " provenance"
    ),
}

MAX_CAPTURE_SIZE = 50 * 1024 * 1024
MAX_OUTPUT_SIZE = 100 * 1024 * 1024
OUTPUT_CHECK_INTERVAL = 0.05
CAPTURE_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}
FIELD_TYPES = {
    "ip.src": "ip-src",
    "ipv6.src": "ip-src",
    "ip.dst": "ip-dst",
    "ipv6.dst": "ip-dst",
    "dns.qry.name": "domain",
    "dns.resp.name": "domain",
    "dns.cname": "domain",
    "dns.a": "ip-dst",
    "dns.aaaa": "ip-dst",
    "dns.mx.mail_exchange": "domain",
    "dns.ns": "domain",
    "dns.ptr.domain_name": "domain",
    "http.request.full_uri": "url",
    "http.host": "hostname",
    "http.user_agent": "user-agent",
    "tls.handshake.extensions_server_name": "hostname",
}
CONTEXT_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "udp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "http.file_data",
    "smtp.req.command",
)


def _timeout(config):
    value = config.get("timeout")
    if value in (None, ""):
        return 60
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError):
        raise ValueError("timeout must be a positive finite number of seconds, at most 300.") from None
    if isinstance(value, bool) or not math.isfinite(number) or not 0 < number <= 300:
        raise ValueError("timeout must be a positive finite number of seconds, at most 300.")
    return number


def _uploaded_capture(request):
    encoded = request.get("data")
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("A base64-encoded PCAP or PCAPNG file is required in data.")
    if len(encoded) > 4 * ((MAX_CAPTURE_SIZE + 2) // 3):
        raise ValueError("The capture exceeds the 50 MiB limit.")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("data is not valid base64.") from None
    if len(data) > MAX_CAPTURE_SIZE:
        raise ValueError("The capture exceeds the 50 MiB limit.")
    if data[:4] not in CAPTURE_MAGICS:
        raise ValueError("The input is not a PCAP or PCAPNG capture.")
    return data


def _run_tshark(executable, capture, directory, timeout, *, imf_metadata=False):
    command = [
        executable,
        "-n",
        "-2",
        "-r",
        str(capture),
        "-o",
        "tcp.desegment_tcp_streams:TRUE",
        "-o",
        "tcp.reassemble_out_of_order:TRUE",
        "-o",
        "http.desegment_body:TRUE",
        "-o",
        "smtp.desegment_lines:TRUE",
        "-o",
        "smtp.desegment_data:TRUE",
    ]
    if imf_metadata:
        # Raw IMF TVBs are exactly the bytes used by the export-objects tap.
        # A targeted pass keeps compatibility with TShark 4.0, where -e cannot use @imf.
        command.extend(["-Y", "imf", "-T", "json", "-x", "-j", "frame imf", "--no-duplicate-keys"])
    else:
        command.extend(
            [
                "--export-objects",
                f"http,{directory / 'http'}",
                "--export-objects",
                f"imf,{directory / 'imf'}",
                "-T",
                "json",
            ]
        )
        for field in (*FIELD_TYPES, *CONTEXT_FIELDS):
            command.extend(["-e", field])
    # Avoid loading the service user's Wireshark profile, keys or personal plugins.
    environment = dict(os.environ, XDG_CONFIG_HOME=str(directory), WIRESHARK_CONFIG_DIR=str(directory))
    report = directory / ("imf-packets.json" if imf_metadata else "packets.json")
    errors_path = directory / "stderr.txt"
    with report.open("wb") as output, errors_path.open("wb") as errors:
        with subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            cwd=directory,
            env=environment,
        ) as process:
            deadline = time.monotonic() + timeout
            try:
                while True:
                    _check_output_sizes(directory, report, errors_path)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("TShark exceeded the configured timeout.")
                    try:
                        process.wait(timeout=min(OUTPUT_CHECK_INTERVAL, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        continue
                # Fast writers may finish between checks, so validate once more before reading any output.
                _check_output_sizes(directory, report, errors_path)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
    if process.returncode:
        raise ValueError("TShark could not read the capture. Check that it is complete and TShark >= 4.0 is installed.")
    try:
        packets = json.loads(report.read_bytes())
    except ValueError:
        raise ValueError("TShark returned invalid JSON metadata.") from None
    if not isinstance(packets, list):
        raise ValueError("TShark returned invalid packet metadata.")
    return packets


def _check_output_sizes(directory, report, errors):
    # Poll during extraction: a small compressed capture can expand to large files.
    # Writers may overshoot between checks; this is monitoring, not a filesystem quota.
    reports = {report, directory / "packets.json", directory / "imf-packets.json"}
    if sum(path.stat().st_size for path in reports if path.exists()) > MAX_OUTPUT_SIZE:
        raise ValueError("The capture's JSON metadata exceeds the 100 MiB limit.")
    if errors.stat().st_size > MAX_OUTPUT_SIZE:
        raise ValueError("TShark's diagnostic output exceeds the 100 MiB limit.")
    exported_size = 0
    for protocol in ("http", "imf"):
        folder = directory / protocol
        if not folder.exists():
            continue
        with os.scandir(folder) as entries:
            for entry in entries:
                if entry.is_file(follow_symlinks=False):
                    exported_size += entry.stat(follow_symlinks=False).st_size
                    if exported_size > MAX_OUTPUT_SIZE:
                        raise ValueError("The capture's exported files exceed the 100 MiB limit.")


def _values(layers, name):
    values = layers.get(name, [])
    if isinstance(values, str):
        values = [values]
    return [value for value in values if isinstance(value, str) and value]


def _one(layers, name):
    values = _values(layers, name)
    return values[0] if len(values) == 1 else None


def _instant(epoch):
    try:
        value = Decimal(epoch)
        if not value.is_finite():
            return None
        micros = int((value * 1000000).to_integral_value(rounding=ROUND_FLOOR))
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)
    except (InvalidOperation, ValueError, TypeError, OverflowError):
        return None


def _bounds(records):
    times = [Decimal(record["time_epoch"]) for record in records if _instant(record["time_epoch"]) is not None]
    if not times:
        return {}
    return {"first_seen": _instant(str(min(times))), "last_seen": _instant(str(max(times)))}


def _endpoint_pair(layers, transport):
    # Flat TShark fields do not preserve nesting order in tunneled packets.
    # Only assign endpoints when one address pair and one transport header are unambiguous.
    versions = [version for version in ("ip", "ipv6") if _values(layers, version + ".src")]
    if len(versions) != 1:
        return None
    fields = [versions[0] + ".src", transport + ".srcport", versions[0] + ".dst", transport + ".dstport"]
    values = tuple(_one(layers, name) for name in fields)
    return values if all(value is not None for value in values) else None


class _CaptureContext:
    """Capture-scoped streams, exact packet times, observables and payload identities."""

    def __init__(self, event, data, packets, filename=None):
        self.event = event
        self.digest = hashlib.sha256(data).hexdigest()
        self.capture = MISPObject("pcap-metadata", strict=True, standalone=False)
        self.capture.uuid = str(uuid5(NAMESPACE_URL, "misp-pcap:" + self.digest))
        self.event.add_object(self.capture)
        self.flows, self.frames, self.attributes = {}, {}, {}
        self.payloads = defaultdict(dict)
        self.warnings = []
        self.capture_records = []
        format_ = "PCAPNG" if data[:4] == b"\x0a\x0d\x0d\x0a" else "PCAP"
        for relation, value in {
            "file-format": format_,
            "file-name": filename if isinstance(filename, str) and filename else "capture." + format_.lower(),
            "file-size-in-bytes": len(data),
            "file-hash-md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
            "file-hash-sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
            "file-hash-sha256": self.digest,
            "captured-packets": len(packets),
        }.items():
            self.capture.add_attribute(relation, value=value, to_ids=False)
        for ordinal, packet in enumerate(packets, 1):
            self._packet(packet, ordinal)
        self._finish()

    def _packet(self, packet, ordinal):
        layers = packet.get("_source", {}).get("layers", {})
        number = _one(layers, "frame.number") or str(ordinal)
        record = {"frame_number": number, "time_epoch": _one(layers, "frame.time_epoch")}
        self.capture_records.append(record)
        keys = [(kind, value) for kind in ("tcp", "udp") for value in _values(layers, kind + ".stream")]
        key = keys[0] if len(keys) == 1 else None
        if key is not None and _instant(record["time_epoch"]) is None and _endpoint_pair(layers, key[0]) is None:
            key = None  # No valid standard network-connection can be built from this packet.
        if key is None and keys:
            record["streams"] = [{"transport": kind, "stream_id": value} for kind, value in keys]
        self.frames[number] = (key, record)
        if key is not None:
            transport, stream_id = key
            if key not in self.flows:
                obj = MISPObject("network-connection", strict=True, standalone=False)
                obj.uuid = str(uuid5(UUID(self.capture.uuid), f"{transport}.stream:{stream_id}"))
                obj.add_attribute("layer4-protocol", value=transport.upper(), to_ids=False)
                endpoints = _endpoint_pair(layers, transport)
                if endpoints is not None:
                    for relation, value in zip(("ip-src", "src-port", "ip-dst", "dst-port"), endpoints):
                        obj.add_attribute(relation, value=value, to_ids=False)
                    obj.add_attribute("layer3-protocol", value="IPv6" if ":" in endpoints[0] else "IPv4", to_ids=False)
                obj.add_reference(self.capture.uuid, "derived-from", "Source capture; stream IDs are capture-scoped.")
                self.capture.add_reference(obj.uuid, "contains", f"{transport}.stream={stream_id}")
                self.event.add_object(obj)
                self.flows[key] = {
                    "object": obj,
                    "endpoints": endpoints,
                    "records": [],
                    "observables": {},
                    "packets": [0, 0],
                    "protocols": set(),
                }
            flow = self.flows[key]
            flow["records"].append(record)
            endpoints = _endpoint_pair(layers, transport)
            if endpoints is not None and flow["endpoints"] is not None:
                if endpoints == flow["endpoints"]:
                    flow["packets"][0] += 1
                elif endpoints == flow["endpoints"][2:] + flow["endpoints"][:2]:
                    flow["packets"][1] += 1
            for protocol in ("http", "dns", "tls", "smtp"):
                if any(name.startswith(protocol + ".") for name in layers):
                    flow["protocols"].add(protocol.upper())

        for field, kind in FIELD_TYPES.items():
            for value in _values(layers, field):
                if kind == "domain":
                    value = value.rstrip(".").lower()
                if not value:
                    continue
                identity = (kind, value)
                if identity not in self.attributes:
                    attribute = self.event.add_attribute(kind, value=value, to_ids=False)
                    attribute.uuid = str(uuid5(UUID(self.capture.uuid), json.dumps(identity)))
                    self.attributes[identity] = {"attribute": attribute, "fields": set(), "records": {}}
                observation = self.attributes[identity]
                observation["fields"].add(field)
                observation["records"][number] = record
                if key is not None:
                    local = self.flows[key]["observables"].setdefault(identity, {"fields": set(), "frames": set()})
                    local["fields"].add(field)
                    local["frames"].add(number)
        for payload in _values(layers, "http.file_data"):
            self._payload("http", payload, number)

    def _payload(self, protocol, hexadecimal, number):
        try:
            data = bytes.fromhex(hexadecimal.replace(":", ""))
        except ValueError:
            self.warnings.append(f"Invalid {protocol} payload metadata in frame {number}; source link omitted.")
            return
        self.payloads[(protocol, hashlib.sha256(data).hexdigest())][number] = self.frames.get(number)

    def add_imf(self, packets):
        for packet in packets:
            layers = packet.get("_source", {}).get("layers", {})
            number = str(layers.get("frame", {}).get("frame.number", ""))
            raw = layers.get("imf_raw", [])
            # --no-duplicate-keys represents repeated IMF protocol nodes as a list of raw vectors.
            vectors = raw if raw and isinstance(raw[0], list) else [raw]
            for vector in vectors:
                if vector and isinstance(vector[0], str):
                    self._payload("imf", vector[0], number)

    def _finish(self):
        bounds = _bounds(self.capture_records)
        if bounds:
            self.capture.add_attribute("first-packet-seen", value=bounds["first_seen"], to_ids=False)
            self.capture.add_attribute("last-packet-seen", value=bounds["last_seen"], to_ids=False)
            self.capture.add_attribute(
                "elapsed-time",
                value=str(
                    max(Decimal(r["time_epoch"]) for r in self.capture_records if _instant(r["time_epoch"]) is not None)
                    - min(
                        Decimal(r["time_epoch"]) for r in self.capture_records if _instant(r["time_epoch"]) is not None
                    )
                ),
                to_ids=False,
            )
        unassigned = [record for key, record in self.frames.values() if key is None]
        self.capture.add_attribute(
            "text",
            value=json.dumps(
                {
                    "description": (
                        "Hashes identify exact uploaded bytes. Times are capture observations, not message dates."
                    ),
                    "unassigned_packets": unassigned,
                }
            ),
            to_ids=False,
        )
        for observation in self.attributes.values():
            attribute = observation["attribute"]
            for name, value in _bounds(observation["records"].values()).items():
                setattr(attribute, name, value)
            attribute.comment = "Observed in PCAP " + json.dumps(
                {
                    "capture_sha256": self.digest,
                    "fields": sorted(observation["fields"]),
                }
            )
            self.capture.add_reference(
                attribute.uuid,
                "contains",
                json.dumps(
                    {
                        "frames": list(observation["records"]),
                        "fields": sorted(observation["fields"]),
                    }
                ),
            )
        for (transport, stream_id), flow in self.flows.items():
            obj = flow["object"]
            obj.comment = json.dumps(
                {
                    "capture_sha256": self.digest,
                    "transport": transport,
                    "stream_id": stream_id,
                    "orientation": "First observed packet; not an assertion of client/server or connection initiation.",
                    "packets": flow["records"],
                    "unoriented_packets": len(flow["records"]) - sum(flow["packets"]),
                }
            )
            bounds = _bounds(flow["records"])
            if bounds:
                obj.add_attribute("first-packet-seen", value=bounds["first_seen"], to_ids=False)
                obj.add_attribute("last-packet-seen", value=bounds["last_seen"], to_ids=False)
            for relation, count in zip(("src-packets-count", "dst-packets-count"), flow["packets"]):
                obj.add_attribute(relation, value=count, to_ids=False)
            for protocol in sorted(flow["protocols"]):
                obj.add_attribute("layer7-protocol", value=protocol, to_ids=False)
            for attribute in obj.attributes:
                for name, value in bounds.items():
                    setattr(attribute, name, value)
            for identity, observation in flow["observables"].items():
                obj.add_reference(
                    self.attributes[identity]["attribute"].uuid,
                    "contains",
                    json.dumps(
                        {
                            "frames": sorted(observation["frames"], key=int),
                            "fields": sorted(observation["fields"]),
                        }
                    ),
                )

    def link_export(self, obj, protocol, data):
        digest = hashlib.sha256(data).hexdigest()
        matches = self.payloads.get((protocol, digest), {})
        obj.add_reference(self.capture.uuid, "derived-from", "Capture of reconstructed content.")
        by_flow = defaultdict(list)
        records = []
        for context in matches.values():
            if context is not None:
                key, record = context
                records.append(record)
                if key is not None:
                    by_flow[key].append(record["frame_number"])
        for key, frames in by_flow.items():
            obj.add_reference(
                self.flows[key]["object"].uuid,
                "derived-from",
                json.dumps(
                    {
                        "payload_sha256": digest,
                        "completion_frames": frames,
                        "basis": (
                            "Derived via an IMF message whose exact reconstructed bytes were observed on this stream."
                            if protocol == "imf"
                            else "Exact HTTP payload bytes observed on this stream."
                        ),
                    }
                ),
            )
        for attribute in obj.attributes:
            for name, value in _bounds(records).items():
                setattr(attribute, name, value)
        if not by_flow:
            self.warnings.append(
                f"No unambiguous source stream for {protocol} payload {digest}; capture reference retained."
            )


def _exported_objects(event, directory, context=None):
    exports = []
    for protocol in ("http", "imf"):
        folder = directory / protocol
        if folder.exists():
            exports.extend(
                (protocol, path) for path in sorted(folder.iterdir()) if path.is_file() and not path.is_symlink()
            )
    if sum(path.stat().st_size for _, path in exports) > MAX_OUTPUT_SIZE:
        raise ValueError("The capture's exported files exceed the 100 MiB limit.")
    seen = {}
    for protocol, path in exports:
        data = path.read_bytes()
        identity = (protocol, hashlib.sha256(data).hexdigest())
        if identity in seen:
            # An object represents exported content, possibly seen on multiple source streams.
            if protocol == "http" and path.name not in {
                attribute.value for attribute in seen[identity].get_attributes_by_relation("filename")
            }:
                original_name = seen[identity].get_attributes_by_relation("filename")[0]
                bounds = {
                    name: getattr(original_name, name)
                    for name in ("first_seen", "last_seen")
                    if getattr(original_name, name, None) is not None
                }
                seen[identity].add_attribute("filename", value=path.name, to_ids=False, **bounds)
            continue
        if protocol == "http":
            file_object = FileObject(pseudofile=BytesIO(data), filename=path.name, standalone=False)
            file_object.comment = "HTTP object reassembled from PCAP"
            event.add_object(file_object)
            seen[identity] = file_object
            if context is not None:
                context.link_export(file_object, protocol, data)
        else:
            try:
                result = email_import.dict_handler(
                    {
                        "data": base64.b64encode(data).decode("ascii"),
                        "config": {"extract_urls": "true"},
                    }
                )
            except (PyMISPError, ValueError, LookupError) as error:
                # Preserve malformed messages for review without losing the rest of the capture.
                file_object = FileObject(pseudofile=BytesIO(data), filename=path.name, standalone=False)
                file_object.comment = f"SMTP message reassembled from PCAP; email parsing failed: {error}"
                event.add_object(file_object)
                seen[identity] = file_object
                if context is not None:
                    context.link_export(file_object, protocol, data)
                continue
            for email_object in result["results"]["Object"]:
                obj = event.add_object(**email_object)
                if obj.name == "email":
                    obj.comment = "SMTP message reassembled from PCAP."
                seen.setdefault(identity, obj)
                if context is not None:
                    context.link_export(obj, protocol, data)


def dict_handler(request):
    try:
        if not isinstance(request, dict):
            raise ValueError("The request must be a JSON object.")
        data = _uploaded_capture(request)
        config = request.get("config") or {}
        if not isinstance(config, dict):
            raise ValueError("config must be a JSON object.")
        timeout = _timeout(config)
        executable = shutil.which("tshark")
        if executable is None:
            raise ValueError("TShark >= 4.0 is required. Install tshark on the misp-modules service user's PATH.")
        with TemporaryDirectory(prefix="misp-pcap-") as temporary:
            directory = Path(temporary)
            capture = directory / "capture.pcap"
            capture.write_bytes(data)
            deadline = time.monotonic() + timeout
            packets = _run_tshark(executable, capture, directory, timeout)
            event = MISPEvent()
            context = _CaptureContext(event, data, packets, request.get("filename"))
            if (directory / "imf").exists() and any((directory / "imf").iterdir()):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("TShark exceeded the configured timeout.")
                context.add_imf(_run_tshark(executable, capture, directory, remaining, imf_metadata=True))
            _exported_objects(event, directory, context)
            serialized = event.to_json()
            if len(serialized.encode("utf-8")) > MAX_OUTPUT_SIZE:
                raise ValueError("The capture's MISP metadata exceeds the 100 MiB limit.")
            result = {"results": json.loads(serialized)}
            if context.warnings:
                result["warnings"] = sorted(set(context.warnings))
            return result
    except (ValueError, OSError, PyMISPError) as error:
        return {"error": str(error)}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (ValueError, TypeError):
        return {"error": "The request must be valid JSON."}
    return dict_handler(request)


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
