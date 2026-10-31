"""Import indicators and reassembled HTTP/SMTP objects from an offline capture."""

import base64
import binascii
import json
import math
import os
import shutil
import subprocess
import time
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from pymisp import MISPEvent
from pymisp.exceptions import PyMISPError
from pymisp.tools import FileObject

from . import email_import

misperrors = {"error": "Error"}
mispattributes = {"inputSource": ["file"], "output": ["MISP attributes", "MISP objects"], "format": "misp_standard"}
moduleconfig = ["timeout"]
moduleinfo = {
    "version": "1.0",
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
    ),
    "references": [
        "https://github.com/MISP/misp-modules/issues/397",
        "https://www.wireshark.org/docs/man-pages/tshark.html",
    ],
    "input": "Base64-encoded PCAP or PCAPNG file",
    "output": "MISP network attributes, file and email objects, including attachments and hashes",
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


def _run_tshark(executable, capture, directory, timeout):
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
        "--export-objects",
        f"http,{directory / 'http'}",
        "--export-objects",
        f"imf,{directory / 'imf'}",
        "-T",
        "json",
    ]
    for field in FIELD_TYPES:
        command.extend(["-e", field])
    # Avoid loading the service user's Wireshark profile, keys or personal plugins.
    environment = dict(os.environ, XDG_CONFIG_HOME=str(directory), WIRESHARK_CONFIG_DIR=str(directory))
    report = directory / "packets.json"
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
    if report.stat().st_size > MAX_OUTPUT_SIZE:
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


def _network_attributes(event, packets):
    seen = set()
    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        for field, attribute_type in FIELD_TYPES.items():
            values = layers.get(field, [])
            if isinstance(values, str):
                values = [values]
            for value in values:
                if not isinstance(value, str) or not value:
                    continue
                if attribute_type == "domain":
                    value = value.rstrip(".").lower()
                if not value or (attribute_type, value) in seen:
                    continue
                seen.add((attribute_type, value))
                event.add_attribute(attribute_type, value=value, to_ids=False, comment=f"Observed in PCAP ({field})")


def _exported_objects(event, directory):
    exports = []
    for protocol in ("http", "imf"):
        folder = directory / protocol
        if folder.exists():
            exports.extend(
                (protocol, path) for path in sorted(folder.iterdir()) if path.is_file() and not path.is_symlink()
            )
    if sum(path.stat().st_size for _, path in exports) > MAX_OUTPUT_SIZE:
        raise ValueError("The capture's exported files exceed the 100 MiB limit.")
    for protocol, path in exports:
        data = path.read_bytes()
        if protocol == "http":
            file_object = FileObject(pseudofile=BytesIO(data), filename=path.name, standalone=False)
            file_object.comment = "HTTP object reassembled from PCAP"
            event.add_object(file_object)
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
                continue
            for email_object in result["results"]["Object"]:
                event.add_object(**email_object)


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
            packets = _run_tshark(executable, capture, directory, timeout)
            event = MISPEvent()
            _network_attributes(event, packets)
            _exported_objects(event, directory)
            return {"results": json.loads(event.to_json())}
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
