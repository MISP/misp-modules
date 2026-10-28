"""Import DMARC aggregate reports without network lookups."""

import base64
import binascii
import gzip
import ipaddress
import json
import zipfile
import zlib
from datetime import datetime, timezone
from io import BytesIO
from xml.etree import ElementTree

from pymisp import MISPEvent, MISPObject

misperrors = {"error": "Error"}
mispattributes = {
    "inputSource": ["file", "paste"],
    "output": ["MISP objects"],
    "format": "misp_standard",
}
moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "description": "Import DMARC aggregate XML reports, including gzip and ZIP files.",
    "module-type": ["import"],
    "name": "DMARC Import",
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Upload an aggregate XML report (.xml, .xml.gz, or a ZIP containing exactly one XML file), or paste XML."
        " Creates an annotation object with report metadata, published policy and the original XML attachment. Each"
        " aggregate record becomes a linked domain-ip object with its source IP (ip-src), header-from domain, reporting"
        " interval and a JSON text attribute preserving counts, disposition, SPF/DKIM results, identifiers and"
        " extension fields. Additional identifier and authentication domains are included for correlation. All"
        " attributes have to_ids disabled: DMARC observations do not by themselves identify malicious senders. No API"
        " key or network access is needed. Input and decompressed XML are limited to 20 MiB each, with at most 10,000"
        " records and 32 XML nesting levels. DTDs, encrypted or multi-file ZIPs, nested archives and forensic/failure"
        " reports (RUF/ARF) are not supported. Invalid records reject the entire import."
    ),
    "references": [
        "https://www.rfc-editor.org/rfc/rfc7489.html",
        "https://github.com/MISP/misp-modules/issues/508",
    ],
    "input": "DMARC aggregate XML, optionally gzip- or ZIP-compressed",
    "output": "MISP annotation and domain-ip objects with report context and authentication results",
}

MAX_REPORT_SIZE = 20 * 1024 * 1024
MAX_RECORDS = 10_000


class _ReportTreeBuilder(ElementTree.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.depth = 0

    def start(self, tag, attrs):
        self.depth += 1
        if self.depth > 32:
            raise ValueError("XML nesting exceeds the 32-level limit.")
        return super().start(tag, attrs)

    def end(self, tag):
        self.depth -= 1
        return super().end(tag)

    def doctype(self, name, pubid, system):
        # Reject declarations through the XML parser, including UTF-16 input.
        raise ValueError("DTDs and entity declarations are not supported.")


def _read_limited(stream):
    data = stream.read(MAX_REPORT_SIZE + 1)
    if len(data) > MAX_REPORT_SIZE:
        raise ValueError("Report exceeds the 20 MiB size limit.")
    return data


def _unpack(data):
    if data.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=BytesIO(data)) as stream:
            return _read_limited(stream)
    if data.startswith(b"PK"):
        with zipfile.ZipFile(BytesIO(data)) as archive:
            files = [entry for entry in archive.infolist() if not entry.is_dir()]
            if len(files) != 1 or not files[0].filename.lower().endswith(".xml"):
                raise ValueError("ZIP must contain exactly one XML file.")
            entry = files[0]
            if entry.flag_bits & 1:
                raise ValueError("Encrypted ZIP files are not supported.")
            if entry.file_size > MAX_REPORT_SIZE:
                raise ValueError("Report exceeds the 20 MiB size limit.")
            # Never extract uploaded paths to the filesystem.
            with archive.open(entry) as stream:
                return _read_limited(stream)
    return data


def _fields(element, namespace, skip_records=False):
    """Keep repeated elements grouped so DKIM signatures and override reasons stay associated."""
    fields = {}
    for child in element:
        name = child.tag.removeprefix(namespace)
        if skip_records and name == "record":
            continue
        value = _fields(child, namespace) if len(child) else (child.text or "").strip()
        fields.setdefault(name, []).append(value)
    return fields


def _parse_report(data):
    root = ElementTree.fromstring(data, parser=ElementTree.XMLParser(target=_ReportTreeBuilder()))
    if root.tag.rsplit("}", 1)[-1] != "feedback":
        raise ValueError("Expected a DMARC aggregate feedback report.")
    namespace = root.tag[: -len("feedback")]

    def text(node, path):
        value = node.findtext("/".join(namespace + part for part in path.split("/")), "").strip()
        if not value:
            raise ValueError(f"Missing DMARC field: {path}.")
        return value

    def integer(node, path, minimum):
        value = text(node, path)
        if not value.isascii() or not value.isdecimal() or int(value) < minimum:
            raise ValueError(f"Invalid DMARC integer: {path}.")
        return int(value)

    text(root, "report_metadata/org_name")
    text(root, "report_metadata/email")
    report_id = text(root, "report_metadata/report_id")
    domain = text(root, "policy_published/domain")
    if text(root, "policy_published/p") not in ("none", "quarantine", "reject"):
        raise ValueError("Invalid published DMARC policy.")
    begin = integer(root, "report_metadata/date_range/begin", 0)
    end = integer(root, "report_metadata/date_range/end", 0)
    if begin > end:
        raise ValueError("DMARC reporting interval ends before it begins.")
    first_seen = datetime.fromtimestamp(begin, timezone.utc)
    last_seen = datetime.fromtimestamp(end, timezone.utc)
    records = root.findall(namespace + "record")
    if not records or len(records) > MAX_RECORDS:
        raise ValueError("Expected between 1 and 10,000 DMARC records.")

    event = MISPEvent()
    report = MISPObject("annotation", standalone=False)
    report.comment = f"DMARC aggregate report {report_id} for {domain}"
    report.add_attribute("type", value="DMARC aggregate report", to_ids=False)
    report.add_attribute("text", value=json.dumps(_fields(root, namespace, skip_records=True), indent=2), to_ids=False)
    report.add_attribute("attachment", value="dmarc-report.xml", data=BytesIO(data), to_ids=False)
    event.add_object(report)

    for index, record in enumerate(records, 1):
        source = text(record, "row/source_ip")
        if "%" in source:
            raise ValueError(f"Invalid source IP in record {index}.")
        source = str(ipaddress.ip_address(source))
        integer(record, "row/count", 1)
        disposition = text(record, "row/policy_evaluated/disposition")
        # RFC 9990 adds "pass" alongside the legacy dispositions.
        if disposition not in ("none", "pass", "quarantine", "reject"):
            raise ValueError(f"Invalid disposition in record {index}.")
        for mechanism in ("dkim", "spf"):
            if text(record, f"row/policy_evaluated/{mechanism}") not in ("pass", "fail"):
                raise ValueError(f"Invalid {mechanism} policy result in record {index}.")

        observation = MISPObject("domain-ip", standalone=False)
        observation.comment = f"DMARC aggregate report {report_id}: record {index}; published domain {domain}"
        observation.add_attribute("ip", type="ip-src", value=source, to_ids=False)
        observation.add_attribute(
            "domain", value=text(record, "identifiers/header_from"), comment="DMARC header_from", to_ids=False
        )
        for path in (
            "identifiers/envelope_from",
            "identifiers/envelope_to",
            "auth_results/dkim/domain",
            "auth_results/spf/domain",
        ):
            query = "/".join(namespace + part for part in path.split("/"))
            values = dict.fromkeys(
                node.text.strip() for node in record.findall(query) if node.text and node.text.strip()
            )
            for value in values:
                observation.add_attribute("domain", value=value, comment=f"DMARC {path}", to_ids=False)
        observation.add_attribute("first-seen", value=first_seen, to_ids=False)
        observation.add_attribute("last-seen", value=last_seen, to_ids=False)
        observation.add_attribute("text", value=json.dumps(_fields(record, namespace), indent=2), to_ids=False)
        report.add_reference(observation.uuid, "contains", "Aggregate DMARC record")
        event.add_object(observation)
    return {"results": json.loads(event.to_json())}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("data"), str) or not request["data"]:
            raise ValueError("Expected base64-encoded DMARC report data.")
        if len(request["data"]) > 4 * ((MAX_REPORT_SIZE + 2) // 3):
            raise ValueError("Report exceeds the 20 MiB size limit.")
        data = base64.b64decode(request["data"], validate=True)
        if len(data) > MAX_REPORT_SIZE:
            raise ValueError("Report exceeds the 20 MiB size limit.")
        return _parse_report(_unpack(data))
    except (
        ValueError,
        TypeError,
        binascii.Error,
        ElementTree.ParseError,
        OSError,
        EOFError,
        OverflowError,
        zipfile.BadZipFile,
        NotImplementedError,
        LookupError,
        zlib.error,
    ) as error:
        return {"error": f"Unable to import DMARC report: {error}"}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
