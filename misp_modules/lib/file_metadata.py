"""Offline ExifTool extraction shared by the attachment expansion and file import."""

import base64
import hashlib
import json
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import date, time
from functools import lru_cache
from importlib import resources
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid5

from pymisp import MISPObject

EXIFTOOL_MINIMUM = (13, 0)
REQUIREMENTS = [
    "PyMISP",
    "ExifTool 13.00 or later on PATH",
    "Perl Archive::Zip for Office Open XML and OpenDocument metadata",
]
REFERENCES = ["https://exiftool.org/exiftool_pod.html", "https://exiftool.org/TagNames/"]
NAMESPACE = UUID("98d65b97-9ed9-42f0-b576-7194fb0dd41b")
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOOL_OUTPUT = 16 * 1024 * 1024
MAX_DIAGNOSTICS = 64 * 1024
TIMEOUT_SECONDS = 30
MAX_TAGS = 4096
MAX_TAG_BYTES = 32 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024

DATE_VALUE = re.compile(r"(?P<year>[0-9]{4})(?:[:-](?P<month>[0-9]{2})(?:[:-](?P<day>[0-9]{2}))?)?")
TIME_VALUE = re.compile(r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2})(?::(?P<second>[0-9]{2})(?P<fraction>\.[0-9]+)?)?")
OFFSET = re.compile(r"(?P<offset>Z|[+-](?:[01][0-9]|2[0-3]):?[0-5][0-9])$")
NAME_WORDS = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|[0-9]+")
LOCATION_WORDS = {"location", "latitude", "longitude", "altitude", "city", "country", "province", "sublocation"}
LOCATION_PREFIXES = (
    "gpscoordinates",
    "gpsposition",
    "location",
    "sublocation",
    "worldregion",
    "stateprovince",
    "countrycode",
    "geotag",
)
CONTROL_FILE_TAGS = {"File:Main:FileType", "File:Main:MIMEType"}
BINARY_PLACEHOLDER = re.compile(r"\(Binary data [0-9]+ bytes?(?:, use -b option to extract)?\)\Z")


def _json(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def _uuid(namespace, *parts):
    return str(uuid5(namespace, _json(parts)))


def _option(config, name):
    value = config.get(name)
    if isinstance(value, str):
        value = value.strip().lower()
        if value in ("true", "yes", "1"):
            return True
        if value in ("", "false", "no", "0"):
            return False
    if value is None or isinstance(value, bool):
        return bool(value)
    raise ValueError(f"{name} must be a boolean.")


def _upload(encoded, filename):
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_FILE_BYTES + 2) // 3):
        raise ValueError("Supply base64 file data of at most 64 MiB.")
    try:
        data = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ValueError("File data is not valid base64.") from error
    if not data or len(data) > MAX_FILE_BYTES:
        raise ValueError("File data must contain between 1 byte and 64 MiB.")
    if not isinstance(filename, str):
        raise ValueError("filename must be text.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if filename in ("", ".", "..") or len(filename) > 255 or not filename.isprintable():
        raise ValueError("Supply a printable filename of at most 255 characters.")
    return data, filename


def _read_bounded(process, stream, limit):
    data = bytearray()
    while chunk := stream.read1(65536):
        if len(data) + len(chunk) > limit:
            process.kill()
            raise ValueError("ExifTool exceeded its output limit.")
        data.extend(chunk)
    return bytes(data)


def _run_exiftool(command, directory):
    # Drain both pipes concurrently and stop the parser before accumulating unbounded output.
    with subprocess.Popen(
        command, cwd=directory, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        with ThreadPoolExecutor(max_workers=2) as readers:
            stdout = readers.submit(_read_bounded, process, process.stdout, MAX_TOOL_OUTPUT)
            stderr = readers.submit(_read_bounded, process, process.stderr, MAX_DIAGNOSTICS)
            try:
                status = process.wait(timeout=TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired as error:
                process.kill()
                raise ValueError("ExifTool exceeded its 30-second processing limit.") from error
            return status, stdout.result(), stderr.result()


def _extract(data, filename, scan_embedded):
    executable = shutil.which("exiftool")
    if not executable:
        raise ValueError("ExifTool 13.00 or later must be installed on the module service PATH.")
    # Keep a safe extension for extension-sensitive formats such as sidecars.
    suffix = Path(filename).suffix
    suffix = suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,16}", suffix) else ""
    with TemporaryDirectory(prefix="misp-file-metadata-") as directory:
        path = Path(directory) / f"upload{suffix}"
        path.write_bytes(data)
        command = [
            str(Path(executable).absolute()),
            "-config",
            "",
            "-q",
            "-j",
            "-n",
            "-struct",
            "-G0:1:3:4",
            "-api",
            "StructFormat=JSONQ",
            "-api",
            "QuickTimeUTC=0",
            "-e",
            "--System:all",
            "-all",
            "-ExifToolVersion",
        ]
        if scan_embedded:
            command.append("-ee3")
        status, stdout, stderr = _run_exiftool(command + [path.name], directory)

    try:
        records = json.loads(stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("ExifTool returned no usable metadata.") from error
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise ValueError("ExifTool returned an unexpected metadata response.")
    tags = records[0]
    version = tags.get("ExifTool:Main:ExifToolVersion")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+", version):
        raise ValueError("ExifTool did not report its version.")
    if tuple(map(int, version.split("."))) < EXIFTOOL_MINIMUM:
        raise ValueError("ExifTool 13.00 or later is required to preserve raw values in structured tags.")

    warnings = []
    for tag, value in tags.items():
        if tag.startswith("ExifTool:"):
            if tag.endswith(":Error"):
                raise ValueError(f"ExifTool could not read the supplied file. {str(value)[:1000]}")
            if tag.endswith(":Warning"):
                warnings.append(str(value)[:1000])
    if status:
        raise ValueError("ExifTool could not read the supplied file.")
    if stderr.strip():
        warnings.append("ExifTool emitted additional diagnostics on stderr.")
    return tags, version, warnings


def _timestamp(value, name):
    uncertainty = {"precision": "unknown", "timezone": "unspecified"}
    if not isinstance(value, str):
        return uncertainty

    text = value.strip()
    if name.startswith("subsectime"):
        if re.fullmatch(r"[0-9]+", text):
            uncertainty.update(precision="fractional-second", fractional_digits=len(text))
        return uncertainty
    if OFFSET.fullmatch(text):
        return {"precision": "offset-only", "timezone": "explicit", "offset": text}

    clock = text
    if "T" in text or " " in text:
        calendar, clock = re.split("[T ]", text, maxsplit=1)
        if not DATE_VALUE.fullmatch(calendar):
            return uncertainty
    else:
        calendar = text if DATE_VALUE.fullmatch(text) else ""
        if calendar:
            clock = ""

    if calendar:
        match = DATE_VALUE.fullmatch(calendar)
        year, month, day = match.group("year", "month", "day")
        try:
            date(int(year), int(month or 1), int(day or 1))
        except ValueError:
            return uncertainty
        uncertainty["precision"] = "day" if day else "month" if month else "year"
    if not clock:
        return uncertainty

    offset = OFFSET.search(clock)
    match = TIME_VALUE.fullmatch(clock[: offset.start()] if offset else clock)
    if not match:
        return uncertainty
    hour, minute, second, fraction = match.group("hour", "minute", "second", "fraction")
    try:
        time(int(hour), int(minute), int(second or 0))
    except ValueError:
        return uncertainty
    uncertainty["precision"] = "second" if second else "minute"
    if fraction:
        uncertainty.update(precision="fractional-second", fractional_digits=len(fraction) - 1)
    if offset:
        uncertainty.update(timezone="explicit", offset=offset["offset"])
    return uncertainty


def _tag_record(tag, value):
    name = tag.rsplit(":", 1)[-1]
    lower = name.lower()
    words = set(word.lower() for word in NAME_WORDS.findall(name))
    record = {"tag": tag, "value": value}
    if (
        "date" in words
        or lower.endswith(("timestamp", "datestamp"))
        or lower.startswith(("offsettime", "subsectime", "timezone", "timecode"))
        or lower in {
            "creationtime",
            "modificationtime",
            "lastprinted",
            "recordedtime",
            "recordingtime",
            "encodingtime",
            "taggingtime",
            "releasedtime",
            "digitalcreationtime",
            "timecreated",
            "year",
        }
    ):
        return "timestamp-claim", dict(record, verification="unverified", **_timestamp(value, lower))
    if (
        words & LOCATION_WORDS
        or lower.startswith(LOCATION_PREFIXES)
        or lower in {"gpsmapdatum", "gpstrack", "gpsimgdirection", "venue"}
    ):
        return "location-claim", dict(record, verification="unverified")
    return "metadata-tag", record


@lru_cache(maxsize=1)
def _template():
    return json.loads(
        resources.files("misp_modules").joinpath("data", "file-metadata", "definition.json").read_text(encoding="utf-8")
    )


def _add(obj, relation, value, *, key=None, **kwargs):
    attribute = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
    attribute.uuid = _uuid(UUID(obj.uuid), relation, key)


def _reference(obj, target):
    ref = obj.add_reference(target, "extracted-from")
    ref.uuid = _uuid(UUID(obj.uuid), "extracted-from", target)


def _result(data, filename, attachment_uuid, scan_embedded, include_original):
    tags, version, warnings = _extract(data, filename, scan_embedded)
    digest = hashlib.sha256(data).hexdigest()
    profile = "embedded" if scan_embedded else "standard"
    file_type = tags.get("File:Main:FileType")
    mime_type = tags.get("File:Main:MIMEType")
    source = MISPObject("file", strict=True, standalone=False)
    source.uuid = _uuid(NAMESPACE, "file", digest, filename, attachment_uuid)
    _add(source, "filename", filename)
    _add(source, "sha256", digest)
    _add(source, "size-in-bytes", len(data))
    if mime_type:
        _add(source, "mimetype", mime_type)
    if include_original:
        _add(source, "attachment", filename, data=BytesIO(data))

    metadata = MISPObject("file-metadata", strict=True, standalone=False, misp_objects_template_custom=_template())
    metadata.uuid = _uuid(NAMESPACE, "file-metadata", source.uuid, version, profile)
    _add(metadata, "parser", "ExifTool")
    _add(metadata, "parser-version", version)
    _add(metadata, "extraction-profile", profile)
    _add(metadata, "source-sha256", digest)
    if file_type:
        _add(metadata, "detected-format", file_type)
    _reference(metadata, source.uuid)
    if attachment_uuid:
        _reference(source, attachment_uuid)

    counts = {"metadata-tag": 0, "timestamp-claim": 0, "location-claim": 0}
    total_bytes = included = omitted = binary_tags = 0
    for tag, value in tags.items():
        family, _, name = tag.partition(":")
        if not name or family in {"ExifTool", "System", "Composite"} or tag in CONTROL_FILE_TAGS:
            continue
        if isinstance(value, str) and BINARY_PLACEHOLDER.fullmatch(value):
            binary_tags += 1
            continue
        relation, record = _tag_record(tag, value)
        serialized = _json(record)
        if (
            len(serialized) > MAX_TAG_BYTES
            or total_bytes + len(serialized) > MAX_METADATA_BYTES
            or included >= MAX_TAGS
        ):
            omitted += 1
            continue
        _add(metadata, relation, serialized, key=tag)
        counts[relation] += 1
        total_bytes += len(serialized)
        included += 1
    if omitted:
        _add(metadata, "omitted-tag-count", omitted)
        warnings.append(f"{omitted} metadata tags exceeded the result limits and were omitted.")
    if binary_tags:
        _add(metadata, "binary-tag-count", binary_tags)
    if not included:
        warnings.append("No selected textual or structured metadata was returned.")
    for index, warning in enumerate(warnings[:20]):
        _add(metadata, "warning", warning, key=index)

    return {
        "results": {"Object": [json.loads(obj.to_json(strict=True)) for obj in (source, metadata)]},
        "summary": {
            "source_sha256": digest,
            "format": file_type,
            "parser_version": version,
            "extraction_profile": profile,
            "metadata_tags": included,
            "timestamp_claims": counts["timestamp-claim"],
            "location_claims": counts["location-claim"],
            "omitted_tags": omitted,
            "binary_tags_skipped": binary_tags,
            "original_attached": include_original,
        },
        "warnings": warnings[:20],
    }


def run(q, *, expansion):
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected a JSON request object.")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        scan_embedded = _option(config, "scan_embedded")
        attachment_uuid = None
        if expansion:
            attribute = request.get("attribute")
            if not isinstance(attribute, dict) or attribute.get("type") != "attachment":
                raise ValueError("Expected an attachment attribute.")
            try:
                attachment_uuid = str(UUID(attribute.get("uuid", "")))
            except (AttributeError, TypeError, ValueError) as error:
                raise ValueError("The attachment requires a valid UUID.") from error
            data, filename = _upload(attribute.get("data", request.get("data")), attribute.get("value"))
            include_original = False
        else:
            filename = request.get("filename")
            data, filename = _upload(request.get("data"), "upload" if filename in (None, "") else filename)
            include_original = _option(config, "include_original")
        return _result(data, filename, attachment_uuid, scan_embedded, include_original)
    except (UnicodeError, json.JSONDecodeError, TypeError, RecursionError):
        return {"error": "Unable to decode the metadata request or parser output."}
    except OSError:
        return {"error": "Unable to execute ExifTool or read the supplied file."}
    except ValueError as error:
        return {"error": str(error)}
