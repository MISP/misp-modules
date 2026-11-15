"""Import selected Autopsy rows and explicit normalized mobile-forensic artifacts."""

import base64
import binascii
import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from io import BytesIO, StringIO
from uuid import UUID, uuid5

from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

mispattributes = {"inputSource": ["file"], "output": ["MISP objects"], "format": "misp_standard"}
moduleconfig = [
    "format",
    "artifact_type",
    "rows",
    "case_id",
    "data_source_id",
    "device_id",
    "evidence_id",
    "report_id",
    "tool_version",
    "timezone",
]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Autopsy and Mobile Forensic Selected Results Import",
    "description": (
        "Import selected browser, download, communication and application artifacts with forensic provenance."
    ),
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Accepts Autopsy Export Selected Rows to CSV and a versioned selected-results JSON interchange for mobile"
        " parsers. Reuses tsk-web-history/bookmark/cookie/search-query/downloads, tsk-chats and software objects."
        " Preserves selected raw rows, report hashes and case/device/source identifiers in forensic-artifact objects."
        " Explicit row selection omits the full source attachment when rows are excluded. All attributes are"
        " unreviewed, non-IDS and non-correlating. Local timestamps need an explicit report offset; paths and URLs"
        " are never opened. Commercial native reports require sample fixtures and a named maintainer before an"
        " adapter is added. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/autopsy_import.md)."
    ),
    "references": [
        "https://www.autopsy.com/",
        "https://github.com/sleuthkit/autopsy/blob/develop/Core/src/org/sleuthkit/autopsy/directorytree/ExportCSVAction.java",
    ],
    "input": "Base64 UTF-8 Autopsy selected-row CSV or misp-forensic-selected version 1 JSON.",
    "output": "Source report, forensic-artifact provenance and linked tsk-* or software observations.",
}
MAX_INPUT = 20 * 1024 * 1024
MAX_ROWS = 1000
MAX_ROW = 64 * 1024
MAX_OUTPUT = 100 * 1024 * 1024
NAMESPACE = UUID("7233cd50-2276-4554-8b77-6e38265b0b15")
CONTEXT = ("case_id", "data_source_id", "data_source", "device_id", "evidence_id", "report_id")
# English display labels from Sleuth Kit BlackboardAttribute Bundle.properties.
LABELS = {
    "TSK_URL": "URL",
    "TSK_DATETIME": "Date/Time",
    "TSK_DATETIME_ACCESSED": "Date Accessed",
    "TSK_DATETIME_CREATED": "Date Created",
    "TSK_DATETIME_SENT": "Date Sent",
    "TSK_DATETIME_RCVD": "Date Received",
    "TSK_NAME": "Name",
    "TSK_PROG_NAME": "Program Name",
    "TSK_TITLE": "Title",
    "TSK_DOMAIN": "Domain",
    "TSK_REFERRER": "Referrer URL",
    "TSK_VALUE": "Value",
    "TSK_PATH": "Path",
    "TSK_PATH_ID": "Path ID",
    "TSK_TEXT": "Text",
    "TSK_MESSAGE_TYPE": "Message Type",
    "TSK_SUBJECT": "Subject",
    "TSK_PHONE_NUMBER_FROM": "From Phone Number",
    "TSK_PHONE_NUMBER_TO": "To Phone Number",
    "TSK_EMAIL_FROM": "E-Mail From",
    "TSK_EMAIL_TO": "E-Mail To",
    "TSK_EMAIL_CONTENT_PLAIN": "Message (Plaintext)",
    "TSK_VERSION": "Version",
    "TSK_ORGANIZATION": "Organization",
    "TSK_USER_NAME": "Username",
}
PROFILES = {
    "TSK_WEB_HISTORY": (
        "tsk-web-history",
        {
            "TSK_URL": "URL",
            "TSK_TITLE": "title",
            "TSK_DOMAIN": "domain-name",
            "TSK_PROG_NAME": "browser",
            "TSK_REFERRER": "referrer",
        },
        {"TSK_DATETIME_ACCESSED": "datetime-accessed"},
    ),
    "TSK_WEB_BOOKMARK": (
        "tsk-web-bookmark",
        {
            "TSK_URL": "URL",
            "TSK_NAME": "name",
            "TSK_TITLE": "title",
            "TSK_DOMAIN": "domain-name",
            "TSK_PROG_NAME": "browser",
        },
        {"TSK_DATETIME_CREATED": "datetime-bookmarked"},
    ),
    "TSK_WEB_COOKIE": (
        "tsk-web-cookie",
        {
            "TSK_URL": "URL",
            "TSK_NAME": "name",
            "TSK_VALUE": "value",
            "TSK_DOMAIN": "domain-name",
            "TSK_PROG_NAME": "browser",
        },
        {"TSK_DATETIME_CREATED": "datetime-created"},
    ),
    "TSK_WEB_SEARCH_QUERY": (
        "tsk-web-search-query",
        {
            "TSK_DOMAIN": "domain",
            "TSK_TEXT": "text",
            "TSK_PROG_NAME": "browser",
            "TSK_USER_NAME": "username",
        },
        {"TSK_DATETIME_ACCESSED": "datetime-searched"},
    ),
    "TSK_WEB_DOWNLOAD": (
        "tsk-web-downloads",
        {
            "TSK_URL": "url",
            "TSK_NAME": "name",
            "TSK_PATH": "path-downloadedTo",
            "TSK_PATH_ID": "pathID",
        },
        {"TSK_DATETIME_ACCESSED": "datetime-accessed"},
    ),
    "TSK_MESSAGE": (
        "tsk-chats",
        {
            "TSK_TEXT": "message",
            "TSK_MESSAGE_TYPE": "message-type",
            "TSK_SUBJECT": "subject",
            "TSK_PROG_NAME": "app-used",
            "TSK_PHONE_NUMBER_FROM": "Source",
            "TSK_PHONE_NUMBER_TO": "destination",
        },
        {"TSK_DATETIME_SENT": "datetime-sent", "TSK_DATETIME_RCVD": "datetime-received"},
    ),
    "TSK_EMAIL_MSG": (
        "tsk-chats",
        {
            "TSK_EMAIL_CONTENT_PLAIN": "message",
            "TSK_SUBJECT": "subject",
            "TSK_EMAIL_FROM": "Source",
            "TSK_EMAIL_TO": "destination",
        },
        {"TSK_DATETIME_SENT": "datetime-sent", "TSK_DATETIME_RCVD": "datetime-received"},
    ),
    "TSK_INSTALLED_PROG": (
        "software",
        {
            "TSK_PROG_NAME": "name",
            "TSK_VERSION": "version",
        },
        {},
    ),
}


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Non-finite JSON number: " + value)


def _bounded(value):
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > 32:
            raise ValueError("Record/context nesting exceeds 32 levels.")
        if isinstance(item, dict):
            for key in item:
                key.encode("utf-8")
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            item.encode("utf-8")
    if len(_json(value).encode()) > MAX_ROW:
        raise ValueError("A record/context exceeds the 64 KiB limit.")


def _text(value, field):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not str(value).strip():
        raise ValueError(field + " must be non-empty text or an integer identifier.")
    value = str(value)
    if len(value) > 4096 or any(ord(char) < 32 for char in value):
        raise ValueError(field + " contains control characters or exceeds 4096 characters.")
    return value


def _offset(value):
    if value in (None, ""):
        return None
    if value in ("UTC", "Z"):
        return timezone.utc
    if not isinstance(value, str) or not re.fullmatch(r"[+-](?:[01]\d|2[0-3]):[0-5]\d", value) or value == "-00:00":
        raise ValueError("timezone must be UTC or a known numeric offset such as +01:00.")
    minutes = int(value[1:3]) * 60 + int(value[4:])
    return timezone(timedelta(minutes=minutes if value[0] == "+" else -minutes))


def _time(value, canonical, offset):
    if isinstance(value, bool):
        raise ValueError("Boolean timestamp.")
    if canonical and (isinstance(value, int) or isinstance(value, str) and re.fullmatch(r"-?\d+", value)):
        # TSK DATETIME attributes explicitly use Unix seconds, never milliseconds.
        if int(value) == 0:
            raise ValueError("Zero is the Sleuth Kit unknown-time sentinel.")
        return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=int(value))).isoformat()
    if not isinstance(value, str):
        raise ValueError("Timestamp needs explicit units and timezone.")
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)"
        r"(Z|[+-]\d{2}:?\d{2}| (?:UTC|GMT)(?:[+-]\d{2}:\d{2})?| [A-Za-z_/-]+)?",
        value,
    )
    if not match:
        raise ValueError("Unsupported timestamp representation/precision.")
    date, zone = match.groups()
    if zone == "-00:00" or zone == "-0000":
        raise ValueError("Unknown timezone offset.")
    if zone in ("Z", " UTC", " GMT"):
        tz = timezone.utc
    elif zone and zone.startswith((" UTC", " GMT")):
        tz = _offset(zone[4:])
    elif zone and zone[0] in "+-":
        tz = _offset(zone if ":" in zone else zone[:3] + ":" + zone[3:])
    else:
        tz = offset
    if tz is None:
        raise ValueError("Local/abbreviated timestamp requires an explicit report timezone offset.")
    return datetime.fromisoformat(date).replace(tzinfo=tz).astimezone(timezone.utc).isoformat()


def _selection(value, count):
    if value in (None, ""):
        return set(range(1, count + 1))
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list) or not value or len(value) > MAX_ROWS:
        raise ValueError("rows must be a non-empty list or comma-separated one-based row numbers.")
    selected = set()
    for number in value:
        if (
            isinstance(number, bool)
            or not isinstance(number, (int, str))
            or not re.fullmatch(r"[1-9]\d*", str(number).strip())
        ):
            raise ValueError("rows must contain positive one-based integers.")
        selected.add(int(str(number).strip()))
    if not selected <= set(range(1, count + 1)):
        raise ValueError("Selected row numbers are outside this export.")
    return selected


def _json_rows(text):
    """Recover exact row text after validation, retaining lexical numeric precision."""
    decoder = json.JSONDecoder()
    position = text.index("{") + 1

    def whitespace(index):
        while index < len(text) and text[index] in " \t\r\n":
            index += 1
        return index

    while True:
        position = whitespace(position)
        if text[position] == ",":
            position = whitespace(position + 1)
        key, position = decoder.raw_decode(text, position)
        position = whitespace(whitespace(position) + 1)  # The validated colon.
        if key != "artifacts":
            _, position = decoder.raw_decode(text, position)
            continue
        position = whitespace(position + 1)  # The validated artifact array.
        rows = []
        while text[position] != "]":
            start = position
            _, position = decoder.raw_decode(text, position)
            rows.append(text[start:position])
            position = whitespace(position)
            if text[position] == ",":
                position = whitespace(position + 1)
        return rows


def _read(raw, config):
    text = raw.decode("utf-8-sig")
    format_ = config.get("format")
    if format_ is None or format_ == "":
        format_ = "auto"
    if format_ == "auto":
        format_ = "selected-json" if text.lstrip().startswith(("{", "[")) else "autopsy-csv"
    if format_ not in ("autopsy-csv", "selected-json"):
        raise ValueError("format must be auto, autopsy-csv or selected-json.")
    if format_ == "selected-json":
        document = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
        if (
            not isinstance(document, dict)
            or document.get("format") != "misp-forensic-selected"
            or type(document.get("version")) is not int
            or document["version"] != 1
            or set(document) - {"format", "version", "producer", "context", "artifacts"}
        ):
            raise ValueError(
                "JSON must use the documented misp-forensic-selected version 1 contract; native commercial reports are"
                " unsupported."
            )
        producer = document.get("producer")
        if not isinstance(producer, dict):
            raise ValueError("producer must contain an explicit tool/parser name.")
        _text(producer.get("name"), "producer.name")
        if producer.get("version") not in (None, ""):
            _text(producer["version"], "producer.version")
        context = document.get("context", {})
        if not isinstance(context, dict):
            raise ValueError("context must be an object.")
        rows = document.get("artifacts")
    else:
        _text(config.get("artifact_type"), "artifact_type for Autopsy CSV")
        producer, context = {"name": "Autopsy"}, {}
        reader = csv.DictReader(StringIO(text, newline=""), strict=True)
        if (
            not reader.fieldnames
            or any(not name for name in reader.fieldnames)
            or len(set(reader.fieldnames)) != len(reader.fieldnames)
        ):
            raise ValueError("CSV requires unique non-empty column headers.")
        rows = []
        for row in reader:
            if len(rows) >= MAX_ROWS:
                raise ValueError("Export exceeds 1000 rows; export fewer selected results.")
            if None in row or any(value is None for value in row.values()):
                raise ValueError("CSV row does not match its header width.")
            rows.append(row)
    if not isinstance(rows, list) or not rows or len(rows) > MAX_ROWS:
        raise ValueError("Export must contain 1 to 1000 artifact rows.")
    _bounded(producer)
    _bounded(context)
    for row in rows:
        if not isinstance(row, dict) or not row:
            raise ValueError("Each artifact row must be a non-empty object.")
        _bounded(row)
    lexical = _json_rows(text) if format_ == "selected-json" else [_json(row) for row in rows]
    if any(len(row.encode()) > MAX_ROW for row in lexical):
        raise ValueError("A source record exceeds the 64 KiB limit.")
    return rows, format_, producer, context, lexical


@lru_cache(maxsize=1)
def _template():
    return json.loads(
        resources.files("misp_modules").joinpath("data", "forensic-artifact", "definition.json").read_text()
    )


class _Builder:
    def __init__(self, raw, filename, format_, producer, context, config, selected, count):
        self.event, self.warnings = MISPEvent(), Counter()
        self.digest, self.format, self.config = hashlib.sha256(raw).hexdigest(), format_, config
        self.producer, self.context, self.offset = producer, context, _offset(config.get("timezone"))
        self.selection = {"rows": sorted(selected), "input_records": count, "source_attached": len(selected) == count}
        self.mapped = 0
        self.source = self.object("file", _json([self.digest, filename, config, sorted(selected)]))
        self.source.comment = "Source forensic report; SHA-256 identifies this export, not its underlying device/image."
        for key, value in {"filename": filename, "sha256": self.digest, "size-in-bytes": len(raw)}.items():
            self.add(self.source, key, value)
        if len(selected) == count:
            self.add(self.source, "attachment", filename, data=BytesIO(raw))
        else:
            self.warnings["Full source attachment omitted because row selection excludes records"] += 1

    def object(self, name, identity):
        options = {"misp_objects_template_custom": _template()} if name == "forensic-artifact" else {}
        obj = MISPObject(name, strict=True, standalone=False, **options)
        obj.uuid = str(uuid5(NAMESPACE, identity))
        self.event.add_object(obj)
        return obj

    def add(self, obj, relation, value, **kwargs):
        attribute = obj.add_attribute(relation, value=value, to_ids=False, disable_correlation=True, **kwargs)
        attribute.uuid = str(uuid5(UUID(str(obj.uuid)), _json([relation, str(value)])))

    def link(self, source, target, relation):
        reference = source.add_reference(target.uuid, relation)
        reference.uuid = str(uuid5(UUID(str(source.uuid)), _json([str(target.uuid), relation])))

    def field(self, attributes, canonical):
        keys = [
            key
            for key in (canonical, LABELS.get(canonical))
            if key is not None and attributes.get(key) not in (None, "")
        ]
        if not keys:
            return None, False
        values = [attributes[key] for key in keys]
        if (
            any(isinstance(value, (bool, list, dict, float)) for value in values)
            or len({_json(value) for value in values}) != 1
        ):
            self.warnings[f"Invalid/conflicting {canonical}; retained raw"] += 1
            return None, False
        return str(values[0]), keys[0] == canonical

    def time(self, attributes, canonical):
        value, is_canonical = self.field(attributes, canonical)
        if value is None:
            return None
        try:
            return _time(value, is_canonical, self.offset)
        except (ValueError, OverflowError):
            self.warnings[f"Unnormalized {canonical} timestamp; retained raw"] += 1
            return None

    def record(self, row, number, lexical):
        if self.format == "selected-json":
            kind = row.get("artifact_type")
            if kind is None or kind == "":
                kind = self.config.get("artifact_type")
            attributes = row.get("attributes")
            if not isinstance(attributes, dict):
                raise ValueError("Selected JSON rows require an attributes object.")
            local = row.get("context", {})
            if not isinstance(local, dict):
                raise ValueError("Row context must be an object.")
            metadata = {
                key: row.get(key) for key in ("artifact_id", "source_file", "source_object_id", "application_id")
            }
        else:
            kind, attributes, local = self.config["artifact_type"], row, {}
            metadata = {
                key: row.get(label)
                for key, label in {
                    "artifact_id": "Artifact ID",
                    "source_file": "Source File",
                    "source_object_id": "Source Object ID",
                }.items()
            }
            local = {
                key: row[label]
                for key, label in {"data_source": "Data Source", "data_source_id": "Data Source ID"}.items()
                if row.get(label)
            }
        kind = _text(kind, "artifact_type")
        context = {key: self.config[key] for key in CONTEXT if self.config.get(key) not in (None, "")}
        context.update(self.context)
        context.update(local)
        _bounded(context)
        record = self.object("forensic-artifact", _json([str(self.source.uuid), number, kind, context]))
        producer_version = self.producer.get("version")
        if producer_version is None or producer_version == "":
            producer_version = self.config.get("tool_version")
        values = {
            "producer": self.producer["name"],
            "producer-version": producer_version,
            "artifact-type": kind,
            "record-number": number,
            "source-sha256": self.digest,
            "source-format": self.format,
            "raw-record": lexical,
            "source-context": _json(
                {
                    "producer": self.producer,
                    "context": context,
                    "timezone": self.config.get("timezone"),
                    "selection": self.selection,
                }
            ),
            "review-status": "unreviewed",
        }
        values.update({key.replace("_", "-"): value for key, value in context.items() if key in CONTEXT})
        values.update({key.replace("_", "-"): value for key, value in metadata.items()})
        for key, value in values.items():
            if value is not None and value != "":
                if key not in ("raw-record", "source-context", "record-number", "review-status"):
                    value = _text(value, key)
                self.add(record, key, value)
        self.link(record, self.source, "derived-from")
        self.link(self.source, record, "contains")
        event_time = self.time(attributes, "TSK_DATETIME")
        if event_time is not None:
            self.add(record, "event-time", event_time)
        if kind not in PROFILES:
            self.warnings["Unsupported artifact type retained without typed mapping"] += 1
            return
        name, fields, times = PROFILES[kind]
        mapped = {}
        for canonical, relation in fields.items():
            value, _ = self.field(attributes, canonical)
            if value is not None:
                mapped[relation] = value
        for canonical, relation in times.items():
            value = self.time(attributes, canonical)
            if value is not None:
                mapped[relation] = value
        if kind == "TSK_EMAIL_MSG":
            mapped["message-type"] = "Email"
        if kind == "TSK_WEB_DOWNLOAD" and "name" not in mapped and mapped.get("path-downloadedTo"):
            path = mapped["path-downloadedTo"].replace("\\", "/")
            if not path.endswith("/"):
                mapped["name"] = path.rsplit("/", 1)[-1]
        definition = MISPObject(name, strict=True, standalone=False)._definition
        if any(not mapped.get(key) for key in definition.get("required", [])) or (
            definition.get("requiredOneOf") and not any(mapped.get(key) for key in definition["requiredOneOf"])
        ):
            self.warnings[f"Incomplete {kind} retained without invalid {name} object"] += 1
            return
        obj = self.object(name, _json([str(record.uuid), name]))
        obj.comment = (
            "Selected forensic observation; linked raw row is authoritative and has not been assessed as malicious."
        )
        for relation, value in mapped.items():
            self.add(obj, relation, value)
        self.link(obj, record, "derived-from")
        self.link(record, obj, "describes")
        self.mapped += 1


def dict_handler(request):
    try:
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        if set(config) - set(moduleconfig):
            raise ValueError("Unknown configuration option.")
        _bounded(config)
        for name in ("artifact_type", "tool_version", *CONTEXT):
            if config.get(name) not in (None, ""):
                _text(config[name], name)
        encoded = request.get("data")
        if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_INPUT + 2) // 3):
            raise ValueError("Provide a base64 report of at most 20 MiB.")
        raw = base64.b64decode(encoded, validate=True)
        if not raw or len(raw) > MAX_INPUT:
            raise ValueError("Report must contain 1 byte to 20 MiB.")
        rows, format_, producer, context, lexical = _read(raw, config)
        selected = _selection(config.get("rows"), len(rows))
        filename = _text(
            request.get("filename")
            or ("selected-results.csv" if format_ == "autopsy-csv" else "selected-results.json"),
            "filename",
        )
        builder = _Builder(raw, filename, format_, producer, context, config, selected, len(rows))
        for number, row in enumerate(rows, 1):
            if number in selected:
                builder.record(row, number, lexical[number - 1])
        serialized = builder.event.to_json()
        if len(serialized.encode()) > MAX_OUTPUT:
            raise ValueError("MISP result exceeds the 100 MiB limit.")
        return {
            "results": json.loads(serialized),
            "summary": {
                "input_records": len(rows),
                "selected_records": len(selected),
                "mapped_records": builder.mapped,
                "unmapped_records": len(selected) - builder.mapped,
                "source_attached": len(selected) == len(rows),
            },
            "warnings": [f"{count}: {message}" for message, count in sorted(builder.warnings.items())],
        }
    except (
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
        UnicodeError,
        binascii.Error,
        csv.Error,
        PyMISPError,
    ) as exc:
        return {"error": f"Selected forensic import: {exc}"}


def handler(q=False):
    if q is False:
        return False
    try:
        return dict_handler(json.loads(q))
    except (ValueError, TypeError, RecursionError):
        return {"error": "Request must be valid JSON."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
