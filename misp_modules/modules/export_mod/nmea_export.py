"""Export original NMEA receiver logs without joining or synthesizing sentence streams."""

import base64
import binascii
import json
import re
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from misp_modules.lib import nmea0183
from misp_modules.lib.indicator_list import boolean

MAX_LOGS = 1000
MAX_ARCHIVE_SIZE = 21 * 1024 * 1024
moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "NMEA 0183 Export",
    "description": "Export original NMEA 0183 log attachments in a ZIP archive.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Exports active nmea attachments with their exact original bytes, in separate ZIP members. Validates"
        " checksums and supported fields; excludes deleted events, objects and attributes. Does not join streams"
        " from different receivers or synthesize receiver measurements from geolocation objects. Includes"
        " contextual attachments regardless of to_ids. No network access or extra dependency is required. See the"
        " [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/nmea_export.md)."
    ),
    "references": ["https://gpsd.io/NMEA.html"],
    "input": "MISP nmea objects; fetch events with attachment data included.",
    "output": "Base64-encoded ZIP archive containing the original NMEA logs.",
}


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _objects(data):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(envelope, dict) for envelope in data):
        raise ValueError("data must contain an event or a list of events.")
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if boolean(event.get("deleted"), "deleted") or boolean(envelope.get("deleted"), "deleted"):
            continue
        for obj in _records(dict(event, **envelope), "Object"):
            if not boolean(obj.get("deleted"), "deleted") and obj.get("name") == "nmea":
                yield obj


def _attachments(data):
    for obj in _objects(data):
        attachments = [
            attribute
            for attribute in _records(obj, "Attribute")
            if not boolean(attribute.get("deleted"), "deleted") and attribute.get("object_relation") == "attachment"
        ]
        if not attachments:
            raise ValueError("An nmea object requires an active attachment with data.")
        yield from attachments


def _filename(attribute, index):
    value = attribute.get("value")
    if not isinstance(value, str):
        raise ValueError("Attachment filenames must be text.")
    basename = value.replace("\\", "/").rsplit("/", 1)[-1]
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", basename).strip(".")[:180] or "log.nmea"
    return f"{index:04d}-{safe}"


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or "data" not in request:
            raise ValueError("Provide MISP events in data.")
        buffer = BytesIO()
        size = lines = positions = count = 0
        with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
            for count, attachment in enumerate(_attachments(request["data"]), 1):
                if count > MAX_LOGS:
                    raise ValueError("Export exceeds the 1,000-log limit.")
                raw = nmea0183.decode(attachment.get("data"))
                source = nmea0183.Log(raw)
                size += len(raw)
                lines += source.line_count
                positions += len(source.positions)
                if size > nmea0183.MAX_SIZE or lines > nmea0183.MAX_LINES or positions > nmea0183.MAX_POSITIONS:
                    raise ValueError("Combined NMEA logs exceed the size, line or position limit.")
                archive.writestr(_filename(attachment, count), raw)
        if not count:
            raise ValueError(
                "No NMEA attachments to export; geolocation objects do not contain original receiver logs."
            )
        payload = buffer.getvalue()
        if len(payload) > MAX_ARCHIVE_SIZE:
            raise ValueError("NMEA archive exceeds the 21 MiB size limit.")
        return {"response": [], "data": base64.b64encode(payload).decode("ascii")}
    except (ValueError, TypeError, binascii.Error, RecursionError, OverflowError) as error:
        return {"error": f"Unable to export NMEA: {error}"}


def introspection():
    return {
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "zip",
        "responseType": "application/zip",
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
