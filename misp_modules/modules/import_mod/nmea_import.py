"""Import NMEA 0183 logs as preserved datasets and linked position observations."""

import binascii
import hashlib
import json
from functools import lru_cache
from importlib import resources
from io import BytesIO

from pymisp import MISPEvent, MISPObject

from misp_modules.lib import nmea0183

mispattributes = {"inputSource": ["file", "paste"], "output": ["MISP objects"], "format": "misp_standard"}
moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "NMEA 0183 Import",
    "description": "Import NMEA 0183 receiver logs with linked geolocation observations.",
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Preserves the original log with hashes, sentence counts, talkers and derived bounds in an nmea object."
        " Extracts GGA, RMC and GLL positions with fix-quality context. RMC and ZDA supply UTC dates; undated"
        " observations retain time-of-day without guessing a date. Checksums are required and validated. All"
        " attributes have to_ids disabled. Includes the nmea template for older PyMISP releases. No network access"
        " or extra dependency is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/nmea_import.md)."
    ),
    "references": ["https://gpsd.io/NMEA.html"],
    "input": "Base64-encoded ASCII NMEA 0183 log in data; optional filename.",
    "output": "MISP nmea and geolocation objects in misp_standard format.",
}


@lru_cache(maxsize=1)
def _template():
    # Keep identical to MISP/misp-objects/objects/nmea/definition.json.
    return json.loads(resources.files("misp_modules").joinpath("data", "nmea", "definition.json").read_text())


def _parse(raw, filename):
    source = nmea0183.Log(raw)
    event = MISPEvent()
    dataset = MISPObject("nmea", strict=True, standalone=False, misp_objects_template_custom=_template())

    def add(relation, value, **kwargs):
        dataset.add_attribute(relation, value=value, to_ids=False, **kwargs)

    add("filename", filename)
    add("attachment", filename, data=BytesIO(raw))
    add("mime-type", "text/plain")
    add("size-in-bytes", len(raw))
    for algorithm in ("md5", "sha1", "sha256"):
        add(algorithm, hashlib.new(algorithm, raw, usedforsecurity=False).hexdigest())
    for relation, count in (
        ("sentence-count", source.sentence_count),
        ("position-count", len(source.positions)),
        ("invalid-fix-count", source.invalid_fix_count),
        ("unhandled-sentence-count", source.unhandled_count),
    ):
        add(relation, count)
    for kind in sorted(source.sentence_types):
        add("sentence-type", kind)
    for talker in sorted(source.talkers):
        add("talker-id", talker)
    if source.positions:
        for coordinate in ("latitude", "longitude"):
            values = [position[coordinate] for position in source.positions]
            add(f"min-{coordinate}", format(min(values), "f"))
            add(f"max-{coordinate}", format(max(values), "f"))
    times = [position["timestamp"] for position in source.positions if position["timestamp"] is not None]
    if times:
        add("start-time", min(times))
        add("end-time", max(times))
    for position in source.positions:
        location = MISPObject("geolocation", strict=True, standalone=False)
        details = position["details"]
        context = f'NMEA {details["talker-id"]}{details["sentence-type"]} line {details["line"]}'
        location.comment = context
        fields = {
            "latitude": format(position["latitude"], "f"),
            "longitude": format(position["longitude"], "f"),
            "epsg": "4326",
            "spacial-reference": "WGS84 EPSG:4326",
            "text": json.dumps(details, sort_keys=True),
        }
        if position["altitude"] is not None:
            fields["altitude"] = format(position["altitude"], "f")
        if position["timestamp"] is not None:
            fields["first-seen"] = fields["last-seen"] = position["timestamp"]
        for relation, value in fields.items():
            location.add_attribute(relation, value=value, to_ids=False)
        dataset.add_reference(location.uuid, "contains", context)
        event.add_object(location)
    event.add_object(dataset)
    result = {"results": json.loads(event.to_json())}
    undated = len(source.positions) - len(times)
    if undated:
        result["warnings"] = [
            f"{undated} position(s) have no preceding dated sentence for their talker; UTC time retained without a"
            " date."
        ]
    return result


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an import request object.")
        raw = nmea0183.decode(request.get("data"))
        filename = request.get("filename")
        if filename is None or filename == "":
            filename = "import.nmea"
        if not isinstance(filename, str) or any(ord(char) < 32 for char in filename):
            raise ValueError("filename must be text without control characters.")
        filename = filename.replace("\\", "/").rsplit("/", 1)[-1] or "import.nmea"
        return _parse(raw, filename)
    except (ValueError, TypeError, binascii.Error, RecursionError, OverflowError) as error:
        return {"error": f"Unable to import NMEA: {error}"}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
