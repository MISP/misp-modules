"""Import GPX datasets and their geographic observations without network access."""

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from io import BytesIO
from xml.etree import ElementTree

from pymisp import MISPEvent, MISPObject

mispattributes = {
    "inputSource": ["file", "paste"],
    "output": ["MISP objects"],
    "format": "misp_standard",
}
moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "GPX Import",
    "description": "Import GPX files as a gpx object with linked geolocation objects.",
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP with the gpx and geolocation object templates"],
    "features": (
        "Imports GPX 1.0 and 1.1, preserving the original bytes in a gpx attachment with hashes, metadata, counts"
        " and spatial bounds. Each waypoint, route point and track point becomes a linked geolocation object with"
        " WGS84 coordinates, elevation and observation time where available. All attributes have to_ids disabled."
        " No external service or additional dependency is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/gpx_import.md)."
    ),
    "references": ["https://www.topografix.com/gpx.asp"],
    "input": "Base64-encoded GPX XML in data; optional filename.",
    "output": "MISP gpx and geolocation objects in misp_standard format.",
}

MAX_GPX_SIZE = 20 * 1024 * 1024
MAX_POINTS = 10_000


class _GPXTreeBuilder(ElementTree.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.path = []
        self.points = 0
        self.point_paths = set()

    def start(self, tag, attrs):
        if not self.path:
            ns = tag[:-3]
            self.point_paths = {
                (tag, ns + "wpt"),
                (tag, ns + "rte", ns + "rtept"),
                (tag, ns + "trk", ns + "trkseg", ns + "trkpt"),
            }
        self.path.append(tag)
        if len(self.path) > 32:
            raise ValueError("XML nesting exceeds the 32-level limit.")
        if tuple(self.path) in self.point_paths:
            self.points += 1
            if self.points > MAX_POINTS:
                raise ValueError("GPX exceeds the 10,000-point limit.")
        return super().start(tag, attrs)

    def end(self, tag):
        self.path.pop()
        return super().end(tag)

    def doctype(self, name, pubid, system):
        raise ValueError("DTDs and entity declarations are not supported.")


def _decimal(value, name, minimum=None, maximum=None):
    if not isinstance(value, str) or not re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)", value.strip()):
        raise ValueError(f"Invalid GPX {name}.")
    number = Decimal(value.strip())
    if minimum is not None and number < minimum or maximum is not None and number > maximum:
        raise ValueError(f"GPX {name} is out of range.")
    if name == "longitude" and number == 180:
        raise ValueError("GPX longitude must be less than 180.")
    return number


def _time(value):
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?"
        r"(?:Z|[+-](?:(?:0[0-9]|1[0-3]):[0-5][0-9]|14:00))?",
        value,
    ):
        raise ValueError("Invalid GPX observation time.")
    end_of_day = value[11:13] == "24"
    if end_of_day:
        fraction = re.match(r"\.([0-9]+)", value[19:])
        if value[14:19] != "00:00" or fraction and fraction[1].strip("0"):
            raise ValueError("Invalid GPX observation time.")
        # XML Schema permits midnight as 24:00:00; older Python runtimes do not.
        value = value[:11] + "00" + value[13:]
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if end_of_day:
        result += timedelta(days=1)
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)


def _points(root, ns):
    for index, point in enumerate(root.findall(ns + "wpt"), 1):
        yield point, f"GPX waypoint {index}", False
    for index, route in enumerate(root.findall(ns + "rte"), 1):
        for position, point in enumerate(route.findall(ns + "rtept"), 1):
            yield point, f"GPX route {index} point {position}", True
    for index, track in enumerate(root.findall(ns + "trk"), 1):
        for segment, node in enumerate(track.findall(ns + "trkseg"), 1):
            for position, point in enumerate(node.findall(ns + "trkpt"), 1):
                yield point, f"GPX track {index} segment {segment} point {position}", True


def _parse(data, filename):
    root = ElementTree.fromstring(data, parser=ElementTree.XMLParser(target=_GPXTreeBuilder()))
    version = root.get("version")
    if version not in ("1.0", "1.1") or root.tag not in (
        "gpx",
        f"{{http://www.topografix.com/GPX/{version.replace('.', '/')}}}gpx",
    ):
        raise ValueError("Expected GPX 1.0 or 1.1 in the official namespace, or without a namespace.")
    ns = root.tag[:-3]
    metadata = root.find(ns + "metadata") if version == "1.1" else root

    def text(node, path):
        if node is None:
            return ""
        return node.findtext("/".join(ns + part for part in path.split("/")), "").strip()

    event = MISPEvent()
    dataset = MISPObject("gpx", strict=True, standalone=False)

    def add(relation, value, **kwargs):
        dataset.add_attribute(relation, value=value, to_ids=False, **kwargs)

    add("filename", filename)
    add("attachment", filename, data=BytesIO(data))
    add("mime-type", "application/gpx+xml")
    add("size-in-bytes", len(data))
    add("gpx-version", version)
    for algorithm in ("md5", "sha1", "sha256"):
        add(algorithm, hashlib.new(algorithm, data, usedforsecurity=False).hexdigest())
    if root.get("creator"):
        add("creator", root.get("creator"))
    for relation, path in (
        ("name", "name"),
        ("description-text", "desc"),
        ("author", "author/name" if version == "1.1" else "author"),
    ):
        if value := text(metadata, path):
            add(relation, value)
    if value := text(metadata, "time"):
        add("time", _time(value))
    for keyword in text(metadata, "keywords").split(","):
        if keyword.strip():
            add("keywords", keyword.strip())
    if metadata is not None:
        links = [link.get("href", "").strip() for link in metadata.findall(ns + "link")]
        if version == "1.0":
            links.append(text(metadata, "url"))
        for link in dict.fromkeys(filter(None, links)):
            add("link", link)

    locations, times = [], []
    for point, context, timed_path in _points(root, ns):
        latitude = _decimal(point.get("lat"), "latitude", -90, 90)
        longitude = _decimal(point.get("lon"), "longitude", -180, 180)
        locations.append((latitude, longitude))
        location = MISPObject("geolocation", strict=True, standalone=False)
        location.comment = context
        for relation, value in (
            ("latitude", str(latitude)),
            ("longitude", str(longitude)),
            ("epsg", "4326"),
            ("spacial-reference", "WGS84 EPSG:4326"),
        ):
            location.add_attribute(relation, value=value, to_ids=False)
        if point.find(ns + "ele") is not None:
            value = text(point, "ele")
            location.add_attribute("altitude", value=str(_decimal(value, "elevation")), to_ids=False)
        if point.find(ns + "time") is not None:
            value = text(point, "time")
            timestamp = _time(value)
            for relation in ("first-seen", "last-seen"):
                location.add_attribute(relation, value=timestamp, to_ids=False)
            if timed_path:
                times.append(timestamp)
        notes = [
            f"{field}: {value}"
            for field in ("name", "cmt", "desc", "src", "sym", "type")
            if (value := text(point, field))
        ]
        if notes:
            location.add_attribute("text", value="\n".join(notes), to_ids=False)
        dataset.add_reference(location.uuid, "contains", context)
        event.add_object(location)

    for relation, path in (
        ("waypoint-count", "wpt"),
        ("route-count", "rte"),
        ("track-count", "trk"),
        ("track-segment-count", "trk/trkseg"),
    ):
        add(relation, len(root.findall("/".join(ns + part for part in path.split("/")))))
    add("point-count", len(locations))
    # Derive bounds from observations, rather than trusting a possibly stale header.
    if locations:
        latitudes, longitudes = zip(*locations)
        for relation, value in (
            ("min-latitude", min(latitudes)),
            ("max-latitude", max(latitudes)),
            ("min-longitude", min(longitudes)),
            ("max-longitude", max(longitudes)),
        ):
            add(relation, str(value))
    if times:
        add("start-time", min(times))
        add("end-time", max(times))
    event.add_object(dataset)
    return {"results": json.loads(event.to_json())}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or not isinstance(request.get("data"), str) or not request["data"]:
            raise ValueError("Provide base64-encoded GPX XML in data.")
        if len(request["data"]) > 4 * ((MAX_GPX_SIZE + 2) // 3):
            raise ValueError("GPX exceeds the 20 MiB size limit.")
        data = base64.b64decode(request["data"], validate=True)
        if len(data) > MAX_GPX_SIZE:
            raise ValueError("GPX exceeds the 20 MiB size limit.")
        filename = request.get("filename")
        if filename is None or filename == "":
            filename = "import.gpx"
        if not isinstance(filename, str) or any(ord(char) < 32 for char in filename):
            raise ValueError("filename must be a string without control characters.")
        filename = filename.replace("\\", "/").rsplit("/", 1)[-1] or "import.gpx"
        return _parse(data, filename)
    except (ValueError, TypeError, binascii.Error, ElementTree.ParseError, LookupError, OverflowError) as error:
        return {"error": f"Unable to import GPX: {error}"}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
