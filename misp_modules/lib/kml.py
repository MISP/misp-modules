"""Bounded KML geometry parsing and KMZ package reading; never resolves resources."""

import base64
import posixpath
import re
import stat
import zlib
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from io import BytesIO
from pathlib import PurePosixPath
from urllib.parse import quote, unquote, urljoin, urlsplit
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile, is_zipfile

KML_NS = "http://www.opengis.net/kml/2.2"
GX = "{http://www.google.com/kml/ext/2.2}"
MAX_SIZE = 20 * 1024 * 1024
MAX_MEMBERS = 1000
MAX_COORDINATES = 10_000
MAX_PLACEMARKS = 10_000
MAX_DEPTH = 32
MAX_NODES = 200_000
GEOMETRIES = {"Point", "LineString", "LinearRing", "Polygon", "MultiGeometry", "Model"}
MIME = {"kml": "application/vnd.google-earth.kml+xml", "kmz": "application/vnd.google-earth.kmz"}


def number(value, field, minimum=None, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)) or len(str(value)) > 256:
        raise ValueError(f"Invalid {field}.")
    try:
        result = Decimal(str(value))
    except InvalidOperation:
        raise ValueError(f"Invalid {field}.") from None
    if not result.is_finite() or minimum is not None and result < minimum or maximum is not None and result > maximum:
        raise ValueError(f"Invalid {field}.")
    if abs(result.as_tuple().exponent) > 256:
        raise ValueError(f"{field} exceeds supported numeric precision.")
    return result


def decode(encoded):
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("Provide base64-encoded KML/KMZ data; include attachments when fetching events.")
    if len(encoded) > 4 * ((MAX_SIZE + 2) // 3):
        raise ValueError("KML/KMZ exceeds the 20 MiB size limit.")
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > MAX_SIZE:
        raise ValueError("KML/KMZ exceeds the 20 MiB size limit.")
    return raw


def member_name(name):
    if not isinstance(name, str) or len(name) > 512 or not name or "\\" in name or ":" in name:
        raise ValueError("Unsafe KMZ member name.")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in name.rstrip("/").split("/")):
        raise ValueError("Unsafe KMZ member path.")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("Control characters in KMZ member names are unsupported.")
    return name.rstrip("/")


def read_package(raw):
    files, names, total = {}, set(), 0
    try:
        with ZipFile(BytesIO(raw)) as archive:
            if len(archive.infolist()) > MAX_MEMBERS:
                raise ValueError("KMZ exceeds the 1,000-member limit.")
            for info in archive.infolist():
                if info.orig_filename != info.filename:
                    raise ValueError("Invalid KMZ member name.")
                name = member_name(info.filename)
                if name.casefold() in names:
                    raise ValueError("Duplicate or case-ambiguous KMZ member names.")
                names.add(name.casefold())
                if stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK:
                    raise ValueError("KMZ symbolic links are unsupported.")
                if info.flag_bits & 1 or info.compress_type not in (ZIP_STORED, ZIP_DEFLATED):
                    raise ValueError("KMZ must use unencrypted stored or deflated ZIP members.")
                total += info.file_size
                if total > MAX_SIZE:
                    raise ValueError("Expanded KMZ exceeds the 20 MiB size limit.")
                if info.is_dir():
                    continue
                files[name] = archive.read(info)
    except (BadZipFile, zlib.error, NotImplementedError, RuntimeError) as error:
        raise ValueError(f"Invalid KMZ archive: {error}") from None
    roots = [name for name in files if "/" not in name and name.lower().endswith(".kml")]
    if "doc.kml" in roots:
        entry = "doc.kml"
    elif len(roots) == 1:
        entry = roots[0]
    else:
        raise ValueError("KMZ requires doc.kml or one unambiguous root-level KML entry document.")
    return files, entry


class _Builder(ET.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.depth = self.count = 0

    def start(self, tag, attrs):
        self.depth += 1
        self.count += 1
        if self.depth > MAX_DEPTH or self.count > MAX_NODES:
            raise ValueError("KML exceeds the nesting or XML node limit.")
        return super().start(tag, attrs)

    def end(self, tag):
        self.depth -= 1
        return super().end(tag)

    def doctype(self, name, pubid, system):
        raise ValueError("DTDs and entity declarations are unsupported.")


def timestamp(value):
    """Validate common KML date forms; map only complete instants without losing precision."""
    full = re.fullmatch(
        r"([0-9]{4}-[0-9]{2}-[0-9]{2}T)([0-9]{2}):([0-9]{2}):([0-9]{2})"
        r"(?:\.([0-9]{1,64}))?(Z|[+-](?:(?:0[0-9]|1[0-3]):[0-5][0-9]|14:00))?",
        value,
    )
    if full:
        end_of_day = full[2] == "24"
        if end_of_day and (full[3] != "00" or full[4] != "00" or full[5] and full[5].strip("0")):
            raise ValueError("Invalid KML end-of-day time.")
        normalized = value[:11] + "00" + value[13:] if end_of_day else value
        result = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        if end_of_day:
            result += timedelta(days=1)
        if not full[6] or full[5] and len(full[5]) > 6:
            return None
        return result.astimezone(timezone.utc)
    partial = re.fullmatch(
        r"([0-9]{4})(?:-([0-9]{2})(?:-([0-9]{2}))?)?(?:Z|[+-](?:(?:0[0-9]|1[0-3]):[0-5][0-9]|14:00))?", value
    )
    if not partial:
        raise ValueError("Invalid or unsupported KML timestamp.")
    date(int(partial[1]), int(partial[2] or 1), int(partial[3] or 1))
    return None


class Dataset:
    def __init__(self, raw):
        if len(raw) > MAX_SIZE:
            raise ValueError("KML/KMZ exceeds the 20 MiB size limit.")
        self.format, self.files, self.entry = "kml", {}, None
        if is_zipfile(BytesIO(raw)):
            self.format = "kmz"
            self.files, self.entry = read_package(raw)
            xml = self.files[self.entry]
        else:
            xml = raw
        self.xml = xml
        self.positions, self.points, self.geometry_types = [], [], set()
        self.placemark_count = self.node_count = self.unresolved_links = 0
        self.links = []
        self.root = self._document(xml, self.entry or "")
        visited, cursor = {self.entry}, 0
        while cursor < len(self.links):
            link = self.links[cursor]
            cursor += 1
            target = self._target(link) if self.format == "kmz" else None
            if target is None:
                self.unresolved_links += 1
            elif target not in visited:
                visited.add(target)
                self._document(self.files[target], target)

    def _document(self, xml, entry):
        builder = _Builder()
        root = ET.fromstring(xml, parser=ET.XMLParser(target=builder))
        self.node_count += builder.count
        if self.node_count > MAX_NODES:
            raise ValueError("KML package exceeds the XML node limit.")
        self.ns = root.tag[:-3] if root.tag.endswith("kml") else "invalid"
        namespaces = {
            "",
            "{" + KML_NS + "}",
            *("{http://earth.google.com/kml/" + version + "}" for version in ("2.0", "2.1", "2.2")),
        }
        if self.ns not in namespaces or root.tag != self.ns + "kml":
            raise ValueError("Expected a KML 2.x document in its official namespace, or without a namespace.")
        self.current_entry = entry
        feature = next(
            (child for child in root if child.tag in {self.ns + name for name in ("Document", "Folder", "Placemark")}),
            root,
        )
        if not hasattr(self, "name"):
            self.name = self._text(feature, "name")
            self.description = self._text(feature, "description")
        self._features(root, [], quote(entry, safe="/"))
        return root

    def _target(self, link):
        try:
            url = urlsplit(link)
            if url.scheme or url.netloc or url.query or url.fragment or not url.path or url.path.startswith("/"):
                return None
            path = posixpath.normpath(unquote(url.path))
            member_name(path)
        except ValueError:
            return None
        return path if path in self.files and path.lower().endswith(".kml") else None

    def _text(self, element, name):
        child = element.find(self.ns + name)
        return "".join(child.itertext()).strip() if child is not None else ""

    def _features(self, parent, folders, base):
        base = urljoin(base, parent.get("{http://www.w3.org/XML/1998/namespace}base", ""))
        for child in parent:
            if child.tag in (self.ns + "Document", self.ns + "Folder"):
                self._features(child, folders + [self._text(child, "name")], base)
            elif child.tag == self.ns + "NetworkLink":
                link = child.find(self.ns + "Link")
                if link is None:
                    link = child.find(self.ns + "Url")
                if link is not None:
                    link_base = urljoin(base, child.get("{http://www.w3.org/XML/1998/namespace}base", ""))
                    link_base = urljoin(link_base, link.get("{http://www.w3.org/XML/1998/namespace}base", ""))
                    try:
                        href = link.find(self.ns + "href")
                        if href is not None:
                            link_base = urljoin(link_base, href.get("{http://www.w3.org/XML/1998/namespace}base", ""))
                        self.links.append(urljoin(link_base, self._text(link, "href")))
                    except ValueError:
                        self.unresolved_links += 1
            elif child.tag == self.ns + "Placemark":
                self.placemark_count += 1
                if self.placemark_count > MAX_PLACEMARKS:
                    raise ValueError("KML exceeds the 10,000-Placemark limit.")
                context = {
                    "placemark": self.placemark_count,
                    "document": self.current_entry,
                    "folder-path": folders,
                    "name": self._text(child, "name"),
                    "description": self._text(child, "description"),
                }
                if child.get("id"):
                    context["id"] = child.get("id")
                extended = child.find(self.ns + "ExtendedData")
                if extended is not None:
                    context["extended-data"] = ET.tostring(extended, encoding="unicode")
                times, raw_times = self._times(child)
                if raw_times:
                    context["time"] = raw_times
                for geometry in child:
                    if geometry.tag in {self.ns + name for name in GEOMETRIES} | {GX + "Track", GX + "MultiTrack"}:
                        self._geometry(geometry, context, times)

    def _times(self, feature):
        primitives = feature.findall(self.ns + "TimeStamp") + feature.findall(self.ns + "TimeSpan")
        if len(primitives) > 1:
            raise ValueError("A feature must have at most one time primitive.")
        fields, raw = {}, {}
        if not primitives:
            return fields, raw
        node = primitives[0]
        pairs = (
            (("when", "first-seen"),)
            if node.tag == self.ns + "TimeStamp"
            else (("begin", "first-seen"), ("end", "last-seen"))
        )
        for tag, relation in pairs:
            value = self._text(node, tag)
            if value:
                raw[tag] = value
                parsed = timestamp(value)
                if parsed is not None:
                    fields[relation] = parsed
        if "when" in raw and "first-seen" in fields:
            fields["last-seen"] = fields["first-seen"]
        if fields.get("first-seen") and fields.get("last-seen") and fields["first-seen"] > fields["last-seen"]:
            raise ValueError("KML TimeSpan begins after it ends.")
        return fields, raw

    def _position(self, parts):
        if len(parts) not in (2, 3):
            raise ValueError("KML positions require longitude, latitude and optional altitude.")
        point = [number(parts[0], "longitude", -180, 180), number(parts[1], "latitude", -90, 90)]
        if len(parts) == 3:
            point.append(number(parts[2], "altitude"))
        self.positions.append(point)
        if len(self.positions) > MAX_COORDINATES:
            raise ValueError("KML exceeds the 10,000-coordinate limit.")
        return point

    def _coordinates(self, node):
        elements = node.findall(self.ns + "coordinates")
        if len(elements) != 1:
            raise ValueError("Geometry requires exactly one coordinates element.")
        return [self._position(item.split(",")) for item in (elements[0].text or "").split()]

    def _mode(self, node, inherited):
        modes = node.findall(self.ns + "altitudeMode") + node.findall(GX + "altitudeMode")
        if len(modes) > 1:
            raise ValueError("Geometry has multiple altitude modes.")
        if not modes:
            return inherited or "clampToGround"
        value = (modes[0].text or "").strip()
        allowed = (
            ("clampToSeaFloor", "relativeToSeaFloor")
            if modes[0].tag.startswith(GX)
            else ("clampToGround", "relativeToGround", "absolute")
        )
        if value not in allowed:
            raise ValueError("Unsupported KML altitude mode.")
        return value

    def _observation(self, position, context, times, mode, **details):
        metadata = {"altitude-mode": mode, **details}
        if len(position) == 3:
            metadata["source-altitude"] = str(position[2])
        self.points.append({"position": position, "context": context, "details": metadata, "times": times})

    def _geometry(self, node, context, times, inherited_mode=None):
        kind = (
            node.tag.removeprefix(self.ns)
            if node.tag.startswith(self.ns) and not node.tag.startswith(GX)
            else "gx:" + node.tag.removeprefix(GX)
        )
        self.geometry_types.add(kind)
        mode = self._mode(node, inherited_mode)
        if kind in ("Point", "LineString", "LinearRing"):
            coordinates = self._coordinates(node)
            minimum = {"Point": 1, "LineString": 2, "LinearRing": 4}[kind]
            if len(coordinates) < minimum or kind == "Point" and len(coordinates) != 1:
                raise ValueError("Invalid number of KML geometry positions.")
            if kind == "LinearRing" and coordinates[0] != coordinates[-1]:
                raise ValueError("KML LinearRing must be closed.")
            if kind == "Point":
                self._observation(coordinates[0], context, times, mode, geometry="Point")
        elif kind == "Polygon":
            outer = node.findall(self.ns + "outerBoundaryIs")
            if len(outer) != 1:
                raise ValueError("Polygon requires one outer boundary.")
            for boundary in outer + node.findall(self.ns + "innerBoundaryIs"):
                rings = boundary.findall(self.ns + "LinearRing")
                if len(rings) != 1:
                    raise ValueError("Polygon boundaries require a LinearRing.")
                self._geometry(rings[0], context, times, mode)
        elif kind in ("MultiGeometry", "gx:MultiTrack"):
            for child in node:
                if (
                    kind == "MultiGeometry"
                    and child.tag in {self.ns + name for name in GEOMETRIES} | {GX + "Track", GX + "MultiTrack"}
                    or kind == "gx:MultiTrack"
                    and child.tag == GX + "Track"
                ):
                    self._geometry(child, context, times, mode)
        elif kind == "gx:Track":
            whens, coords, angles = (
                node.findall(self.ns + "when"),
                node.findall(GX + "coord"),
                node.findall(GX + "angles"),
            )
            if len(whens) != len(coords) or angles and len(angles) != len(coords):
                raise ValueError("gx:Track times, coordinates and optional angles must have equal counts.")
            for index, (when, coord) in enumerate(zip(whens, coords), 1):
                value = (when.text or "").strip()
                parsed = timestamp(value) if value else None
                text = (coord.text or "").strip()
                if not text:
                    continue  # KML permits empty samples in sparse tracks.
                parts = text.split()
                if len(parts) != 3:
                    raise ValueError("gx:coord requires three space-separated coordinates.")
                position = self._position(parts)
                fields = {"first-seen": parsed, "last-seen": parsed} if parsed is not None else {}
                self._observation(position, context, fields, mode, geometry="gx:Track", sample=index, when=value)
        # Model anchors, overlays, camera coordinates and arbitrary extension payloads remain in the source.
