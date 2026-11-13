"""Export geographic MISP objects to GPX, retaining stored datasets."""

import base64
import binascii
import copy
import json
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from xml.etree import ElementTree

from misp_modules.lib.indicator_list import boolean

moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "GPX Export",
    "description": "Export gpx attachments and geolocation objects as GPX.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Returns a single stored GPX attachment unchanged, or combines datasets and standalone geolocation objects"
        " into GPX 1.1. Routes, tracks, segments and vendor extensions are retained. Linked geolocations already"
        " represented by a stored dataset are excluded to prevent duplicate points. Contextual attributes are"
        " included regardless of to_ids; deleted data is excluded. No external service or additional dependency"
        " is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/gpx_export.md)."
    ),
    "references": ["https://www.topografix.com/gpx.asp"],
    "input": "MISP gpx and geolocation objects; include attachment data when fetching events.",
    "output": "Base64-encoded GPX XML.",
}

GPX_NS = "{http://www.topografix.com/GPX/1/1}"
MISP_NS = "{https://www.misp-project.org/namespace/gpx/1}"
LEGACY_NS = "{http://www.topografix.com/GPX/1/0}"
MAX_GPX_SIZE = 20 * 1024 * 1024
MAX_POINTS = 10_000
POINT_FIELDS = (
    "ele time magvar geoidheight name cmt desc src link sym type fix sat hdop vdop pdop ageofdgpsdata dgpsid extensions"
    .split()
)
CHILDREN = {
    "wpt": POINT_FIELDS,
    "rtept": POINT_FIELDS,
    "trkpt": POINT_FIELDS,
    "rte": "name cmt desc src link number type extensions rtept".split(),
    "trk": "name cmt desc src link number type extensions trkseg".split(),
    "trkseg": ["trkpt", "extensions"],
}


class _GPXTreeBuilder(ElementTree.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.path = []
        self.points = 0
        self.point_paths = set()
        self.pending_namespaces = {}

    def start_ns(self, prefix, uri):
        # Retain bindings even when a prefix occurs only in text or an xsi:type value.
        self.pending_namespaces["xmlns" + (":" + prefix if prefix else "")] = uri

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
        attrs = dict(attrs, **self.pending_namespaces)
        self.pending_namespaces.clear()
        return super().start(tag, attrs)

    def end(self, tag):
        self.path.pop()
        return super().end(tag)

    def doctype(self, name, pubid, system):
        raise ValueError("DTDs and entity declarations are not supported.")


def _records(container, key):
    value = container.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{key} must be a list of objects.")
    return value


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
            if not boolean(obj.get("deleted"), "deleted") and obj.get("name") in ("gpx", "geolocation"):
                yield obj


def _attributes(obj):
    result = {}
    for attribute in _records(obj, "Attribute"):
        if not boolean(attribute.get("deleted"), "deleted"):
            relation = attribute.get("object_relation")
            if not isinstance(relation, str):
                raise ValueError("Object attributes require object_relation.")
            result.setdefault(relation, []).append(attribute)
    return result


def _text(value):
    if not isinstance(value, str) or any(
        ord(char) not in (9, 10, 13)
        and not (32 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD or 0x10000 <= ord(char) <= 0x10FFFF)
        for char in value
    ):
        raise ValueError("Expected text containing valid XML characters.")
    return value


def _number(value, field, minimum=None, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError(f"Invalid {field}.")
    try:
        number = Decimal(str(value))
    except InvalidOperation:
        raise ValueError(f"Invalid {field}.") from None
    if not number.is_finite() or minimum is not None and number < minimum or maximum is not None and number > maximum:
        raise ValueError(f"Invalid {field}.")
    if field == "longitude" and number == 180:
        raise ValueError("Longitude must be less than 180.")
    # Bound fixed-point expansion for scientific notation in MISP float values.
    if len(str(value)) > 256 or abs(number.as_tuple().exponent) > 256:
        raise ValueError(f"{field} exceeds the supported decimal precision.")
    return format(number, "f")


def _time(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?"
        r"(?:Z|[+-](?:(?:0[0-9]|1[0-3]):[0-5][0-9]|14:00))?",
        value,
    ):
        raise ValueError("Invalid geographic observation time.")
    end_of_day = value[11:13] == "24"
    if end_of_day:
        fraction = re.match(r"\.([0-9]+)", value[19:])
        if value[14:19] != "00:00" or fraction and fraction[1].strip("0"):
            raise ValueError("Invalid geographic observation time.")
        value = value[:11] + "00" + value[13:]
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if end_of_day:
        result += timedelta(days=1)
    result = result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    return result.isoformat().replace("+00:00", "Z")


def _document(attribute):
    encoded = attribute.get("data")
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("GPX attachment data is missing; fetch the event with attachments included.")
    if len(encoded) > 4 * ((MAX_GPX_SIZE + 2) // 3):
        raise ValueError("GPX exceeds the 20 MiB size limit.")
    data = base64.b64decode(encoded, validate=True)
    if len(data) > MAX_GPX_SIZE:
        raise ValueError("GPX exceeds the 20 MiB size limit.")
    root = ElementTree.fromstring(data, parser=ElementTree.XMLParser(target=_GPXTreeBuilder()))
    version = root.get("version")
    if version not in ("1.0", "1.1") or root.tag not in (
        "gpx",
        f"{{http://www.topografix.com/GPX/{version.replace('.', '/')}}}gpx",
    ):
        raise ValueError("Expected a GPX 1.0 or 1.1 attachment.")
    ns = root.tag[:-3]
    points = (
        root.findall(ns + "wpt") + root.findall(f"{ns}rte/{ns}rtept") + root.findall(f"{ns}trk/{ns}trkseg/{ns}trkpt")
    )
    for point in points:
        _number(point.get("lat"), "latitude", -90, 90)
        _number(point.get("lon"), "longitude", -180, 180)
        if point.find(ns + "ele") is not None:
            _number(point.findtext(ns + "ele"), "altitude")
        if point.find(ns + "time") is not None:
            _time(point.findtext(ns + "time"))
    return data, root, ns, len(points)


def _waypoint(obj, fields):
    def value(relation):
        attributes = fields.get(relation, [])
        if len(attributes) > 1:
            raise ValueError(f"Geolocation {relation} must have a single value.")
        return attributes[0].get("value") if attributes else None

    latitude, longitude = value("latitude"), value("longitude")
    if "latitude" not in fields and "longitude" not in fields:
        return None
    epsg, reference = value("epsg"), value("spacial-reference")
    if epsg not in (None, "4326", 4326, "EPSG:4326") or reference not in (None, "WGS84 EPSG:4326"):
        raise ValueError("Geolocation coordinates must use WGS84 EPSG:4326.")
    point = ElementTree.Element(
        GPX_NS + "wpt", lat=_number(latitude, "latitude", -90, 90), lon=_number(longitude, "longitude", -180, 180)
    )
    if fields.get("altitude"):
        ElementTree.SubElement(point, GPX_NS + "ele").text = _number(value("altitude"), "altitude")
    timestamp = value("first-seen")
    if timestamp is None:
        timestamp = value("last-seen")
    if timestamp is not None:
        ElementTree.SubElement(point, GPX_NS + "time").text = _time(timestamp)
    name = obj.get("comment") or value("city") or value("address")
    if name:
        ElementTree.SubElement(point, GPX_NS + "name").text = _text(name)
    notes = [_text(attribute.get("value")) for attribute in fields.get("text", [])]
    if notes:
        ElementTree.SubElement(point, GPX_NS + "desc").text = "\n".join(notes)
    return point


def _convert(node, ns):
    """Copy GPX geometry into 1.1, moving 1.0-only fields into extensions."""
    name = node.tag.removeprefix(ns)
    result = ElementTree.Element(GPX_NS + name, dict(node.attrib))
    result.text, result.tail = node.text, node.tail
    if name == "extensions":
        result.extend(copy.deepcopy(list(node)))
        return result
    if name not in CHILDREN:
        for child in node:
            result.append(
                _convert(child, ns)
                if child.tag.startswith(ns) and (ns or not child.tag.startswith("{"))
                else copy.deepcopy(child)
            )
        return result
    fields, extensions = {}, []
    url = node.findtext(ns + "url")
    for child in node:
        is_core = child.tag.startswith(ns) if ns else not child.tag.startswith("{")
        local = child.tag.removeprefix(ns) if is_core else None
        if child.tag == ns + "extensions":
            extensions.extend(copy.deepcopy(list(child)))
        elif local in CHILDREN[name]:
            fields.setdefault(local, []).append(_convert(child, ns))
        elif local not in ("url", "urlname") or not url:
            preserved = copy.deepcopy(child)
            if is_core:
                preserved.tag = LEGACY_NS + local
            extensions.append(preserved)
    if url:
        link = ElementTree.Element(GPX_NS + "link", href=url)
        if label := node.findtext(ns + "urlname"):
            ElementTree.SubElement(link, GPX_NS + "text").text = label
        fields.setdefault("link", []).append(link)
    if extensions:
        extension = ElementTree.Element(GPX_NS + "extensions")
        extension.extend(extensions)
        fields["extensions"] = [extension]
    for field in CHILDREN[name]:
        result.extend(fields.get(field, []))
    return result


def _metadata(root, ns):
    if root.get("version") == "1.1":
        source = root.find(ns + "metadata")
        return _convert(source, ns) if source is not None else ElementTree.Element(GPX_NS + "metadata")
    metadata = ElementTree.Element(GPX_NS + "metadata")
    for name in ("name", "desc"):
        node = root.find(ns + name)
        if node is not None:
            metadata.append(_convert(node, ns))
    author_name, email = root.findtext(ns + "author"), root.findtext(ns + "email")
    if author_name or email:
        author = ElementTree.SubElement(metadata, GPX_NS + "author")
        if author_name:
            ElementTree.SubElement(author, GPX_NS + "name").text = author_name
        if email and email.count("@") == 1 and all(email.split("@")):
            username, domain = email.split("@")
            ElementTree.SubElement(author, GPX_NS + "email", id=username, domain=domain)
    if url := root.findtext(ns + "url"):
        link = ElementTree.SubElement(metadata, GPX_NS + "link", href=url)
        if label := root.findtext(ns + "urlname"):
            ElementTree.SubElement(link, GPX_NS + "text").text = label
    for name in ("time", "keywords"):
        node = root.find(ns + name)
        if node is not None:
            metadata.append(_convert(node, ns))
    return metadata


def _inherit_namespaces(node, source):
    for key, uri in source.attrib.items():
        if key == "xmlns" or key.startswith("xmlns:"):
            node.attrib.setdefault(key, uri)
    return node


def _serialize(root):
    """Use private prefixes for element names while retaining all source QName bindings."""
    reserved = {"xml", "xmlns"}
    namespaces = {}
    for node in root.iter():
        reserved.update(key[6:] for key in node.attrib if key.startswith("xmlns:"))
        for name in (node.tag, *node.attrib):
            if name.startswith("{"):
                namespaces.setdefault(name[1:].split("}", 1)[0], None)
    index = 0
    for uri in namespaces:
        if uri == "http://www.w3.org/XML/1998/namespace":
            namespaces[uri] = "xml"
            continue
        while f"misp{index}" in reserved:
            index += 1
        namespaces[uri] = f"misp{index}"
        index += 1

    def qualified(name):
        if not name.startswith("{"):
            return name
        uri, local = name[1:].split("}", 1)
        return f"{namespaces[uri]}:{local}"

    # Do not change ElementTree's process-wide prefix registry: requests may run concurrently.
    for node in root.iter():
        node.tag = qualified(node.tag)
        attrs = {qualified(key): value for key, value in node.attrib.items()}
        node.attrib.clear()
        node.attrib.update(attrs)
    for uri, prefix in namespaces.items():
        if prefix != "xml":
            root.set("xmlns:" + prefix, uri)
    return ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)


def _combine(documents, waypoints):
    root = ElementTree.Element(GPX_NS + "gpx", version="1.1", creator="MISP misp-modules")
    metadata = _metadata(documents[0][1], documents[0][2]) if documents else ElementTree.Element(GPX_NS + "metadata")
    if documents:
        _inherit_namespaces(metadata, documents[0][1])
    # Any stored bounds may be stale once several datasets or locations are combined.
    for bounds in list(metadata.findall(GPX_NS + "bounds")):
        metadata.remove(bounds)
    root.append(metadata)
    extensions = ElementTree.Element(GPX_NS + "extensions")
    for document in documents:
        _, source, ns, _ = document
        context = ElementTree.SubElement(extensions, MISP_NS + "source", dict(source.attrib))
        for child in source:
            if child.tag not in (ns + "wpt", ns + "rte", ns + "trk"):
                context.append(copy.deepcopy(child))
    for kind in ("wpt", "rte", "trk"):
        for _, source, ns, _ in documents:
            root.extend(_inherit_namespaces(_convert(node, ns), source) for node in source.findall(ns + kind))
        if kind == "wpt":
            root.extend(waypoints)
    if len(extensions):
        root.append(extensions)
    return _serialize(root)


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict) or "data" not in request:
            raise ValueError("Provide MISP events in data.")
        objects = list(_objects(request["data"]))
        documents, represented, waypoints = [], set(), []
        size = count = skipped = 0
        for obj in objects:
            if obj["name"] != "gpx":
                continue
            attachments = _attributes(obj).get("attachment", [])
            if not attachments:
                raise ValueError("A gpx object requires an active attachment with data.")
            for attachment in attachments:
                document = _document(attachment)
                size += len(document[0])
                count += document[3]
                if size > MAX_GPX_SIZE or count > MAX_POINTS:
                    raise ValueError("Combined GPX exceeds the 20 MiB or 10,000-point limit.")
                documents.append(document)
            for reference in _records(obj, "ObjectReference"):
                if reference.get("relationship_type") == "contains" and not boolean(
                    reference.get("deleted"), "deleted"
                ):
                    identifier = reference.get("referenced_uuid")
                    if isinstance(identifier, str):
                        represented.add(identifier)
        for obj in objects:
            if obj["name"] != "geolocation" or obj.get("uuid") in represented:
                continue
            waypoint = _waypoint(obj, _attributes(obj))
            if waypoint is None:
                skipped += 1
                continue
            count += 1
            if count > MAX_POINTS:
                raise ValueError("Combined GPX exceeds the 10,000-point limit.")
            waypoints.append(waypoint)
        if not documents and not waypoints:
            raise ValueError("No GPX attachments or geolocations with coordinates to export.")
        payload = documents[0][0] if len(documents) == 1 and not waypoints else _combine(documents, waypoints)
        if len(payload) > MAX_GPX_SIZE:
            raise ValueError("Exported GPX exceeds the 20 MiB size limit.")
        result = {"response": [], "data": base64.b64encode(payload).decode("ascii")}
        if skipped:
            result["warnings"] = [f"Skipped {skipped} geolocation object(s) without coordinates."]
        return result
    except (ValueError, TypeError, binascii.Error, ElementTree.ParseError, LookupError, OverflowError) as error:
        return {"error": f"Unable to export GPX: {error}"}


def introspection():
    return {
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "gpx",
        "responseType": "application/gpx+xml",
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
