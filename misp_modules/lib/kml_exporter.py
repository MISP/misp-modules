"""Shared KML/KMZ export preserving source documents and isolating package assets."""

import base64
import html
import json
from decimal import Decimal
from io import BytesIO
from urllib.parse import quote
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZipFile

from misp_modules.lib import kml
from misp_modules.lib.indicator_list import boolean

MAX_ARCHIVE_SIZE = 20 * 1024 * 1024


def _records(container, key):
    records = container.get(key, [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{key} must be a list of objects.")
    return records


def _objects(data):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(envelope, dict) for envelope in data):
        raise ValueError("data must contain an event or list of events.")
    for envelope in data:
        event = envelope.get("Event", envelope)
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        if boolean(event.get("deleted"), "deleted") or boolean(envelope.get("deleted"), "deleted"):
            continue
        for obj in _records(dict(event, **envelope), "Object"):
            if not boolean(obj.get("deleted"), "deleted") and obj.get("name") in ("kml", "geolocation"):
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


def _point(obj, index):
    fields = _attributes(obj)

    def value(relation):
        attributes = fields.get(relation, [])
        if len(attributes) > 1:
            raise ValueError(f"Geolocation {relation} must have a single value.")
        return attributes[0].get("value") if attributes else None

    if "latitude" not in fields and "longitude" not in fields:
        return None
    if value("epsg") not in (None, "4326", 4326, "EPSG:4326") or value("spacial-reference") not in (
        None,
        "WGS84 EPSG:4326",
    ):
        raise ValueError("Geolocation coordinates must use WGS84 EPSG:4326.")
    longitude = kml.number(value("longitude"), "longitude", -180, 180)
    latitude = kml.number(value("latitude"), "latitude", -90, 90)
    node = ET.Element("Placemark", id=f"misp-point-{index}")
    name = obj.get("comment") or value("city") or value("address")
    if name:
        ET.SubElement(node, "name").text = _text(name)
    notes = [_text(attribute.get("value")) for attribute in fields.get("text", [])]
    if notes:
        ET.SubElement(node, "description").text = html.escape("\n".join(notes))
    times = {}
    for relation in ("first-seen", "last-seen"):
        if relation in fields:
            text = _text(value(relation))
            parsed = kml.timestamp(text)
            if parsed is None:
                raise ValueError(
                    "Export observation times require a complete timestamp with timezone and microsecond precision or"
                    " less."
                )
            times[relation] = parsed
    if times.get("first-seen") and times.get("last-seen") and times["first-seen"] > times["last-seen"]:
        raise ValueError("Geolocation first-seen is after last-seen.")
    if times:
        if len(times) == 2 and times["first-seen"] == times["last-seen"]:
            ET.SubElement(ET.SubElement(node, "TimeStamp"), "when").text = (
                times["first-seen"].isoformat().replace("+00:00", "Z")
            )
        else:
            span = ET.SubElement(node, "TimeSpan")
            for relation, tag in (("first-seen", "begin"), ("last-seen", "end")):
                if relation in times:
                    ET.SubElement(span, tag).text = times[relation].isoformat().replace("+00:00", "Z")
    metadata = {}
    for relation in (
        "city",
        "country",
        "countrycode",
        "region",
        "address",
        "zipcode",
        "neighborhood",
        "accuracy-radius",
    ):
        if relation in fields:
            metadata["misp:" + relation] = _text(str(value(relation)))
    if obj.get("uuid"):
        metadata["misp:uuid"] = _text(obj["uuid"])
    if "altitude" in fields:
        # KML absolute heights are relative to sea level; MISP's WGS84 height has no geoid conversion here.
        metadata["misp:altitude-wgs84"] = format(kml.number(value("altitude"), "altitude"), "f")
    if notes:
        metadata["misp:text"] = json.dumps(notes)
    if metadata:
        extended = ET.SubElement(node, "ExtendedData")
        for key, text in metadata.items():
            ET.SubElement(ET.SubElement(extended, "Data", name=key), "value").text = text
    point = ET.SubElement(node, "Point")
    ET.SubElement(point, "coordinates").text = f'{format(longitude, "f")},{format(latitude, "f")}'
    return node


def _document(points, links=()):
    root = ET.Element("kml", xmlns=kml.KML_NS)
    document = ET.SubElement(root, "Document")
    ET.SubElement(document, "name").text = "MISP geographic export"
    for name, path in links:
        node = ET.SubElement(document, "NetworkLink")
        ET.SubElement(node, "name").text = _text(name)
        ET.SubElement(ET.SubElement(node, "Link"), "href").text = quote(path, safe="/")
    document.extend(points)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _basename(value):
    if not isinstance(value, str):
        raise ValueError("Attachment filenames must be text.")
    name = value.replace("\\", "/").rsplit("/", 1)[-1]
    try:
        kml.member_name(name)
    except ValueError:
        name = "document.kml"
    return name if name.lower().endswith(".kml") else name + ".kml"


def _package(files):
    if len(files) > kml.MAX_MEMBERS or sum(len(raw) for raw in files.values()) > kml.MAX_SIZE:
        raise ValueError("Exported KMZ exceeds the member or expanded size limit.")
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        for name, raw in files.items():
            kml.member_name(name)
            archive.writestr(name, raw)
    payload = buffer.getvalue()
    if len(payload) > MAX_ARCHIVE_SIZE:
        raise ValueError("KMZ archive exceeds the 20 MiB output limit.")
    return payload


def export(data, output_format):
    objects = list(_objects(data))
    documents, represented, points = [], set(), []
    size = input_size = coordinates = placemarks = skipped = 0
    for obj in objects:
        if obj["name"] != "kml":
            continue
        attachments = _attributes(obj).get("attachment", [])
        if not attachments:
            raise ValueError("A kml object requires an active attachment with data.")
        for attachment in attachments:
            if len(documents) >= kml.MAX_MEMBERS:
                raise ValueError("Combined export exceeds the source-dataset limit.")
            raw = kml.decode(attachment.get("data"))
            source = kml.Dataset(raw)
            input_size += len(raw)
            size += sum(len(value) for value in source.files.values()) if source.files else len(raw)
            coordinates += len(source.positions)
            placemarks += source.placemark_count
            if (
                input_size > kml.MAX_SIZE
                or size > kml.MAX_SIZE
                or coordinates > kml.MAX_COORDINATES
                or placemarks > kml.MAX_PLACEMARKS
            ):
                raise ValueError("Combined KML sources exceed the size, coordinate or Placemark limit.")
            documents.append((attachment, raw, source))
        for reference in _records(obj, "ObjectReference"):
            if reference.get("relationship_type") == "contains" and not boolean(reference.get("deleted"), "deleted"):
                identifier = reference.get("referenced_uuid")
                if isinstance(identifier, str):
                    represented.add(identifier)
    for obj in objects:
        if obj["name"] != "geolocation" or obj.get("uuid") in represented:
            continue
        point = _point(obj, len(points) + 1)
        if point is None:
            skipped += 1
            continue
        coordinates += 1
        placemarks += 1
        if coordinates > kml.MAX_COORDINATES or placemarks > kml.MAX_PLACEMARKS:
            raise ValueError("Combined KML exceeds the coordinate or Placemark limit.")
        points.append(point)
    if not documents and not points:
        raise ValueError("No KML/KMZ attachments or geolocations with coordinates to export.")
    if output_format == "kml":
        if not documents:
            payload = _document(points)
            kml.Dataset(payload)
        elif len(documents) == 1 and documents[0][2].format == "kml" and not points:
            payload = documents[0][1]
        else:
            raise ValueError(
                "Use kmz_export to preserve package assets or combine source datasets and additional locations."
            )
    elif len(documents) == 1 and documents[0][2].format == "kmz" and not points:
        payload = documents[0][1]
    else:
        files, links = {}, []
        for index, (attachment, _, source) in enumerate(documents, 1):
            prefix = f"datasets/{index:04d}/" if len(documents) > 1 or points else ""
            members = source.files or {_basename(attachment.get("value")): source.xml}
            entry = source.entry or next(iter(members))
            files.update((prefix + name, raw) for name, raw in members.items())
            links.append((attachment.get("value", "Dataset"), prefix + entry))
        if not documents or len(documents) > 1 or points:
            files = {"doc.kml": _document(points, links), **files}
        payload = _package(files)
        kml.Dataset(payload)
    result = {"response": [], "data": base64.b64encode(payload).decode("ascii")}
    if skipped:
        result["warnings"] = [f"Skipped {skipped} geolocation object(s) without coordinates."]
    return result


def handler(q, output_format):
    if q is False:
        return False
    try:
        request = json.loads(q, parse_float=Decimal)
        if not isinstance(request, dict) or "data" not in request:
            raise ValueError("Provide MISP events in data.")
        return export(request["data"], output_format)
    except (ValueError, TypeError, ET.ParseError, RecursionError, OverflowError) as error:
        return {"error": f"Unable to export {output_format.upper()}: {error}"}
