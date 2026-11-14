"""Import GeoJSON datasets and point observations without network access."""

import binascii
import hashlib
import json
from io import BytesIO

from pymisp import MISPEvent, MISPObject

from misp_modules.lib import geojson

mispattributes = {"inputSource": ["file", "paste"], "output": ["MISP objects"], "format": "misp_standard"}
moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "GeoJSON Import",
    "description": "Import GeoJSON datasets with linked geolocation objects for point features.",
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP with the geojson and geolocation object templates"],
    "features": (
        "Preserves the original GeoJSON attachment, hashes, feature count, geometry types and derived bounds."
        " Point and MultiPoint geometries become linked geolocation objects. Lines, polygons, properties and"
        " foreign members remain in the attachment. All attributes have to_ids disabled. No network access or"
        " additional dependency is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/geojson_import.md)."
    ),
    "references": ["https://www.rfc-editor.org/rfc/rfc7946.html"],
    "input": "Base64-encoded UTF-8 GeoJSON in data; optional filename.",
    "output": "MISP geojson and geolocation objects in misp_standard format.",
}


def _parse(raw, filename):
    source = geojson.Dataset(raw)
    event = MISPEvent()
    dataset = MISPObject("geojson", strict=True, standalone=False)

    def add(relation, value, **kwargs):
        dataset.add_attribute(relation, value=value, to_ids=False, **kwargs)

    add("filename", filename)
    add("attachment", filename, data=BytesIO(raw))
    add("mime-type", "application/geo+json")
    add("size-in-bytes", len(raw))
    add("feature-count", len(source.features))
    for algorithm in ("md5", "sha1", "sha256"):
        add(algorithm, hashlib.new(algorithm, raw, usedforsecurity=False).hexdigest())
    for kind in sorted(source.geometry_types):
        add("geometry-types", kind)
    for key, relation in (("name", "name"), ("description", "description-text")):
        value = source.document.get(key)
        if isinstance(value, str) and value:
            add(relation, value)
    if source.positions:
        for axis, coordinate in enumerate(("longitude", "latitude")):
            values = [position[axis] for position in source.positions]
            add(f"min-{coordinate}", str(min(values)))
            add(f"max-{coordinate}", str(max(values)))
    contexts, context_size = {}, 0
    for position, feature, context in source.points:
        # MultiPoint and GeometryCollection children share properties. Bound their
        # total expansion into MISP attributes, and encode each feature only once.
        key = id(feature)
        if key not in contexts:
            context_data = {name: feature[name] for name in ("id", "properties") if name in feature}
            note = geojson.dumps(context_data)
            contexts[key] = (note, len(note.encode("utf-8")))
        note, note_size = contexts[key]
        context_size += note_size
        if context_size > geojson.MAX_SIZE:
            raise ValueError("Expanded point properties exceed the 20 MiB context limit.")
        location = MISPObject("geolocation", strict=True, standalone=False)
        location.comment = context
        fields = {
            "longitude": str(position[0]),
            "latitude": str(position[1]),
            "epsg": "4326",
            "spacial-reference": "WGS84 EPSG:4326",
        }
        if len(position) == 3:
            fields["altitude"] = str(position[2])
        # GeoJSON has no standard timestamp property. Preserve properties verbatim as analyst context.
        fields["text"] = note
        for relation, value in fields.items():
            location.add_attribute(relation, value=value, to_ids=False)
        dataset.add_reference(location.uuid, "contains", context)
        event.add_object(location)
    event.add_object(dataset)
    return {"results": json.loads(event.to_json())}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an import request object.")
        raw = geojson.decode(request.get("data"))
        filename = request.get("filename")
        if filename is None or filename == "":
            filename = "import.geojson"
        if not isinstance(filename, str) or any(ord(char) < 32 for char in filename):
            raise ValueError("filename must be text without control characters.")
        filename = filename.replace("\\", "/").rsplit("/", 1)[-1] or "import.geojson"
        return _parse(raw, filename)
    except (ValueError, TypeError, binascii.Error, RecursionError, OverflowError) as error:
        return {"error": f"Unable to import GeoJSON: {error}"}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
