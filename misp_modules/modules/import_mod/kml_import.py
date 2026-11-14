"""Import preserved KML/KMZ datasets with linked geographic observations."""

import binascii
import hashlib
import json
from functools import lru_cache
from importlib import resources
from io import BytesIO
from xml.etree import ElementTree

from pymisp import MISPEvent, MISPObject

from misp_modules.lib import kml

mispattributes = {"inputSource": ["file", "paste"], "output": ["MISP objects"], "format": "misp_standard"}
moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "KML/KMZ Import",
    "description": "Import KML documents and KMZ packages with linked Point and gx:Track geolocations.",
    "module-type": ["import"],
    "logo": "",
    "requirements": ["PyMISP"],
    "features": (
        "Preserves original XML or the complete KMZ archive, including assets, styles and extensions. Extracts"
        " Point and gx:Track observations, metadata, counts and derived bounds. Resolves local KML NetworkLinks"
        " inside KMZ only, with cycle detection; never fetches remote resources. Retains altitude modes and source"
        " heights as context without assuming ellipsoid heights. Includes the kml object template for older"
        " PyMISP releases. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/kml_import.md)."
    ),
    "references": [
        "https://www.ogc.org/standards/kml/",
        "https://developers.google.com/kml/documentation/kmlreference",
    ],
    "input": "Base64-encoded KML XML or KMZ archive in data; optional filename.",
    "output": "MISP kml and geolocation objects in misp_standard format.",
}


@lru_cache(maxsize=1)
def _template():
    # Keep identical to MISP/misp-objects/objects/kml/definition.json.
    return json.loads(resources.files("misp_modules").joinpath("data", "kml", "definition.json").read_text())


def _parse(raw, filename):
    source = kml.Dataset(raw)
    filename = filename or "import." + source.format
    event = MISPEvent()
    dataset = MISPObject("kml", strict=True, standalone=False, misp_objects_template_custom=_template())

    def add(relation, value, **kwargs):
        dataset.add_attribute(relation, value=value, to_ids=False, **kwargs)

    add("filename", filename)
    add("attachment", filename, data=BytesIO(raw))
    add("source-format", source.format)
    add("mime-type", kml.MIME[source.format])
    add("size-in-bytes", len(raw))
    add("placemark-count", source.placemark_count)
    add("coordinate-count", len(source.positions))
    add("observation-count", len(source.points))
    for algorithm in ("md5", "sha1", "sha256"):
        add(algorithm, hashlib.new(algorithm, raw, usedforsecurity=False).hexdigest())
    for kind in sorted(source.geometry_types):
        add("geometry-type", kind)
    for relation, value in (("name", source.name), ("description-text", source.description)):
        if value:
            add(relation, value)
    if source.entry:
        add("entry-document", source.entry)
        add("archive-member-count", len(source.files))
    if source.positions:
        for axis, coordinate in enumerate(("longitude", "latitude")):
            values = [point[axis] for point in source.positions]
            add(f"min-{coordinate}", format(min(values), "f"))
            add(f"max-{coordinate}", format(max(values), "f"))
    times = [value for point in source.points for value in point["times"].values()]
    if times:
        add("start-time", min(times))
        add("end-time", max(times))
    context_size = 0
    for point in source.points:
        notes = json.dumps({**point["context"], **point["details"]}, sort_keys=True)
        context_size += len(notes.encode("utf-8"))
        if context_size > kml.MAX_SIZE:
            raise ValueError("Expanded observation context exceeds the 20 MiB limit.")
        location = MISPObject("geolocation", strict=True, standalone=False)
        context = f'KML Placemark {point["context"]["placemark"]} ({point["details"]["geometry"]})'
        location.comment = point["context"]["name"] or context
        fields = {
            "longitude": format(point["position"][0], "f"),
            "latitude": format(point["position"][1], "f"),
            "epsg": "4326",
            "spacial-reference": "WGS84 EPSG:4326",
            "text": notes,
            **point["times"],
        }
        for relation, value in fields.items():
            location.add_attribute(relation, value=value, to_ids=False)
        dataset.add_reference(location.uuid, "contains", context)
        event.add_object(location)
    event.add_object(dataset)
    result = {"results": json.loads(event.to_json())}
    if source.unresolved_links:
        result["warnings"] = [
            f"{source.unresolved_links} NetworkLink(s) retained without resolution; only local KML members inside KMZ"
            " are followed."
        ]
    return result


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected an import request object.")
        raw = kml.decode(request.get("data"))
        filename = request.get("filename")
        if filename is not None:
            if not isinstance(filename, str) or any(ord(char) < 32 for char in filename):
                raise ValueError("filename must be text without control characters.")
            filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
        return _parse(raw, filename)
    except (ValueError, TypeError, binascii.Error, ElementTree.ParseError, RecursionError, OverflowError) as error:
        return {"error": f"Unable to import KML/KMZ: {error}"}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
