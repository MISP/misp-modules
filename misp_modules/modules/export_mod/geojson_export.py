"""Export stored GeoJSON datasets and standalone geographic observations."""

import base64
import binascii
import json
from decimal import Decimal

from misp_modules.lib import geojson
from misp_modules.lib.indicator_list import boolean

moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "GeoJSON Export",
    "description": "Export geojson attachments and geolocation objects as GeoJSON.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Returns a single stored GeoJSON attachment unchanged, or combines datasets and standalone geolocation"
        " objects into a FeatureCollection. Retains geometries, feature properties and source metadata; excludes"
        " linked locations already represented by stored datasets. Includes contextual attributes regardless of"
        " to_ids and excludes deleted data. No external service or additional dependency is required. See the"
        " [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/geojson_export.md)."
    ),
    "references": ["https://www.rfc-editor.org/rfc/rfc7946.html"],
    "input": "MISP geojson and geolocation objects; include attachment data when fetching events.",
    "output": "Base64-encoded UTF-8 GeoJSON.",
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
            if not boolean(obj.get("deleted"), "deleted") and obj.get("name") in ("geojson", "geolocation"):
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


def _point(obj):
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
    coordinates = [
        geojson.number(value("longitude"), "longitude", -180, 180, strings=True),
        geojson.number(value("latitude"), "latitude", -90, 90, strings=True),
    ]
    if "altitude" in fields:
        coordinates.append(geojson.number(value("altitude"), "altitude", strings=True))
    properties = {}
    for relation in (
        "city",
        "country",
        "countrycode",
        "region",
        "address",
        "zipcode",
        "neighborhood",
        "accuracy-radius",
        "first-seen",
        "last-seen",
    ):
        if relation in fields:
            properties[relation] = value(relation)
    name = obj.get("comment") or properties.get("city") or properties.get("address")
    if name:
        properties["name"] = name
    if "text" in fields:
        properties["misp:text"] = [attribute.get("value") for attribute in fields["text"]]
    feature = {"type": "Feature", "geometry": {"type": "Point", "coordinates": coordinates}, "properties": properties}
    if obj.get("uuid"):
        if not isinstance(obj["uuid"], str):
            raise ValueError("Geolocation uuid must be text.")
        feature["id"] = obj["uuid"]
    return feature


def _combine(documents, points):
    features, sources = [], []
    for _, dataset in documents:
        root = dataset.document
        source = {"type": root["type"], "feature-start": len(features), "feature-count": len(dataset.features)}
        if root["type"] == "FeatureCollection":
            # Preserve collection-level foreign members and original bounds as source context.
            source["metadata"] = {key: value for key, value in root.items() if key not in ("type", "features")}
        sources.append(source)
        features.extend(dataset.features)
    features.extend(points)
    result = {"type": "FeatureCollection", "features": features}
    if sources:
        result["misp:source-datasets"] = sources
    return geojson.dumps(result).encode("utf-8")


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q, parse_float=Decimal)
        if not isinstance(request, dict) or "data" not in request:
            raise ValueError("Provide MISP events in data.")
        objects = list(_objects(request["data"]))
        documents, represented, points = [], set(), []
        size = positions = features = skipped = 0
        for obj in objects:
            if obj["name"] != "geojson":
                continue
            attachments = _attributes(obj).get("attachment", [])
            if not attachments:
                raise ValueError("A geojson object requires an active attachment with data.")
            for attachment in attachments:
                raw = geojson.decode(attachment.get("data"))
                dataset = geojson.Dataset(raw)
                size += len(raw)
                positions += len(dataset.positions)
                features += len(dataset.features)
                if size > geojson.MAX_SIZE or positions > geojson.MAX_POSITIONS or features > geojson.MAX_FEATURES:
                    raise ValueError("Combined GeoJSON exceeds the size, feature or position limit.")
                documents.append((raw, dataset))
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
            point = _point(obj)
            if point is None:
                skipped += 1
                continue
            positions += 1
            features += 1
            if positions > geojson.MAX_POSITIONS or features > geojson.MAX_FEATURES:
                raise ValueError("Combined GeoJSON exceeds the feature or position limit.")
            points.append(point)
        if not documents and not points:
            raise ValueError("No GeoJSON attachments or geolocations with coordinates to export.")
        payload = documents[0][0] if len(documents) == 1 and not points else _combine(documents, points)
        # Validate the combined document too, including its metadata and output byte size.
        geojson.Dataset(payload)
        result = {"response": [], "data": base64.b64encode(payload).decode("ascii")}
        if skipped:
            result["warnings"] = [f"Skipped {skipped} geolocation object(s) without coordinates."]
        return result
    except (ValueError, TypeError, binascii.Error, RecursionError, OverflowError) as error:
        return {"error": f"Unable to export GeoJSON: {error}"}


def introspection():
    return {
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "geojson",
        "responseType": "application/geo+json",
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
