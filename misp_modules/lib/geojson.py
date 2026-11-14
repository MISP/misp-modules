"""Bounded, network-free GeoJSON parsing shared by import and export."""

import base64
import json
from decimal import Decimal, InvalidOperation

MAX_SIZE = 20 * 1024 * 1024
MAX_FEATURES = 10_000
MAX_POSITIONS = 10_000
MAX_DEPTH = 32
MAX_NODES = 200_000
GEOMETRY_TYPES = {
    "Point",
    "MultiPoint",
    "LineString",
    "MultiLineString",
    "Polygon",
    "MultiPolygon",
    "GeometryCollection",
}


def number(value, name, minimum=None, maximum=None, strings=False):
    if isinstance(value, bool) or not isinstance(
        value, (int, float, Decimal, str) if strings else (int, float, Decimal)
    ):
        raise ValueError(f"Invalid {name}.")
    try:
        result = Decimal(str(value))
    except InvalidOperation:
        raise ValueError(f"Invalid {name}.") from None
    if not result.is_finite() or minimum is not None and result < minimum or maximum is not None and result > maximum:
        raise ValueError(f"Invalid {name}.")
    if len(str(value)) > 256 or abs(result.as_tuple().exponent) > 256:
        raise ValueError(f"{name} exceeds supported numeric precision.")
    return result


def _members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON member: {key}.")
        result[key] = value
    return result


def _constant(value):
    raise ValueError(f"Non-finite JSON number: {value}.")


def _check_tree(root):
    stack, count = [(root, 0)], 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise ValueError("GeoJSON exceeds the nesting or node limit.")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
        elif isinstance(value, (int, Decimal)) and not isinstance(value, bool):
            number(value, "JSON number")


def decode(encoded):
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("Provide base64-encoded GeoJSON in data; include attachments when fetching events.")
    if len(encoded) > 4 * ((MAX_SIZE + 2) // 3):
        raise ValueError("GeoJSON exceeds the 20 MiB size limit.")
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > MAX_SIZE:
        raise ValueError("GeoJSON exceeds the 20 MiB size limit.")
    return raw


def dumps(value):
    """Encode decimal JSON numbers without converting coordinates through binary floats."""
    if isinstance(value, Decimal):
        return str(number(value, "JSON number"))
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k) + ":" + dumps(v) for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(dumps(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=True, allow_nan=False)


class Dataset:
    def __init__(self, raw):
        if len(raw) > MAX_SIZE:
            raise ValueError("GeoJSON exceeds the 20 MiB size limit.")
        self.document = json.loads(
            raw.decode("utf-8-sig"), parse_float=Decimal, parse_constant=_constant, object_pairs_hook=_members
        )
        _check_tree(self.document)
        self.positions, self.points, self.geometry_types = [], [], set()
        root = self.document
        self._object(root)
        if root.get("type") == "FeatureCollection":
            self.features = self._array(root.get("features"))
        elif root.get("type") == "Feature":
            self.features = [root]
        elif root.get("type") in GEOMETRY_TYPES:
            self.features = [{"type": "Feature", "geometry": root, "properties": {}}]
        else:
            raise ValueError("Expected a GeoJSON geometry, Feature or FeatureCollection.")
        if len(self.features) > MAX_FEATURES:
            raise ValueError("GeoJSON exceeds the 10,000-feature limit.")
        for index, feature in enumerate(self.features, 1):
            self._object(feature)
            if feature.get("type") != "Feature" or "geometry" not in feature or "properties" not in feature:
                raise ValueError("Features require type, geometry and properties.")
            if feature["properties"] is not None and not isinstance(feature["properties"], dict):
                raise ValueError("Feature properties must be an object or null.")
            if "id" in feature and (
                isinstance(feature["id"], bool) or not isinstance(feature["id"], (str, int, Decimal))
            ):
                raise ValueError("Feature id must be a string or number.")
            if feature["geometry"] is not None:
                self._geometry(feature["geometry"], feature, f"GeoJSON feature {index}")

    @staticmethod
    def _object(value):
        if not isinstance(value, dict):
            raise ValueError("GeoJSON objects must be JSON objects.")
        if "crs" in value:
            raise ValueError("Legacy crs members are unsupported; supply RFC 7946 WGS84 coordinates.")

    @staticmethod
    def _array(value):
        if not isinstance(value, list):
            raise ValueError("Expected a GeoJSON array.")
        return value

    def _position(self, value):
        self._array(value)
        if len(value) not in (2, 3):
            raise ValueError("Positions require longitude, latitude and optional altitude.")
        number(value[0], "longitude", -180, 180)
        number(value[1], "latitude", -90, 90)
        if len(value) == 3:
            number(value[2], "altitude")
        self.positions.append(value)
        if len(self.positions) > MAX_POSITIONS:
            raise ValueError("GeoJSON exceeds the 10,000-position limit.")

    def _line(self, value, ring=False):
        self._array(value)
        if value and len(value) < (4 if ring else 2):
            raise ValueError("Linear rings require four positions; lines require two.")
        for position in value:
            self._position(position)
        if ring and value and value[0] != value[-1]:
            raise ValueError("Polygon rings must be closed.")

    def _polygon(self, value):
        for ring in self._array(value):
            self._line(ring, ring=True)

    def _geometry(self, geometry, feature, context):
        self._object(geometry)
        kind = geometry.get("type")
        if kind not in GEOMETRY_TYPES:
            raise ValueError("Unsupported GeoJSON geometry type.")
        self.geometry_types.add(kind)
        if kind == "GeometryCollection":
            for index, child in enumerate(self._array(geometry.get("geometries")), 1):
                self._geometry(child, feature, f"{context} geometry {index}")
            return
        coordinates = self._array(geometry.get("coordinates"))
        if not coordinates:
            return  # RFC 7946 permits treating empty coordinate arrays as null geometries.
        if kind == "Point":
            self._position(coordinates)
            self.points.append((coordinates, feature, context))
        elif kind == "MultiPoint":
            for index, position in enumerate(coordinates, 1):
                self._position(position)
                self.points.append((position, feature, f"{context} point {index}"))
        elif kind == "LineString":
            self._line(coordinates)
        elif kind == "MultiLineString":
            for line in coordinates:
                self._line(line)
        elif kind == "Polygon":
            self._polygon(coordinates)
        elif kind == "MultiPolygon":
            for polygon in coordinates:
                self._polygon(polygon)
