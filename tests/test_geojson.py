"""GeoJSON interoperability, lossless round trips, validation and HTTP discovery."""

import base64
import hashlib
import json
from decimal import Decimal

import pytest
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.lib import geojson
from misp_modules.modules.export_mod import geojson_export as exporter
from misp_modules.modules.import_mod import geojson_import as importer

POINT = {"type": "Point", "coordinates": [6, 49, 123]}
RING = [[6, 49], [7, 49], [7, 50], [6, 49]]
GEOMETRIES = [
    POINT,
    {"type": "MultiPoint", "coordinates": [[0, 0], [-180, -90], [180, 90]]},
    {"type": "LineString", "coordinates": [[6, 49], [7, 50]]},
    {"type": "MultiLineString", "coordinates": [[[6, 49], [7, 50]], [[-1, -2], [1, 2]]]},
    {"type": "Polygon", "coordinates": [RING]},
    {"type": "MultiPolygon", "coordinates": [[RING], [RING]]},
    {"type": "GeometryCollection", "geometries": [POINT, {"type": "GeometryCollection", "geometries": [POINT]}]},
]


def feature(geometry=POINT, **kwargs):
    return {"type": "Feature", "geometry": geometry, "properties": {"name": "Camp", "time": "arbitrary"}, **kwargs}


COLLECTION = {
    "type": "FeatureCollection",
    "name": "Field observations",
    "description": "Mixed geometries",
    "bbox": [0, 0, 0, 0],
    "vendor": {"attribution": "Example source"},
    "features": [feature(geometry, id=index) for index, geometry in enumerate(GEOMETRIES)],
}
RAW = (json.dumps(COLLECTION, ensure_ascii=False, indent=2) + "\n").encode()


def request(raw=RAW, **kwargs):
    return json.dumps({"data": base64.b64encode(raw).decode(), **kwargs})


def imported(raw=RAW, **kwargs):
    result = importer.handler(request(raw, **kwargs))
    assert "error" not in result, result
    return result["results"]["Object"]


def fields(obj):
    result = {}
    for attribute in obj["Attribute"]:
        result.setdefault(attribute["object_relation"], []).append(attribute["value"])
    return result


def attr(relation, value, **kwargs):
    return {"object_relation": relation, "value": value, "to_ids": False, **kwargs}


def location(**kwargs):
    return {
        "name": "geolocation",
        "Attribute": [attr(k, v) for k, v in {"latitude": "49", "longitude": "6", **kwargs}.items()],
    }


def stored(raw=RAW, **kwargs):
    return {
        "name": "geojson",
        "Attribute": [attr("attachment", "field.geojson", data=base64.b64encode(raw).decode())],
        **kwargs,
    }


def export(objects=None, data=None):
    result = exporter.handler(json.dumps({"data": {"Object": objects} if data is None else data}))
    assert "error" not in result, result
    assert result["response"] == []
    raw = base64.b64decode(result["data"], validate=True)
    return raw, json.loads(raw, parse_float=Decimal), result


def test_import_dataset_and_point_mapping():
    objects = imported(filename="C:\\uploads\\field.geojson")
    dataset = next(obj for obj in objects if obj["name"] == "geojson")
    locations = [obj for obj in objects if obj["name"] == "geolocation"]
    assert len(locations) == 6  # No vertices from lines or polygon rings become standalone observations.
    values = fields(dataset)
    assert values["filename"] == ["field.geojson"]
    assert values["mime-type"] == ["application/geo+json"]
    assert values["size-in-bytes"] == [str(len(RAW))]
    assert values["feature-count"] == ["7"]
    assert values["name"] == [COLLECTION["name"]]
    assert values["description-text"] == [COLLECTION["description"]]
    assert set(values["geometry-types"]) == geojson.GEOMETRY_TYPES
    assert values["min-longitude"] == ["-180"] and values["max-longitude"] == ["180"]
    assert values["min-latitude"] == ["-90"] and values["max-latitude"] == ["90"]
    for algorithm in ("md5", "sha1", "sha256"):
        assert values[algorithm] == [hashlib.new(algorithm, RAW, usedforsecurity=False).hexdigest()]
    attachment = next(a for a in dataset["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == RAW
    assert fields(locations[0])["latitude"] == ["49"]
    assert fields(locations[0])["longitude"] == ["6"]
    assert fields(locations[0])["altitude"] == ["123"]
    assert fields(locations[0])["epsg"] == ["4326"]
    assert json.loads(fields(locations[0])["text"][0]) == {
        "id": 0,
        "properties": COLLECTION["features"][0]["properties"],
    }
    assert "first-seen" not in fields(locations[0])
    assert {r["referenced_uuid"] for r in dataset["ObjectReference"]} == {obj["uuid"] for obj in locations}
    assert all(r["relationship_type"] == "contains" for r in dataset["ObjectReference"])
    assert all(a["to_ids"] is False for obj in objects for a in obj["Attribute"])
    event = MISPEvent()
    event.from_dict(info="Imported GeoJSON", Object=objects)
    assert all(obj._validate() for obj in event.objects)


@pytest.mark.parametrize("root", [*GEOMETRIES, feature(), COLLECTION])
def test_all_root_types_round_trip_unchanged(root):
    raw = (json.dumps(root, indent=3) + "\n").encode()
    assert export(imported(raw))[0] == raw


@pytest.mark.parametrize(
    "root",
    [
        {"type": "FeatureCollection", "features": []},
        feature(None, properties=None),
        *({"type": kind, "coordinates": []} for kind in geojson.GEOMETRY_TYPES - {"GeometryCollection"}),
        {"type": "GeometryCollection", "geometries": []},
    ],
)
def test_empty_geometries_and_null_features(root):
    raw = json.dumps(root).encode()
    objects = imported(raw)
    assert len(objects) == 1
    assert "min-latitude" not in fields(objects[0])
    assert export(objects)[0] == raw


def test_precise_coordinates_properties_and_unicode_survive_combining():
    raw = b'{"type":"Feature","geometry":{"type":"Point","coordinates":[6.123456789012345678901,49.123456789012345678901]},"properties":{"value":0.123456789012345678901,"name":"Caf\\u00e9"}}'
    objects = imported(raw)
    assert fields(objects[0])["longitude"] == ["6.123456789012345678901"]
    payload, combined, _ = export([*objects, location(longitude="1.123456789012345678901")])
    assert b"6.123456789012345678901" in payload
    assert b"1.123456789012345678901" in payload
    assert combined["features"][0] == json.loads(raw, parse_float=Decimal)


def test_numeric_misp_values_preserve_decimal_precision():
    # JSON numeric values must retain the same precision as MISP's usual string values.
    raw = (
        '{"data":{"Object":[{"name":"geolocation","Attribute":['
        '{"object_relation":"latitude","value":49.123456789012345678901},'
        '{"object_relation":"longitude","value":6.123456789012345678901}]}]}}'
    )
    result = exporter.handler(raw)
    assert "error" not in result, result
    payload = base64.b64decode(result["data"])
    assert b"49.123456789012345678901" in payload and b"6.123456789012345678901" in payload


def test_merge_keeps_features_and_collection_metadata_and_avoids_duplicates():
    objects = imported()
    extra = location(altitude="5", **{"first-seen": "2026-11-14T10:00:00Z", "text": "Analyst note"})
    extra["uuid"], extra["comment"] = "location-id", "New point"
    _, combined, _ = export([*objects, stored(json.dumps(POINT).encode()), extra])
    assert len(combined["features"]) == 9
    assert combined["features"][:7] == COLLECTION["features"]
    assert combined["features"][7]["geometry"] == POINT
    point = combined["features"][-1]
    assert point["geometry"]["coordinates"] == [6, 49, 5]
    assert point["properties"] == {
        "first-seen": "2026-11-14T10:00:00Z",
        "misp:text": ["Analyst note"],
        "name": "New point",
    }
    assert point["id"] == "location-id"
    assert "bbox" not in combined
    context = combined["misp:source-datasets"][0]
    assert context["feature-start"] == 0 and context["feature-count"] == 7
    assert context["metadata"] == {k: v for k, v in COLLECTION.items() if k not in ("type", "features")}
    assert export(imported(geojson.dumps(combined).encode()))[1] == combined


def test_standalone_locations_envelopes_zero_and_warning():
    obj = location(latitude="0", longitude="0", altitude="0", city="Example")
    _, result, response = export(
        data=[{"Event": {"Object": [obj]}}, {"Object": [{"name": "geolocation", "Attribute": []}]}]
    )
    assert result["features"][0]["geometry"]["coordinates"] == [0, 0, 0]
    assert result["features"][0]["properties"]["name"] == "Example"
    assert response["warnings"] == ["Skipped 1 geolocation object(s) without coordinates."]


@pytest.mark.parametrize("level", ["event", "envelope", "object", "attribute", "reference"])
@pytest.mark.parametrize("flag", [True, 1, "true", "1"])
def test_deleted_records(level, flag):
    first, second = location(), location(latitude="10")
    second["uuid"] = "second"
    document = stored(
        json.dumps(POINT).encode(), ObjectReference=[{"relationship_type": "contains", "referenced_uuid": "second"}]
    )
    data = {"Event": {"Object": [document, first, second]}}
    if level == "event":
        data["Event"]["deleted"] = flag
    elif level == "envelope":
        data["deleted"] = flag
    elif level == "object":
        first["deleted"] = flag
    elif level == "attribute":
        # Deleted invalid coordinates must not poison an otherwise valid point.
        first["Attribute"].append(attr("latitude", "bad", deleted=flag))
    else:
        document["ObjectReference"][0]["deleted"] = flag
    result = exporter.handler(json.dumps({"data": data}))
    if level in ("event", "envelope"):
        assert "error" in result
    else:
        features = json.loads(base64.b64decode(result["data"]))
        expected = {"object": 1, "attribute": 2, "reference": 3}[level]
        assert len(features.get("features", [features])) == expected


@pytest.mark.parametrize(
    "root",
    [
        None,
        [],
        {},
        {"type": "FeatureCollection", "features": {}},
        {"type": "FeatureCollection", "features": [POINT]},
        {"type": "Feature", "geometry": POINT},
        feature(properties=[]),
        feature(id=True),
        {"type": "Point", "coordinates": [49]},
        {"type": "Point", "coordinates": [0, 91]},
        {"type": "Point", "coordinates": [181, 0]},
        {"type": "Point", "coordinates": ["6", 49]},
        {"type": "Point", "coordinates": [False, 0]},
        {"type": "Point", "coordinates": [0, 0, 0, 0]},
        {"type": "LineString", "coordinates": [[0, 0]]},
        {"type": "MultiPoint", "coordinates": [[0]]},
        {"type": "Polygon", "coordinates": [[[0, 0], [1, 1], [2, 2]]]},
        {"type": "Polygon", "coordinates": [[[0, 0], [1, 1], [2, 2], [3, 3]]]},
        {"type": "GeometryCollection", "geometries": [None]},
        {"type": "Point", "coordinates": [0, 0], "crs": {"type": "name"}},
        {"type": "FeatureCollection", "features": [feature()], "crs": None},
    ],
)
def test_invalid_documents_reject_import_and_export(root):
    raw = json.dumps(root).encode()
    assert "error" in importer.handler(request(raw))
    assert "error" in exporter.handler(json.dumps({"data": {"Object": [stored(raw)]}}))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not JSON",
        b"\xff",
        b'{"type":"Point","type":"Polygon","coordinates":[]}',
        b'{"type":"Point","coordinates":[NaN,0]}',
        b'{"type":"Point","coordinates":[Infinity,0]}',
        b'{"type":"Point","coordinates":[0,0,1e999999]}',
        b'{"type":"Point","coordinates":[0,0],"properties":{"bad":NaN}}',
        b'{"type":"FeatureCollection","features":[],"foreign":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}",
    ],
)
def test_invalid_json_and_recursion(raw):
    assert "error" in importer.handler(request(raw))
    assert "error" in exporter.handler(json.dumps({"data": {"Object": [stored(raw)]}}))


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"data": 42}', '{"data":"%%%"}'])
@pytest.mark.parametrize("module", [importer, exporter])
def test_invalid_envelopes(module, raw):
    assert "error" in module.handler(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"latitude": "91"},
        {"longitude": "181"},
        {"longitude": "NaN"},
        {"altitude": "Infinity"},
        {"latitude": True},
        {"epsg": "3857"},
        {"spacial-reference": "Mercator EPSG:3857"},
    ],
)
def test_invalid_standalone_locations(changes):
    assert "error" in exporter.handler(json.dumps({"data": {"Object": [location(**changes)]}}))


def test_missing_duplicate_coordinates_and_missing_attachment_data():
    objects = [
        {"name": "geolocation", "Attribute": [attr("latitude", "0")]},
        {"name": "geolocation", "Attribute": [attr("latitude", "0"), attr("latitude", "1"), attr("longitude", "0")]},
        {"name": "geojson", "Attribute": []},
        {"name": "geojson", "Attribute": [attr("attachment", "missing.geojson")]},
        {"name": "geojson", "Attribute": [attr("attachment", "missing.geojson", deleted=True)]},
    ]
    for obj in objects:
        assert "error" in exporter.handler(json.dumps({"data": {"Object": [obj]}}))


@pytest.mark.parametrize(
    "limit,value", [("MAX_SIZE", 10), ("MAX_FEATURES", 1), ("MAX_POSITIONS", 1), ("MAX_DEPTH", 2), ("MAX_NODES", 10)]
)
def test_resource_limits(monkeypatch, limit, value):
    monkeypatch.setattr(geojson, limit, value)
    assert "error" in importer.handler(request())
    assert "error" in exporter.handler(json.dumps({"data": {"Object": [stored()]}}))


def test_combined_limits(monkeypatch):
    monkeypatch.setattr(geojson, "MAX_POSITIONS", 1)
    for objects in ([stored(json.dumps(POINT).encode()), location()], [location(), location()]):
        assert "error" in exporter.handler(json.dumps({"data": {"Object": objects}}))


def test_utf8_bom_preservation():
    raw = b"\xef\xbb\xbf" + RAW
    assert export(imported(raw))[0] == raw


class TestGeoJSONHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {
                "geojson_import": importer,
                "type:geojson_import": "import_mod",
                "geojson_export": exporter,
                "type:geojson_export": "export_mod",
            }
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_import_and_export(self):
        descriptors = json.loads(self.fetch("/modules").body)
        assert len(descriptors) == 2
        assert importer.handler() is exporter.handler() is False
        assert importer.introspection()["format"] == "misp_standard"
        assert exporter.introspection()["responseType"] == "application/geo+json"
        response = self.fetch("/query", method="POST", body=request(module="geojson_import"))
        assert response.code == 200
        data = json.loads(response.body)["results"]
        response = self.fetch("/query", method="POST", body=json.dumps({"module": "geojson_export", "data": data}))
        assert response.code == 200
        assert base64.b64decode(json.loads(response.body)["data"]) == RAW


@pytest.mark.parametrize("filename", [0, False, [], {}, 42, "bad\nname.geojson"])
def test_invalid_filenames(filename):
    assert "error" in importer.handler(request(filename=filename))


def test_expanded_multipoint_context_is_bounded(monkeypatch):
    root = feature({"type": "MultiPoint", "coordinates": [[0, 0]] * 30}, properties={"note": "x" * 1000})
    raw = json.dumps(root).encode()
    monkeypatch.setattr(geojson, "MAX_SIZE", 4000)
    assert len(raw) < geojson.MAX_SIZE
    assert "context limit" in importer.handler(request(raw))["error"]


def test_false_deletion_flags_and_legacy_wrapper():
    obj = location()
    obj["deleted"] = "false"
    for attribute in obj["Attribute"]:
        attribute["deleted"] = "0"
    _, result, _ = export(data={"Event": {"deleted": "false"}, "Object": [obj]})
    assert len(result["features"]) == 1
