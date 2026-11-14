"""KML semantics, KMZ asset/link preservation, bounded parsing and HTTP round trips."""

import base64
import copy
import hashlib
import json
import socket
import stat
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

import pytest
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.lib import kml, kml_exporter
from misp_modules.modules.export_mod import kml_export, kmz_export
from misp_modules.modules.import_mod import kml_import

RAW = (Path(__file__).parent / "fixtures/kml/mixed.kml").read_bytes()
NS = {"k": kml.KML_NS, "gx": kml.GX[1:-1]}
SIMPLE = (
    b'<kml xmlns="http://www.opengis.net/kml/2.2"><Placemark'
    b' id="shared"><Point><coordinates>6,49,120</coordinates></Point></Placemark></kml>'
)


def package(files=None):
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        for name, raw in (
            files or {"doc.kml": RAW, "icons/pin.png": b"icon bytes", "images/overlay.png": b"overlay bytes"}
        ).items():
            archive.writestr(name, raw)
    return stream.getvalue()


def request(raw=RAW, **kwargs):
    return json.dumps({"data": base64.b64encode(raw).decode(), **kwargs})


def imported(raw=RAW, **kwargs):
    result = kml_import.handler(request(raw, **kwargs))
    assert "error" not in result, result
    return result


def dataset(result):
    return next(obj for obj in result["results"]["Object"] if obj["name"] == "kml")


def locations(result):
    return [obj for obj in result["results"]["Object"] if obj["name"] == "geolocation"]


def fields(obj):
    result = {}
    for attribute in obj["Attribute"]:
        result.setdefault(attribute["object_relation"], []).append(attribute["value"])
    return result


def attr(relation, value, **kwargs):
    return {"object_relation": relation, "value": value, "to_ids": False, **kwargs}


def stored(raw=RAW, filename="source.kml", **kwargs):
    return {"name": "kml", "Attribute": [attr("attachment", filename, data=base64.b64encode(raw).decode())], **kwargs}


def location(**values):
    return {
        "name": "geolocation",
        "Attribute": [attr(k, v) for k, v in {"latitude": "49", "longitude": "6", **values}.items()],
    }


def export(objects=None, data=None, module=kml_export):
    result = module.handler(json.dumps({"data": {"Object": objects} if data is None else data}))
    assert "error" not in result, result
    assert result["response"] == []
    return base64.b64decode(result["data"], validate=True), result


def contents(raw):
    with ZipFile(BytesIO(raw)) as archive:
        assert archive.testzip() is None
        return {name: archive.read(name) for name in archive.namelist()}


def test_complete_dataset_mapping_and_height_semantics():
    result = imported(filename="C:\\uploads\\map.kml")
    source, points = dataset(result), locations(result)
    values = fields(source)
    assert values["filename"] == ["map.kml"]
    assert values["source-format"] == ["kml"]
    assert values["mime-type"] == [kml.MIME["kml"]]
    assert values["name"] == ["Field map"] and values["description-text"] == ["Sites & tracks"]
    assert values["placemark-count"] == ["5"] and values["coordinate-count"] == ["16"]
    assert values["observation-count"] == ["6"] and len(points) == 6
    assert set(values["geometry-type"]) == {
        "Point",
        "MultiGeometry",
        "LineString",
        "Polygon",
        "LinearRing",
        "gx:Track",
        "gx:MultiTrack",
        "Model",
    }
    assert values["min-latitude"] == ["-90"] and values["max-latitude"] == ["90"]
    assert values["min-longitude"] == ["-180"] and values["max-longitude"] == ["180"]
    assert values["start-time"] == ["2026-01-01T10:00:00+00:00"]
    assert values["end-time"] == ["2026-12-01T00:00:00+00:00"]
    assert fields(points[0])["longitude"] == ["6.123456789012345678901"]
    assert fields(points[0])["epsg"] == ["4326"]
    assert fields(points[0])["first-seen"] == fields(points[0])["last-seen"] == ["2026-01-01T10:00:00+00:00"]
    context = json.loads(fields(points[0])["text"][0])
    assert context["name"] == "Café & camp" and context["folder-path"] == ["Field map", "Sites"]
    assert context["id"] == "camp" and context["source-altitude"] == "120.5" and context["altitude-mode"] == "absolute"
    assert "not geometry" in context["extended-data"]
    assert all("altitude" not in fields(point) for point in points)
    assert "first-seen" not in fields(points[1]) and "last-seen" in fields(points[1])
    assert json.loads(fields(points[2])["text"][0])["altitude-mode"] == "relativeToSeaFloor"
    assert json.loads(fields(points[-1])["text"][0])["altitude-mode"] == "absolute"
    assert json.loads(fields(points[4])["text"][0])["sample"] == 3
    assert {ref["referenced_uuid"] for ref in source["ObjectReference"]} == {point["uuid"] for point in points}
    assert all(attr["to_ids"] is False for obj in result["results"]["Object"] for attr in obj["Attribute"])
    event = MISPEvent()
    event.from_dict(info="KML", **copy.deepcopy(result["results"]))
    for obj in event.objects:
        if obj.name == "kml":
            obj._definition = kml_import._template()
        assert obj._validate()
    assert export(data=result["results"])[0] == RAW


def test_kmz_original_bytes_assets_and_hashes():
    raw = package()
    result = imported(raw)
    values = fields(dataset(result))
    assert values["filename"] == ["import.kmz"] and values["entry-document"] == ["doc.kml"]
    assert values["archive-member-count"] == ["3"] and values["source-format"] == ["kmz"]
    assert values["mime-type"] == [kml.MIME["kmz"]]
    for algorithm in ("md5", "sha1", "sha256"):
        assert values[algorithm] == [hashlib.new(algorithm, raw, usedforsecurity=False).hexdigest()]
    assert export(data=result["results"], module=kmz_export)[0] == raw
    assert len(locations(result)) == 6


@pytest.mark.parametrize("namespace", ["", kml.KML_NS, "http://earth.google.com/kml/2.1"])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_legacy_namespaces_and_xml_encodings_preserved(namespace, encoding):
    text = '<?xml version="1.0" encoding="' + encoding + '"?>' + SIMPLE.decode().replace(kml.KML_NS, namespace)
    raw = text.encode(encoding)
    assert export(data=imported(raw)["results"])[0] == raw


def test_prefixed_namespaces_vendor_qnames_and_styles_preserved():
    raw = (
        b'<k:kml xmlns:k="http://www.opengis.net/kml/2.2" xmlns:v="urn:vendor"><k:Document><k:ExtendedData><v:record'
        b' kind="v:Type">v:Value</v:record></k:ExtendedData><k:Placemark><k:Point><k:coordinates>1,2</k:coordinates></k:Point></k:Placemark></k:Document></k:kml>'
    )
    assert len(locations(imported(raw))) == 1
    output, _ = export([stored(raw), location()], module=kmz_export)
    assert contents(output)["datasets/0001/source.kml"] == raw


def test_combined_packages_keep_id_scopes_and_asset_paths_and_round_trip():
    first = package()
    second = package({"doc.kml": RAW, "icons/pin.png": b"other icon", "images/overlay.png": b"other overlay"})
    original = imported(first)
    output, _ = export(
        data=[
            original["results"],
            {"Object": [stored(second, filename="second.kmz"), location(longitude="0", latitude="0")]},
        ],
        module=kmz_export,
    )
    files = contents(output)
    assert next(iter(files)) == "doc.kml"
    assert files["datasets/0001/doc.kml"] == files["datasets/0002/doc.kml"] == RAW
    assert files["datasets/0001/icons/pin.png"] == b"icon bytes"
    assert files["datasets/0002/icons/pin.png"] == b"other icon"
    index = ET.fromstring(files["doc.kml"])
    assert len(index.findall("k:Document/k:NetworkLink", NS)) == 2
    assert len(index.findall("k:Document/k:Placemark", NS)) == 1
    assert len(locations(imported(output))) == 13  # Two source datasets plus one standalone point.
    assert export(data=imported(output)["results"], module=kmz_export)[0] == output


def test_kml_to_kmz_keeps_original_xml_and_filename():
    output, _ = export([stored(RAW, filename="Café map.kml")], module=kmz_export)
    assert contents(output) == {"Café map.kml": RAW}
    assert len(locations(imported(output))) == 6


def linked(href, base=""):
    base_attr = ' xml:base="' + base + '"' if base else ""
    return (
        "<kml"
        f' xmlns="{kml.KML_NS}"{base_attr}><Document><NetworkLink><Link><href>{href}</href></Link></NetworkLink></Document></kml>'
        .encode()
    )


def test_local_networklinks_are_bounded_cycle_safe_and_honor_xml_base():
    raw = package(
        {
            "doc.kml": linked("child.kml", "layers/"),
            "layers/child.kml": linked("../point.kml"),
            "point.kml": SIMPLE.replace(
                b"</Placemark>", b"</Placemark><NetworkLink><Link><href>doc.kml</href></Link></NetworkLink>"
            ),
        }
    )
    result = imported(raw)
    assert len(locations(result)) == 1
    assert json.loads(fields(locations(result)[0])["text"][0])["document"] == "point.kml"


@pytest.mark.parametrize(
    "href",
    [
        "https://example.invalid/evil.kml",
        "file:///tmp/evil.kml",
        "../escape.kml",
        "%2e%2e/escape.kml",
        "missing.kml",
        "nested.kmz",
        "other.kml#feature",
    ],
)
def test_unsupported_links_are_retained_without_network_access(monkeypatch, href):
    def forbidden(*args, **kwargs):
        raise AssertionError("Network access is forbidden")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    raw = package({"doc.kml": linked(href)})
    result = imported(raw)
    assert locations(result) == [] and result["warnings"]
    assert export(data=result["results"], module=kmz_export)[0] == raw


@pytest.mark.parametrize("raw", [b"<kml/>", b'<kml xmlns="http://www.opengis.net/kml/2.2"><Document/></kml>'])
def test_empty_datasets(raw):
    assert locations(imported(raw)) == []
    assert export(data=imported(raw)["results"])[0] == raw


@pytest.mark.parametrize(
    "value,mapped",
    [
        ("2026", False),
        ("2026-02", False),
        ("2026-02-28", False),
        ("2026-02-28T10:00:00", False),
        ("2026-02-28T10:00:00.1234567Z", False),
        ("2026-02-28T10:00:00.123456Z", True),
        ("2026-02-28T24:00:00Z", True),
    ],
)
def test_partial_naive_and_high_precision_times_retained_without_invention(value, mapped):
    raw = SIMPLE.replace(b"<Point>", f"<TimeStamp><when>{value}</when></TimeStamp><Point>".encode())
    point = fields(locations(imported(raw))[0])
    assert ("first-seen" in point) is mapped
    assert json.loads(point["text"][0])["time"]["when"] == value


def test_geolocation_export_zero_values_time_interval_and_wgs84_height_context():
    point = location(
        latitude="0",
        longitude="0",
        altitude="0",
        city="Origin",
        **{"first-seen": "2026-01-01T11:00:00+01:00", "last-seen": "2026-01-02T10:00:00Z", "text": "<b>plain note</b>"},
    )
    output, _ = export([point])
    tree = ET.fromstring(output)
    assert tree.find(".//k:Point/k:coordinates", NS).text == "0,0"
    assert tree.find('.//k:Data[@name="misp:altitude-wgs84"]/k:value', NS).text == "0"
    assert tree.find(".//k:TimeSpan/k:begin", NS).text == "2026-01-01T10:00:00Z"
    assert tree.find(".//k:name", NS) is not None
    assert tree.find(".//k:Placemark/k:description", NS).text == "&lt;b&gt;plain note&lt;/b&gt;"
    assert len(locations(imported(output))) == 1
    assert len(locations(imported(export([point], module=kmz_export)[0]))) == 1


def test_numeric_precision_export_and_coordinate_only_warning():
    raw = '{"data":{"Object":[{"name":"geolocation","Attribute":[{"object_relation":"longitude","value":6.123456789012345678901},{"object_relation":"latitude","value":"49"}]}]}}'
    result = kml_export.handler(raw)
    assert b"6.123456789012345678901,49" in base64.b64decode(result["data"])
    _, result = export([location(), {"name": "geolocation", "Attribute": []}])
    assert result["warnings"]


@pytest.mark.parametrize(
    "objects", [[stored(package(), filename="source.kmz")], [stored(), stored()], [stored(), location()]]
)
def test_kml_export_directs_asset_and_combination_cases_to_kmz(objects):
    result = kml_export.handler(json.dumps({"data": {"Object": objects}}))
    assert "kmz_export" in result["error"]
    assert "data" not in result


@pytest.mark.parametrize(
    "body",
    [
        "<Point><coordinates>181,0</coordinates></Point>",
        "<Point><coordinates>0,91</coordinates></Point>",
        "<Point><coordinates>NaN,0</coordinates></Point>",
        "<Point><coordinates>1,2,Infinity</coordinates></Point>",
        "<Point><coordinates>1,2,3,4</coordinates></Point>",
        "<Point><coordinates>1</coordinates></Point>",
        "<Point><coordinates>1,2 3,4</coordinates></Point>",
        "<Point/>",
        "<Point><altitudeMode>bad</altitudeMode><coordinates>1,2</coordinates></Point>",
        "<LineString><coordinates>1,2</coordinates></LineString>",
        "<LinearRing><coordinates>1,2 2,3 3,4 4,5</coordinates></LinearRing>",
        "<Polygon/>",
        "<gx:Track><when>2026</when></gx:Track>",
        "<gx:Track><when>2026</when><gx:coord>1 2</gx:coord></gx:Track>",
        "<gx:Track><when>2026</when><gx:coord>1 2 3</gx:coord><gx:angles/><gx:angles/></gx:Track>",
        "<TimeStamp><when>2026-02-30T10:00:00Z</when></TimeStamp>",
        "<TimeStamp><when>2026-01-01T24:00:01Z</when></TimeStamp>",
        "<TimeSpan><begin>2026-02-01T00:00:00Z</begin><end>2026-01-01T00:00:00Z</end></TimeSpan>",
    ],
)
def test_invalid_geometries_and_times_reject_entire_dataset(body):
    raw = f'<kml xmlns="{kml.KML_NS}" xmlns:gx="{kml.GX[1:-1]}"><Placemark>{body}</Placemark></kml>'.encode()
    assert "error" in kml_import.handler(request(raw))
    assert "error" in kmz_export.handler(json.dumps({"data": {"Object": [stored(raw)]}}))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not XML",
        b"<kml",
        b"<other/>",
        b'<kml xmlns="urn:wrong"/>',
        b'<!DOCTYPE kml [<!ENTITY x "boom">]><kml>&x;</kml>',
        '<!DOCTYPE kml SYSTEM "file:///etc/passwd"><kml/>'.encode("utf-16"),
        b"PK\x03\x04bad",
        ("<kml>" + "<Folder>" * 33 + "</Folder>" * 33 + "</kml>").encode(),
    ],
)
def test_invalid_xml_dtds_and_depth(raw):
    assert "error" in kml_import.handler(request(raw))


@pytest.mark.parametrize(
    "name", ["../escape", "/absolute", "C:/drive", "dir\\file", "dir/../file", "./file", "dir//file"]
)
def test_unsafe_archive_member_paths(name):
    assert "error" in kml_import.handler(request(package({"doc.kml": SIMPLE, name: b"x"})))


def test_archive_duplicates_case_ambiguity_symlinks_and_unsupported_compression():
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_STORED) as archive:
        archive.writestr("doc.kml", SIMPLE)
        archive.writestr("DOC.KML", SIMPLE)
    assert "error" in kml_import.handler(request(stream.getvalue()))
    stream = BytesIO()
    with ZipFile(stream, "w") as archive:
        archive.writestr("doc.kml", SIMPLE)
        info = ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, b"../../outside")
    assert "error" in kml_import.handler(request(stream.getvalue()))
    stream = BytesIO()
    with ZipFile(stream, "w", compression=12) as archive:
        archive.writestr("doc.kml", SIMPLE)
    assert "error" in kml_import.handler(request(stream.getvalue()))


@pytest.mark.parametrize("files", [{"nested/doc.kml": SIMPLE}, {"a.kml": SIMPLE, "b.kml": SIMPLE}, {"icon.png": b"x"}])
def test_missing_or_ambiguous_entry_document(files):
    assert "error" in kml_import.handler(request(package(files)))


@pytest.mark.parametrize(
    "changes",
    [
        {"latitude": "91"},
        {"longitude": "NaN"},
        {"altitude": "Infinity"},
        {"epsg": "3857"},
        {"first-seen": "2026-01-01"},
        {"first-seen": "2026-01-01T10:00:00"},
        {"text": "bad\x01text"},
    ],
)
def test_invalid_standalone_locations(changes):
    for module in (kml_export, kmz_export):
        assert "error" in module.handler(json.dumps({"data": {"Object": [location(**changes)]}}))


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"data":42}', '{"data":"%%%"}'])
@pytest.mark.parametrize("module", [kml_import, kml_export, kmz_export])
def test_invalid_envelopes(module, raw):
    assert "error" in module.handler(raw)


@pytest.mark.parametrize(
    "limit,value",
    [
        ("MAX_SIZE", 10),
        ("MAX_MEMBERS", 1),
        ("MAX_COORDINATES", 1),
        ("MAX_PLACEMARKS", 1),
        ("MAX_DEPTH", 2),
        ("MAX_NODES", 10),
    ],
)
def test_resource_limits(monkeypatch, limit, value):
    monkeypatch.setattr(kml, limit, value)
    assert "error" in kml_import.handler(request(package()))
    assert "error" in kmz_export.handler(json.dumps({"data": {"Object": [stored(package())]}}))


def test_aggregate_linked_document_and_archive_limits(monkeypatch):
    raw = package({"doc.kml": linked("child.kml"), "child.kml": SIMPLE})
    monkeypatch.setattr(kml, "MAX_COORDINATES", 1)
    assert "error" in kmz_export.handler(json.dumps({"data": {"Object": [stored(raw), location()]}}))
    monkeypatch.setattr(kml_exporter, "MAX_ARCHIVE_SIZE", 1)
    assert "error" in kmz_export.handler(json.dumps({"data": {"Object": [location()]}}))


@pytest.mark.parametrize("level", ["event", "envelope", "object", "attribute", "reference"])
@pytest.mark.parametrize("flag", [True, 1, "true", "1"])
def test_deleted_records_and_references(level, flag):
    point = location()
    point["uuid"] = "point"
    document = stored(SIMPLE, ObjectReference=[{"relationship_type": "contains", "referenced_uuid": "point"}])
    data = {"Event": {"Object": [document, point]}}
    if level == "event":
        data["Event"]["deleted"] = flag
    elif level == "envelope":
        data["deleted"] = flag
    elif level == "object":
        document["deleted"] = flag
    elif level == "attribute":
        document["Attribute"].append(attr("attachment", "missing", deleted=flag))
    else:
        document["ObjectReference"][0]["deleted"] = flag
    result = kmz_export.handler(json.dumps({"data": data}))
    if level in ("event", "envelope"):
        assert "error" in result
    else:
        raw = base64.b64decode(result["data"])
        expected = 2 if level == "reference" else 1
        assert len(locations(imported(raw))) == expected


def test_false_deletion_flags_missing_data_and_coordinate_cardinality():
    assert export([stored(SIMPLE, deleted="false")])[0] == SIMPLE
    for objects in (
        [{"name": "kml", "Attribute": []}],
        [{"name": "kml", "Attribute": [attr("attachment", "missing")]}],
        [{"name": "geolocation", "Attribute": [attr("latitude", "0")]}],
        [{"name": "geolocation", "Attribute": [attr("latitude", "0"), attr("latitude", "1"), attr("longitude", "0")]}],
    ):
        assert "error" in kmz_export.handler(json.dumps({"data": {"Object": objects}}))


class TestKMLHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        for name, module, kind in (
            ("kml_import", kml_import, "import_mod"),
            ("kml_export", kml_export, "export_mod"),
            ("kmz_export", kmz_export, "export_mod"),
        ):
            service.MODULES_HANDLERS.update({name: module, "type:" + name: kind})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_import_and_both_exports(self):
        assert len(json.loads(self.fetch("/modules").body)) == 3
        assert kml_import.handler() is kml_export.handler() is kmz_export.handler() is False
        response = self.fetch("/query", method="POST", body=request(module="kml_import"))
        assert response.code == 200
        data = json.loads(response.body)["results"]
        for name in ("kml_export", "kmz_export"):
            response = self.fetch("/query", method="POST", body=json.dumps({"module": name, "data": data}))
            assert response.code == 200
            output = base64.b64decode(json.loads(response.body)["data"])
            assert output == RAW if name == "kml_export" else contents(output)["import.kml"] == RAW
