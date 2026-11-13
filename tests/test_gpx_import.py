import base64
import hashlib
import json
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from xml.etree import ElementTree

import pytest
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.import_mod import gpx_import as module

GPX = b"""<?xml version="1.0" encoding="UTF-8"?>
<gpx xmlns="http://www.topografix.com/GPX/1/1" xmlns:ext="urn:example:gpx" version="1.1" creator="test-device">
  <metadata><name>Example dataset</name><desc>Field observations</desc><author><name>Observer</name></author>
    <link href="https://example.org/map"/><time>2026-01-01T10:00:00Z</time><keywords>test, field</keywords>
    <bounds minlat="0" minlon="0" maxlat="0" maxlon="0"/>
  </metadata>
  <wpt lat="49.1234567890123456789" lon="6.1"><ele>123.5</ele><time>2026-01-01T09:00:00Z</time>
    <name>Camp</name><desc>Start &amp; finish</desc><extensions><ext:device>gps-1</ext:device></extensions></wpt>
  <rte><name>Route A</name><rtept lat="0" lon="-180"><time>2026-01-01T11:00:00+01:00</time></rtept></rte>
  <trk><name>Track A</name><trkseg>
    <trkpt lat="-90" lon="0"><ele>-2</ele><time>2026-01-01T12:00:00Z</time></trkpt>
    <trkpt lat="90" lon="179.9"><time>2026-01-01T11:00:00Z</time></trkpt>
  </trkseg><trkseg><trkpt lat="49" lon="6"/></trkseg></trk>
</gpx>"""


def request(data=GPX, **kwargs):
    return json.dumps({"data": base64.b64encode(data).decode("ascii"), **kwargs})


def relations(obj):
    result = {}
    for attribute in obj["Attribute"]:
        result.setdefault(attribute["object_relation"], []).append(attribute["value"])
    return result


def test_dataset_and_geolocation_mapping():
    result = module.handler(request(filename="/uploads/field.gpx"))
    assert "error" not in result, result
    objects = result["results"]["Object"]
    dataset = next(obj for obj in objects if obj["name"] == "gpx")
    locations = [obj for obj in objects if obj["name"] == "geolocation"]
    assert len(locations) == 5
    fields = relations(dataset)
    assert fields["filename"] == ["field.gpx"]
    assert fields["creator"] == ["test-device"]
    assert fields["name"] == ["Example dataset"]
    assert fields["description-text"] == ["Field observations"]
    assert fields["author"] == ["Observer"]
    assert fields["keywords"] == ["test", "field"]
    assert fields["link"] == ["https://example.org/map"]
    assert fields["size-in-bytes"] == [str(len(GPX))]
    assert fields["gpx-version"] == ["1.1"]
    for name in ("md5", "sha1", "sha256"):
        assert fields[name] == [hashlib.new(name, GPX, usedforsecurity=False).hexdigest()]
    for name, count in (
        ("point-count", 5),
        ("waypoint-count", 1),
        ("route-count", 1),
        ("track-count", 1),
        ("track-segment-count", 2),
    ):
        assert fields[name] == [str(count)]
    assert fields["min-latitude"] == ["-90"] and fields["max-latitude"] == ["90"]
    assert fields["min-longitude"] == ["-180"] and fields["max-longitude"] == ["179.9"]
    assert fields["start-time"] == ["2026-01-01T10:00:00+00:00"]
    assert fields["end-time"] == ["2026-01-01T12:00:00+00:00"]
    attachment = next(a for a in dataset["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"], validate=True) == GPX
    assert {ref["referenced_uuid"] for ref in dataset["ObjectReference"]} == {obj["uuid"] for obj in locations}
    assert all(ref["relationship_type"] == "contains" for ref in dataset["ObjectReference"])
    waypoint = relations(locations[0])
    assert waypoint["latitude"] == ["49.1234567890123456789"]
    assert waypoint["altitude"] == ["123.5"]
    assert waypoint["first-seen"] == waypoint["last-seen"] == ["2026-01-01T09:00:00+00:00"]
    assert waypoint["epsg"] == ["4326"]
    assert waypoint["text"] == ["name: Camp\ndesc: Start & finish"]
    assert locations[1]["comment"] == "GPX route 1 point 1"
    assert locations[-1]["comment"] == "GPX track 1 segment 2 point 1"
    assert all(a["to_ids"] is False for obj in objects for a in obj["Attribute"])
    # The result can be loaded by a real MISP client, including its object references.
    event = MISPEvent()
    event.load(dict(result["results"], info="Imported GPX"))
    assert len(event.objects) == 6


def test_morning_walk_strava_file():
    """Exercise the complete uploaded Strava/Garmin track, including every observation."""
    data = (Path(__file__).parent / "fixtures" / "gpx" / "Morning_Walk.gpx").read_bytes()
    digest = "77e36202f8bb56cbc31c5bf5cc1ab104841a368c0c9e206853a9110f1b6170a8"
    assert hashlib.sha256(data).hexdigest() == digest
    ns = {"g": "http://www.topografix.com/GPX/1/1"}
    source = ElementTree.fromstring(data)
    points = source.findall("g:trk/g:trkseg/g:trkpt", ns)
    assert len(points) == 606

    result = module.handler(request(data, filename="Morning_Walk.gpx"))
    assert "error" not in result, result
    objects = result["results"]["Object"]
    (dataset,) = (obj for obj in objects if obj["name"] == "gpx")
    locations = [obj for obj in objects if obj["name"] == "geolocation"]
    assert len(objects) == 607 and len(locations) == 606
    fields = relations(dataset)
    assert fields["filename"] == ["Morning_Walk.gpx"]
    assert fields["creator"] == ["StravaGPX"]
    assert fields["sha256"] == [digest]
    assert fields["point-count"] == ["606"]
    assert fields["track-count"] == fields["track-segment-count"] == ["1"]
    assert fields["waypoint-count"] == fields["route-count"] == ["0"]
    assert fields["start-time"] == ["2026-11-13T05:52:57+00:00"]
    assert fields["end-time"] == ["2026-11-13T06:52:26+00:00"]
    for coordinate in ("latitude", "longitude"):
        values = [Decimal(point.get("lat" if coordinate == "latitude" else "lon")) for point in points]
        assert Decimal(fields[f"min-{coordinate}"][0]) == min(values)
        assert Decimal(fields[f"max-{coordinate}"][0]) == max(values)
    references = dataset["ObjectReference"]
    assert len(references) == 606
    assert {ref["referenced_uuid"] for ref in references} == {obj["uuid"] for obj in locations}
    assert all(ref["relationship_type"] == "contains" for ref in references)
    for index, (point, location) in enumerate(zip(points, locations), 1):
        observed = relations(location)
        assert observed["latitude"] == [point.get("lat")]
        assert observed["longitude"] == [point.get("lon")]
        assert observed["altitude"] == [point.findtext("g:ele", namespaces=ns)]
        timestamp = datetime.fromisoformat(point.findtext("g:time", namespaces=ns).replace("Z", "+00:00")).isoformat()
        assert observed["first-seen"] == observed["last-seen"] == [timestamp]
        assert location["comment"] == f"GPX track 1 segment 1 point {index}"
    assert all(attribute["to_ids"] is False for obj in objects for attribute in obj["Attribute"])
    (attachment,) = (a for a in dataset["Attribute"] if a["object_relation"] == "attachment")
    # This also preserves the Garmin heart-rate/cadence/temperature extensions on every point.
    assert base64.b64decode(attachment["data"], validate=True) == data


def test_artifact_hashes_work_with_fips_restrictions(monkeypatch):
    new_hash = hashlib.new

    def fips_hash(algorithm, data=b"", **kwargs):
        if algorithm in ("md5", "sha1") and kwargs.get("usedforsecurity", True):
            raise ValueError("Hash disabled for security use by FIPS policy")
        return new_hash(algorithm, data, **kwargs)

    monkeypatch.setattr(module.hashlib, "new", fips_hash)
    result = module.handler(request())
    assert "error" not in result, result
    (dataset,) = (obj for obj in result["results"]["Object"] if obj["name"] == "gpx")
    fields = relations(dataset)
    for algorithm in ("md5", "sha1", "sha256"):
        assert fields[algorithm] == [new_hash(algorithm, GPX, usedforsecurity=False).hexdigest()]


@pytest.mark.parametrize("version", ["1.0", "1.1"])
@pytest.mark.parametrize("namespace", [False, True])
def test_versions_namespaces_and_empty_datasets(version, namespace):
    ns = f' xmlns="http://www.topografix.com/GPX/{version.replace(".", "/")}"' if namespace else ""
    result = module.handler(request(f'<gpx version="{version}" creator="test"{ns}/>'.encode()))
    (dataset,) = result["results"]["Object"]
    assert dataset["name"] == "gpx"
    assert relations(dataset)["point-count"] == ["0"]


def test_gpx_10_metadata_and_naive_observation_time():
    data = b"""<gpx xmlns="http://www.topografix.com/GPX/1/0" version="1.0" creator="old">
      <name>Old dataset</name><author>Alice</author><url>https://example.org/</url><keywords>one,two</keywords>
      <wpt lat="0" lon="0"><time>2026-01-01T12:00:00</time></wpt></gpx>"""
    result = module.handler(request(data))
    dataset = next(obj for obj in result["results"]["Object"] if obj["name"] == "gpx")
    assert relations(dataset)["author"] == ["Alice"]
    assert relations(dataset)["link"] == ["https://example.org/"]
    assert relations(result["results"]["Object"][0])["first-seen"] == ["2026-01-01T12:00:00+00:00"]


@pytest.mark.parametrize("offset", ["+00:60", "-00:60", "+01:99", "+14:01", "-14:01", "+15:00", "-15:00", "+23:59"])
@pytest.mark.parametrize("context", ["point", "metadata"])
def test_invalid_timezone_offsets_reject_entire_import(offset, context):
    timestamp = f"<time>2026-01-02T12:00:00{offset}</time>"
    if context == "point":
        content = f'<wpt lat="0" lon="0"/><wpt lat="1" lon="2">{timestamp}</wpt>'
    else:
        content = f'<metadata>{timestamp}</metadata><wpt lat="0" lon="0"/>'
    result = module.handler(request(f'<gpx version="1.1" creator="test">{content}</gpx>'.encode()))
    assert "observation time" in result["error"]
    assert "results" not in result


@pytest.mark.parametrize(
    "offset,expected",
    [
        ("+00:00", "2026-01-02T12:00:00+00:00"),
        ("-00:00", "2026-01-02T12:00:00+00:00"),
        ("+13:59", "2026-01-01T22:01:00+00:00"),
        ("-13:59", "2026-01-03T01:59:00+00:00"),
        ("+14:00", "2026-01-01T22:00:00+00:00"),
        ("-14:00", "2026-01-03T02:00:00+00:00"),
    ],
)
def test_valid_timezone_offset_boundaries(offset, expected):
    data = (
        f'<gpx version="1.1" creator="test"><wpt lat="0" lon="0"><time>2026-01-02T12:00:00{offset}</time></wpt></gpx>'
        .encode()
    )
    result = module.handler(request(data))
    assert "error" not in result, result
    (location,) = (obj for obj in result["results"]["Object"] if obj["name"] == "geolocation")
    assert relations(location)["first-seen"] == [expected]


@pytest.mark.parametrize("context", ["point", "metadata"])
@pytest.mark.parametrize(
    "timestamp,expected",
    [
        ("2026-01-01T24:00:00Z", "2026-01-02T00:00:00+00:00"),
        ("2026-01-31T24:00:00+02:00", "2026-01-31T22:00:00+00:00"),
        ("2024-12-31T24:00:00.000-01:00", "2025-01-01T01:00:00+00:00"),
        ("2026-01-01T24:00:00", "2026-01-02T00:00:00+00:00"),
        ("2026-01-01T24:00:01Z", None),
        ("2026-01-01T24:01:00Z", None),
        ("2026-01-01T24:00:00.001Z", None),
    ],
)
def test_end_of_day_timestamps(context, timestamp, expected):
    content = (
        f'<wpt lat="0" lon="0"><time>{timestamp}</time></wpt>'
        if context == "point"
        else f"<metadata><time>{timestamp}</time></metadata>"
    )
    result = module.handler(request(f'<gpx version="1.1" creator="test">{content}</gpx>'.encode()))
    if expected is None:
        assert "observation time" in result["error"] and "results" not in result
    else:
        assert "error" not in result, result
        (obj,) = (
            obj
            for obj in result["results"]["Object"]
            if obj["name"] == ("geolocation" if context == "point" else "gpx")
        )
        assert relations(obj)["first-seen" if context == "point" else "time"] == [expected]


@pytest.mark.parametrize(
    "point",
    [
        '<wpt lon="1"/>',
        '<wpt lat="1"/>',
        '<wpt lat="NaN" lon="0"/>',
        '<wpt lat="Infinity" lon="0"/>',
        '<wpt lat="90.1" lon="0"/>',
        '<wpt lat="0" lon="180"/>',
        '<wpt lat="0" lon="-180.1"/>',
        '<wpt lat="0" lon="0"><ele>bad</ele></wpt>',
        '<wpt lat="0" lon="0"><ele/></wpt>',
        '<wpt lat="0" lon="0"><time/></wpt>',
        '<wpt lat="0" lon="0"><time>2026-02-30T00:00:00Z</time></wpt>',
        '<wpt lat="0" lon="0"><time>tomorrow</time></wpt>',
    ],
)
def test_invalid_points_reject_whole_import(point):
    data = f'<gpx version="1.1"><wpt lat="1" lon="2"/>{point}</gpx>'.encode()
    result = module.handler(request(data))
    assert "error" in result and "results" not in result


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not XML",
        b"<gpx",
        b'<other version="1.1"/>',
        b'<gpx version="2.0"/>',
        b'<gpx xmlns="urn:unrelated" version="1.1"/>',
        b'<gpx xmlns="http://www.topografix.com/GPX/1/0" version="1.1"/>',
        b'<!DOCTYPE gpx [<!ENTITY x "text">]><gpx version="1.1">&x;</gpx>',
        '<!DOCTYPE gpx SYSTEM "file:///etc/passwd"><gpx version="1.1"/>'.encode("utf-16"),
        ('<gpx version="1.1">' + "<x>" * 32 + "</x>" * 32 + "</gpx>").encode(),
    ],
)
def test_invalid_xml(data):
    assert "error" in module.handler(request(data))


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"data": 42}', '{"data": "%%%"}'])
def test_invalid_requests(raw):
    assert "error" in module.handler(raw)


def test_limits(monkeypatch):
    monkeypatch.setattr(module, "MAX_POINTS", 1)
    assert "point limit" in module.handler(request(GPX))["error"]
    monkeypatch.setattr(module, "MAX_GPX_SIZE", 8)
    assert "size limit" in module.handler(request(GPX))["error"]


@pytest.mark.parametrize("namespace", ["", ' xmlns="http://www.topografix.com/GPX/1/1"'])
@pytest.mark.parametrize("local_name", ["wpt", "rtept", "trkpt"])
def test_extension_point_names_do_not_count_as_observations(monkeypatch, namespace, local_name):
    monkeypatch.setattr(module, "MAX_POINTS", 1)
    vendor_points = f"<v:{local_name}/>" * 3
    # Even same-namespace names nested inside a vendor payload are outside GPX's geometry paths.
    payload = f"<v:payload>{vendor_points}<{local_name}/></v:payload>"
    data = (
        f'<gpx version="1.1" creator="test"{namespace} xmlns:v="urn:vendor"><wpt lat="0"'
        f' lon="0"/><extensions>{payload}</extensions></gpx>'.encode()
    )
    result = module.handler(request(data))
    assert "error" not in result, result
    (dataset,) = (obj for obj in result["results"]["Object"] if obj["name"] == "gpx")
    assert relations(dataset)["point-count"] == ["1"]
    # Actual structural points must still hit the parser limit before object construction.
    data = data.replace(b'<wpt lat="0" lon="0"/>', b'<wpt lat="0" lon="0"/>' * 2)
    assert "point limit" in module.handler(request(data))["error"]


class TestGPXImportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"gpx_import": module, "type:gpx_import": "import_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_import(self):
        (descriptor,) = json.loads(self.fetch("/modules").body)
        assert descriptor["mispattributes"]["format"] == "misp_standard"
        assert descriptor["meta"]["module-type"] == ["import"]
        assert module.handler() is False
        response = self.fetch("/query", method="POST", body=request(module="gpx_import"))
        assert response.code == 200
        assert len(json.loads(response.body)["results"]["Object"]) == 6
