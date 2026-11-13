import base64
import copy
import json
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree

import pytest
from pymisp import MISPEvent, MISPObject
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.modules.export_mod import gpx_export as module

NS = {"g": "http://www.topografix.com/GPX/1/1", "m": "https://www.misp-project.org/namespace/gpx/1"}
GPX = b"""<?xml version="1.0"?>
<gpx xmlns="http://www.topografix.com/GPX/1/1" xmlns:ext="urn:example:device" version="1.1" creator="gps">
 <metadata><name>Field dataset</name><bounds minlat="0" minlon="0" maxlat="0" maxlon="0"/></metadata>
 <wpt lat="49.1234567890123456789" lon="6"><name>Camp</name></wpt>
 <rte><name>Route</name><rtept lat="49" lon="6"/></rte>
 <trk><name>Track</name><trkseg><trkpt lat="50" lon="7"><ele>123</ele><time>2026-01-01T12:00:00Z</time>
  <extensions><ext:temperature>20</ext:temperature></extensions></trkpt></trkseg><trkseg/></trk>
 <extensions><ext:device>abc</ext:device></extensions>
</gpx>"""
GPX10 = b"""<gpx xmlns="http://www.topografix.com/GPX/1/0" xmlns:ext="urn:example:device" version="1.0" creator="old">
 <name>Old dataset</name><desc>Legacy data</desc><author>Alice</author><email>alice@example.org</email>
 <url>https://example.org/old</url><urlname>Old map</urlname><time>2026-01-01T10:00:00Z</time><keywords>field</keywords>
 <wpt lat="1" lon="2"><url>https://example.org/point</url><urlname>Point</urlname></wpt>
 <rte><name>Old route</name><rtept lat="1" lon="2"/><ext:route>r</ext:route></rte>
 <trk><name>Old track</name><trkseg><trkpt lat="3" lon="4"><course>180</course><speed>2.5</speed>
  <ext:sensor>s</ext:sensor></trkpt></trkseg></trk>
</gpx>"""


def attr(relation, value, **kwargs):
    return {"object_relation": relation, "value": value, "to_ids": False, **kwargs}


def dataset(data=GPX, references=None):
    return {
        "name": "gpx",
        "Attribute": [attr("attachment", "field.gpx", data=base64.b64encode(data).decode("ascii"))],
        "ObjectReference": references or [],
    }


def location(**values):
    return {
        "name": "geolocation",
        "Attribute": [attr(key, value) for key, value in {"latitude": "0", "longitude": "0", **values}.items()],
    }


def export(objects=None, data=None):
    result = module.handler(json.dumps({"data": {"Object": objects} if data is None else data}))
    assert "error" not in result, result
    assert result["response"] == []
    payload = base64.b64decode(result["data"], validate=True)
    return payload, ElementTree.fromstring(payload), result


@pytest.fixture
def morning_walk():
    """Build MISP inputs independently of the companion importer PR."""
    data = (Path(__file__).parent / "fixtures" / "gpx" / "Morning_Walk.gpx").read_bytes()
    source = ElementTree.fromstring(data)
    points = source.findall("g:trk/g:trkseg/g:trkpt", NS)
    assert len(points) == 606
    stored = dataset(data)
    stored["Attribute"][0]["value"] = "Morning_Walk.gpx"
    locations = []
    for index, point in enumerate(points, 1):
        obj = location(
            latitude=point.get("lat"),
            longitude=point.get("lon"),
            altitude=point.findtext("g:ele", namespaces=NS),
            **{"first-seen": point.findtext("g:time", namespaces=NS)},
        )
        obj["uuid"] = f"00000000-0000-4000-8000-{index:012d}"
        locations.append(obj)
        stored["ObjectReference"].append({"relationship_type": "contains", "referenced_uuid": obj["uuid"]})
    return data, source, stored, locations


def test_morning_walk_attachment_round_trip(morning_walk):
    data, source, stored, locations = morning_walk
    payload, root, _ = export([stored, *locations])
    assert payload == data
    assert root.find("g:trk/g:name", NS).text == source.find("g:trk/g:name", NS).text
    assert len(root.findall("g:trk/g:trkseg/g:trkpt", NS)) == 606
    assert root.findall("g:wpt", NS) == []


def test_morning_walk_combined_export_preserves_garmin_extensions(morning_walk):
    _, source, stored, locations = morning_walk
    _, root, _ = export([stored, *locations, location()])
    assert len(root.findall("g:wpt", NS)) == 1
    assert len(root.findall("g:trk", NS)) == len(root.findall("g:trk/g:trkseg", NS)) == 1
    assert root.findtext("g:trk/g:name", namespaces=NS) == source.findtext("g:trk/g:name", namespaces=NS)
    originals = source.findall("g:trk/g:trkseg/g:trkpt", NS)
    exported = root.findall("g:trk/g:trkseg/g:trkpt", NS)
    assert len(exported) == len(originals) == 606
    for before, after in zip(originals, exported):
        assert after.attrib == before.attrib
        for field in ("ele", "time"):
            assert after.findtext(f"g:{field}", namespaces=NS) == before.findtext(f"g:{field}", namespaces=NS)
        # Compare namespace-qualified elements and all sensor values, ignoring XML prefix choices.
        original_extensions = [
            (el.tag, el.attrib, (el.text or "").strip()) for el in before.find("g:extensions", NS).iter()
        ]
        exported_extensions = [
            (el.tag, el.attrib, (el.text or "").strip()) for el in after.find("g:extensions", NS).iter()
        ]
        assert exported_extensions == original_extensions


def test_morning_walk_geolocations_become_waypoints(morning_walk):
    _, source, _, locations = morning_walk
    _, root, _ = export(locations)
    originals = source.findall("g:trk/g:trkseg/g:trkpt", NS)
    exported = root.findall("g:wpt", NS)
    assert len(exported) == len(originals) == 606
    assert root.findall("g:trk", NS) == []
    for before, after in zip(originals, exported):
        assert after.attrib == before.attrib
        for field in ("ele", "time"):
            assert after.findtext(f"g:{field}", namespaces=NS) == before.findtext(f"g:{field}", namespaces=NS)


@pytest.mark.parametrize(
    "source", [GPX, GPX10, '<gpx version="1.1" creator="utf16"><wpt lat="0" lon="0"/></gpx>'.encode("utf-16")]
)
def test_single_attachment_is_returned_byte_for_byte(source):
    linked = location(latitude="99")
    linked["uuid"] = "linked-location"
    stored = dataset(source, [{"relationship_type": "contains", "referenced_uuid": linked["uuid"]}])
    payload, _, _ = export([stored, linked])
    assert payload == source


def test_standalone_geolocation_mapping_and_input_preservation():
    loc = location(
        latitude="49.1234567890123456789",
        longitude=1e-8,
        altitude="0",
        **{
            "first-seen": "2026-01-01T13:00:00+01:00",
            "last-seen": "2026-01-02T00:00:00Z",
            "text": "Camp & café <A>",
            "epsg": "4326",
        },
    )
    loc["comment"] = "Field camp"
    before = copy.deepcopy(loc)
    _, root, _ = export([loc])
    (point,) = root.findall("g:wpt", NS)
    assert root.get("version") == "1.1"
    assert point.attrib == {"lat": "49.1234567890123456789", "lon": "0.00000001"}
    assert point.findtext("g:ele", namespaces=NS) == "0"
    assert point.findtext("g:time", namespaces=NS) == "2026-01-01T12:00:00Z"
    assert point.findtext("g:name", namespaces=NS) == "Field camp"
    assert point.findtext("g:desc", namespaces=NS) == "Camp & café <A>"
    assert loc == before


@pytest.mark.parametrize("shape", ["bare", "standard", "legacy", "collection"])
def test_event_envelopes(shape):
    event = {"Object": [location()]}
    data = event if shape == "bare" else {"Event": event}
    if shape == "legacy":
        data = {"Event": {"id": "1"}, **event}
    if shape == "collection":
        data = [data, {"Object": [location(latitude="1", longitude="2")]}]
    _, root, _ = export(data=data)
    assert len(root.findall("g:wpt", NS)) == (2 if shape == "collection" else 1)


def test_real_pymisp_objects():
    event = MISPEvent()
    event.info = "Geographic context"
    obj = MISPObject("geolocation")
    obj.add_attribute("latitude", value=49, to_ids=False)
    obj.add_attribute("longitude", value=6, to_ids=False)
    obj.add_attribute("altitude", value=0, to_ids=False)
    event.add_object(obj)
    _, root, _ = export(data=json.loads(event.to_json()))
    assert root.find("g:wpt", NS).attrib == {"lat": "49", "lon": "6"}


@pytest.mark.parametrize("offset", ["+00:60", "-00:60", "+01:99", "+14:01", "-14:01", "+15:00", "-15:00", "+23:59"])
@pytest.mark.parametrize("context", ["first-seen", "last-seen", "attachment"])
def test_invalid_timezone_offsets_reject_entire_export(offset, context):
    timestamp = f"2026-01-02T12:00:00{offset}"
    if context == "attachment":
        obj = dataset(
            f'<gpx version="1.1" creator="test"><wpt lat="0" lon="0"><time>{timestamp}</time></wpt></gpx>'.encode()
        )
    else:
        obj = location(**{context: timestamp})
    result = module.handler(json.dumps({"data": {"Object": [location(), obj]}}))
    assert "observation time" in result["error"]
    assert "data" not in result


@pytest.mark.parametrize(
    "offset,expected",
    [
        ("+00:00", "2026-01-02T12:00:00Z"),
        ("-00:00", "2026-01-02T12:00:00Z"),
        ("+13:59", "2026-01-01T22:01:00Z"),
        ("-13:59", "2026-01-03T01:59:00Z"),
        ("+14:00", "2026-01-01T22:00:00Z"),
        ("-14:00", "2026-01-03T02:00:00Z"),
    ],
)
def test_valid_timezone_offset_boundaries(offset, expected):
    _, root, _ = export([location(**{"first-seen": f"2026-01-02T12:00:00{offset}"})])
    assert root.findtext("g:wpt/g:time", namespaces=NS) == expected


@pytest.mark.parametrize("context", ["geolocation", "attachment"])
@pytest.mark.parametrize(
    "timestamp,expected",
    [
        ("2026-01-01T24:00:00Z", "2026-01-02T00:00:00Z"),
        ("2026-01-31T24:00:00+02:00", "2026-01-31T22:00:00Z"),
        ("2024-12-31T24:00:00.000-01:00", "2025-01-01T01:00:00Z"),
        ("2026-01-01T24:00:00", "2026-01-02T00:00:00Z"),
        ("2026-01-01T24:00:01Z", None),
        ("2026-01-01T24:01:00Z", None),
        ("2026-01-01T24:00:00.001Z", None),
    ],
)
def test_end_of_day_timestamps(context, timestamp, expected):
    source = f'<gpx version="1.1" creator="test"><wpt lat="0" lon="0"><time>{timestamp}</time></wpt></gpx>'.encode()
    obj = dataset(source) if context == "attachment" else location(**{"first-seen": timestamp})
    result = module.handler(json.dumps({"data": {"Object": [obj]}}))
    if expected is None:
        assert "observation time" in result["error"] and "data" not in result
    else:
        assert "error" not in result, result
        payload = base64.b64decode(result["data"])
        if context == "attachment":
            assert payload == source
        else:
            assert ElementTree.fromstring(payload).findtext("g:wpt/g:time", namespaces=NS) == expected


def test_combined_sources_keep_geometry_extensions_and_source_metadata():
    _, root, _ = export([dataset(), dataset(GPX10), location()])
    assert len(root.findall("g:wpt", NS)) == 3
    assert len(root.findall("g:rte/g:rtept", NS)) == 2
    assert len(root.findall("g:trk/g:trkseg", NS)) == 3
    assert len(root.findall("g:trk/g:trkseg/g:trkpt", NS)) == 2
    assert root.findtext("g:metadata/g:name", namespaces=NS) == "Field dataset"
    assert root.find("g:metadata/g:bounds", NS) is None
    assert root.findtext("g:trk/g:trkseg/g:trkpt/g:extensions/{urn:example:device}temperature", namespaces=NS) == "20"
    sources = root.findall("g:extensions/m:source", NS)
    assert len(sources) == 2
    assert sources[0].findtext("g:metadata/g:name", namespaces=NS) == "Field dataset"
    assert sources[0].findtext("g:extensions/{urn:example:device}device", namespaces=NS) == "abc"
    assert sources[1].findtext("{http://www.topografix.com/GPX/1/0}author") == "Alice"
    assert root.findtext("g:wpt/g:link/g:text", namespaces=NS) == "Point"
    assert root.findtext("g:rte/g:extensions/{urn:example:device}route", namespaces=NS) == "r"
    assert (
        root.findtext("g:trk/g:trkseg/g:trkpt/g:extensions/{http://www.topografix.com/GPX/1/0}speed", namespaces=NS)
        == "2.5"
    )


def test_gpx_10_metadata_conversion():
    _, root, _ = export([dataset(GPX10), location()])
    assert root.findtext("g:metadata/g:name", namespaces=NS) == "Old dataset"
    assert root.findtext("g:metadata/g:desc", namespaces=NS) == "Legacy data"
    assert root.findtext("g:metadata/g:author/g:name", namespaces=NS) == "Alice"
    assert root.find("g:metadata/g:author/g:email", NS).attrib == {"id": "alice", "domain": "example.org"}
    assert root.findtext("g:metadata/g:link/g:text", namespaces=NS) == "Old map"


def test_namespace_less_source_and_extension_namespace_preservation():
    source = (
        b'<gpx version="1.1" creator="test"><wpt lat="0"'
        b' lon="0"><extensions><custom>v</custom></extensions></wpt></gpx>'
    )
    _, root, _ = export([dataset(source), location()])
    assert root.findtext("g:wpt/g:extensions/custom", namespaces=NS) == "v"


def test_combining_sources_preserves_qname_namespace_scopes():
    def source(label):
        return f"""<gpx xmlns="http://www.topografix.com/GPX/1/1" xmlns:v="urn:vendor:{label}"
          xmlns:misp0="urn:types:{label}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="1.1" creator="test">
          <metadata><extensions><v:item id="meta-{label}" xsi:type="misp0:Meta"/></extensions></metadata>
          <wpt lat="0" lon="0"><extensions>
            <v:item id="point-{label}" xsi:type="misp0:Kind">misp0:Payload</v:item>
            <v:item xmlns:misp0="urn:inner:{label}" id="inner-{label}" xsi:type="misp0:Inner"/>
            <v:item xmlns:v="urn:shadow:{label}" id="shadow-{label}" xsi:type="v:Shadow"/>
          </extensions></wpt>
          <extensions><v:item id="root-{label}" xsi:type="misp0:Root"/></extensions>
        </gpx>""".encode()

    payload, _, _ = export([dataset(source("one")), dataset(source("two")), location()])
    scopes, pending, seen = [{}], {}, set()
    for event, value in ElementTree.iterparse(BytesIO(payload), events=("start-ns", "start", "end")):
        if event == "start-ns":
            prefix, uri = value
            pending[prefix or ""] = uri
        elif event == "start":
            scopes.append(dict(scopes[-1], **pending))
            pending.clear()
        else:
            qname = value.get("{http://www.w3.org/2001/XMLSchema-instance}type")
            if qname:
                prefix, local = qname.split(":")
                identifier = value.get("id")
                kind, label = identifier.split("-")
                expected_uri = (
                    f'urn:{"inner" if kind == "inner" else "shadow" if kind == "shadow" else "types"}:{label}'
                )
                assert scopes[-1][prefix] == expected_uri
                assert (
                    local == {"meta": "Meta", "point": "Kind", "inner": "Inner", "shadow": "Shadow", "root": "Root"}[
                        kind
                    ]
                )
                if kind == "point":
                    text_prefix, text_local = value.text.split(":")
                    assert scopes[-1][text_prefix] == f"urn:types:{label}" and text_local == "Payload"
                seen.add(identifier)
            scopes.pop()
    assert seen == {
        f"{kind}-{label}" for kind in ("meta", "point", "inner", "shadow", "root") for label in ("one", "two")
    }


@pytest.mark.parametrize("namespace", ["", ' xmlns="http://www.topografix.com/GPX/1/1"'])
@pytest.mark.parametrize("local_name", ["wpt", "rtept", "trkpt"])
def test_extension_point_names_do_not_count_as_observations(monkeypatch, namespace, local_name):
    monkeypatch.setattr(module, "MAX_POINTS", 2)
    payload = f'<v:payload>{f"<v:{local_name}/>" * 3}<{local_name}/></v:payload>'
    data = (
        f'<gpx version="1.1" creator="test"{namespace} xmlns:v="urn:vendor"><wpt lat="0"'
        f' lon="0"/><extensions>{payload}</extensions></gpx>'.encode()
    )
    stored, _, _ = export([dataset(data)])
    assert stored == data
    _, root, _ = export([dataset(data), location()])
    assert len(root.findall("g:wpt", NS)) == 2
    assert len(root.findall(f".//{{urn:vendor}}{local_name}")) == 3


def test_deleted_records_and_place_only_locations():
    active = location(latitude="1", longitude="2", altitude="bad")
    active["Attribute"][-1]["deleted"] = True
    inactive = dict(location(), deleted=True)
    place = {"name": "geolocation", "Attribute": [attr("city", "Luxembourg")]}
    _, root, result = export(data=[{"deleted": True, "Object": [dataset()]}, {"Object": [inactive, active, place]}])
    assert len(root.findall("g:wpt", NS)) == 1
    assert root.find("g:wpt/g:ele", NS) is None
    assert "without coordinates" in result["warnings"][0]


@pytest.mark.parametrize(
    "values",
    [
        {"latitude": "NaN"},
        {"latitude": True},
        {"latitude": "90.1"},
        {"longitude": "180"},
        {"longitude": "-180.1"},
        {"longitude": None},
        {"altitude": "inf"},
        {"altitude": "1e9999999"},
        {"first-seen": "bad"},
        {"first-seen": ""},
        {"first-seen": "2026-02-30T00:00:00Z"},
        {"epsg": "3857"},
        {"spacial-reference": "Mercator EPSG:3857"},
        {"text": "bad\x00text"},
        {"text": "bad\ud800"},
    ],
)
def test_invalid_geolocations_return_errors_without_partial_data(values):
    result = module.handler(json.dumps({"data": {"Object": [location(), location(**values)]}}))
    assert "error" in result and "data" not in result


@pytest.mark.parametrize(
    "source",
    [
        b"not XML",
        b"<gpx",
        b'<gpx version="2.0"/>',
        b'<gpx xmlns="urn:wrong" version="1.1"/>',
        b'<gpx version="1.1"><wpt lat="99" lon="0"/></gpx>',
        b'<!DOCTYPE gpx [<!ENTITY x "entity">]><gpx version="1.1">&x;</gpx>',
        '<!DOCTYPE gpx SYSTEM "file:///etc/passwd"><gpx version="1.1"/>'.encode("utf-16"),
        ('<gpx version="1.1">' + "<x>" * 32 + "</x>" * 32 + "</gpx>").encode(),
    ],
)
def test_invalid_attachments(source):
    assert "error" in module.handler(json.dumps({"data": {"Object": [dataset(source)]}}))


@pytest.mark.parametrize("encoded", [None, "", "%%%", 42])
def test_missing_and_invalid_attachment_data(encoded):
    obj = dataset()
    obj["Attribute"][0]["data"] = encoded
    assert "error" in module.handler(json.dumps({"data": {"Object": [obj]}}))


@pytest.mark.parametrize(
    "raw",
    [
        "{",
        "null",
        "[]",
        "{}",
        '{"data": null}',
        '{"data": [1]}',
        '{"data": {"Event": []}}',
        '{"data": {"Object": [1]}}',
    ],
)
def test_invalid_requests(raw):
    assert "error" in module.handler(raw)


def test_empty_export_and_duplicate_coordinates():
    assert "error" in module.handler(json.dumps({"data": []}))
    _, root, _ = export([location(), location()])
    assert len(root.findall("g:wpt", NS)) == 2


def test_limits(monkeypatch):
    monkeypatch.setattr(module, "MAX_POINTS", 1)
    assert "limit" in module.handler(json.dumps({"data": {"Object": [location(), location()]}}))["error"]
    monkeypatch.setattr(module, "MAX_GPX_SIZE", 8)
    assert "limit" in module.handler(json.dumps({"data": {"Object": [dataset()]}}))["error"]


class TestGPXExportHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update({"gpx_export": module, "type:gpx_export": "export_mod"})
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_and_export(self):
        (descriptor,) = json.loads(self.fetch("/modules").body)
        assert descriptor["meta"]["module-type"] == ["export"]
        assert descriptor["mispattributes"]["outputFileExtension"] == "gpx"
        assert descriptor["mispattributes"]["responseType"] == "application/gpx+xml"
        assert module.handler() is False
        response = self.fetch(
            "/query", method="POST", body=json.dumps({"module": "gpx_export", "data": {"Object": [dataset()]}})
        )
        assert response.code == 200
        assert base64.b64decode(json.loads(response.body)["data"]) == GPX
