"""Real receiver sentences, date/height semantics, bounded import and exact log export."""

import base64
import copy
import hashlib
import json
import operator
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from functools import reduce
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pytest
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

from misp_modules import __main__ as service
from misp_modules.lib import nmea0183
from misp_modules.modules.export_mod import nmea_export as exporter
from misp_modules.modules.import_mod import nmea_import as importer

RAW = (Path(__file__).parent / "fixtures" / "nmea" / "receiver.nmea").read_bytes()
RMC = "GPRMC,235959,A,4807.038,N,01131.000,E,022.4,084.4,311226,003.1,W"
GGA = "GPGGA,000001,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,"
GLL = "GPGLL,4807.038,N,01131.000,E,000002,A,A"
ZDA = "GPZDA,235959.00,31,12,2026,00,00"


def sentence(body, prefix="$"):
    return f"{prefix}{body}*{reduce(operator.xor, body.encode(), 0):02X}".encode()


def log(*bodies, ending=b"\r\n"):
    return ending.join(sentence(body) for body in bodies) + ending


def request(raw=RAW, **kwargs):
    return json.dumps({"data": base64.b64encode(raw).decode(), **kwargs})


def imported(raw=RAW, **kwargs):
    result = importer.handler(request(raw, **kwargs))
    assert "error" not in result, result
    return result


def dataset(result):
    return next(obj for obj in result["results"]["Object"] if obj["name"] == "nmea")


def positions(result):
    return [obj for obj in result["results"]["Object"] if obj["name"] == "geolocation"]


def values(obj):
    fields = {}
    for attr in obj["Attribute"]:
        fields.setdefault(attr["object_relation"], []).append(attr["value"])
    return fields


def stored(raw=RAW, filename="receiver.nmea", **kwargs):
    return {
        "name": "nmea",
        "Attribute": [
            {
                "object_relation": "attachment",
                "value": filename,
                "data": base64.b64encode(raw).decode(),
                "to_ids": False,
            }
        ],
        **kwargs,
    }


def export(objects=None, data=None):
    result = exporter.handler(json.dumps({"data": {"Object": objects} if data is None else data}))
    assert "error" not in result, result
    assert result["response"] == []
    with ZipFile(BytesIO(base64.b64decode(result["data"], validate=True))) as archive:
        assert archive.testzip() is None
        return {name: archive.read(name) for name in archive.namelist()}


def test_reference_sentences_and_template_mapping():
    result = imported(filename="C:\\uploads\\receiver.nmea")
    source = dataset(result)
    fields = values(source)
    fixes = positions(result)
    assert len(fixes) == 3
    assert fields["filename"] == ["receiver.nmea"]
    assert fields["mime-type"] == ["text/plain"]
    assert fields["size-in-bytes"] == [str(len(RAW))]
    assert fields["sentence-count"] == ["4"]
    assert fields["position-count"] == ["3"]
    assert fields["invalid-fix-count"] == fields["unhandled-sentence-count"] == ["0"]
    assert set(fields["sentence-type"]) == {"GGA", "GLL", "RMC", "ZDA"}
    assert fields["talker-id"] == ["GP"]
    for algorithm in ("md5", "sha1", "sha256"):
        assert fields[algorithm] == [hashlib.new(algorithm, RAW, usedforsecurity=False).hexdigest()]
    attachment = next(attr for attr in source["Attribute"] if attr["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == RAW
    assert Decimal(values(fixes[0])["latitude"][0]) == Decimal("48.1173")
    assert values(fixes[0])["epsg"] == ["4326"]
    assert values(fixes[0])["first-seen"] == values(fixes[0])["last-seen"] == ["1994-03-23T12:35:19+00:00"]
    assert values(fixes[1])["altitude"] == ["592.3"]
    details = json.loads(values(fixes[1])["text"][0])
    assert details["fix-quality"] == "1" and details["satellites"] == "8" and details["hdop"] == "0.9"
    assert details["altitude-msl-metres"] == "545.4" and details["geoid-separation-metres"] == "46.9"
    assert details["raw-sentence"].endswith("*47") and details["line"] == 2
    assert "accuracy-radius" not in values(fixes[1])  # HDOP is dimensionless, not a distance.
    assert fields["min-longitude"] == [values(fixes[2])["longitude"][0]]
    assert fields["max-latitude"] == [values(fixes[2])["latitude"][0]]
    assert {ref["referenced_uuid"] for ref in source["ObjectReference"]} == {obj["uuid"] for obj in fixes}
    assert all(ref["relationship_type"] == "contains" for ref in source["ObjectReference"])
    assert all(attr["to_ids"] is False for obj in result["results"]["Object"] for attr in obj["Attribute"])
    event = MISPEvent()
    event.from_dict(info="NMEA observations", **copy.deepcopy(result["results"]))
    for obj in event.objects:
        if obj.name == "nmea":
            obj._definition = importer._template()
        assert obj._validate()
    assert export(data=result["results"]) == {"0001-receiver.nmea": RAW}


@pytest.mark.parametrize("anchor", [RMC, ZDA])
def test_dates_roll_over_midnight_and_year(anchor):
    result = imported(log(anchor, GGA, GLL))
    fixes = positions(result)
    assert values(fixes[-2])["first-seen"] == ["2027-01-01T00:00:01+00:00"]
    assert values(fixes[-1])["first-seen"] == ["2027-01-01T00:00:02+00:00"]
    assert values(dataset(result))["end-time"] == ["2027-01-01T00:00:02+00:00"]


def test_no_date_is_invented_or_backfilled_or_shared_across_talkers():
    result = imported(log(GGA, RMC, GGA.replace("GPGGA", "GNGGA"), GLL))
    fixes = positions(result)
    assert "first-seen" not in values(fixes[0])
    assert "first-seen" not in values(fixes[2])
    assert "first-seen" in values(fixes[3])
    assert result["warnings"][0].startswith("2 position(s)")
    assert json.loads(values(fixes[0])["text"][0])["utc-time"] == "000001"


@pytest.mark.parametrize("date_text,expected", [("010180", 1980), ("311299", 1999), ("010100", 2000), ("311279", 2079)])
def test_rmc_century_rule(date_text, expected):
    body = RMC.replace("311226", date_text)
    stamp = nmea0183.Log(log(body)).positions[0]["timestamp"]
    assert stamp.year == expected


def test_zda_full_year_and_fractional_utc():
    result = imported(log(ZDA.replace("2026", "2085"), GLL.replace("000002", "000002.123456")))
    assert values(positions(result)[0])["first-seen"] == ["2086-01-01T00:00:02.123456+00:00"]


def test_small_out_of_order_times_near_midnight_use_nearest_day():
    source = nmea0183.Log(log(RMC.replace("235959", "000001"), GGA.replace("000001", "235959")))
    assert source.positions[-1]["timestamp"] == datetime(2026, 12, 30, 23, 59, 59, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "body",
    [
        "GPGGA,000001,,,,,0,00,99.99,,,,,,",
        "GPRMC,000001,V,,,,,,,311226,,,N",
        "GPGLL,,,,,000001,V,N",
        RMC + ",N",
        GLL[:-1] + "N",
        RMC + ",A,V",
    ],
)
def test_no_fix_sentences_preserved_without_observations(body):
    raw = log(body)
    result = imported(raw)
    assert positions(result) == []
    assert values(dataset(result))["invalid-fix-count"] == ["1"]
    assert "start-time" not in values(dataset(result))
    assert list(export(data=result["results"]).values()) == [raw]


@pytest.mark.parametrize("quality", list("12345678"))
def test_quality_codes_are_retained_including_estimates_and_simulation(quality):
    result = imported(log(GGA.replace(",1,08,", f",{quality},08,")))
    assert json.loads(values(positions(result)[0])["text"][0])["fix-quality"] == quality


@pytest.mark.parametrize(
    "height,geoid,expected", [("10", "-20", "-10"), ("0", "0", "0"), ("10", "", None), ("", "10", None)]
)
def test_altitude_is_ellipsoid_height_only_when_both_terms_exist(height, geoid, expected):
    body = GGA.replace("545.4,M,46.9,M", f"{height},M,{geoid},M")
    fields = values(positions(imported(log(body)))[0])
    assert fields.get("altitude") == ([expected] if expected is not None else None)


@pytest.mark.parametrize(
    "latitude,ns,longitude,ew,lat,lon",
    [
        ("0000.000", "N", "00000.000", "E", "0", "0"),
        ("9000.000", "S", "18000.000", "W", "-90", "-180"),
        ("9000", "N", "18000", "E", "90", "180"),
        ("1230.000", "S", "04530.000", "W", "-12.5", "-45.5"),
    ],
)
def test_coordinate_conversion_and_boundaries(latitude, ns, longitude, ew, lat, lon):
    body = f"GPGLL,{latitude},{ns},{longitude},{ew},000000,A,A"
    point = nmea0183.Log(log(body)).positions[0]
    assert point["latitude"] == Decimal(lat) and point["longitude"] == Decimal(lon)


def test_high_precision_coordinate_conversion():
    raw = log(GLL.replace("4807.038", "4807.123456789012345678901234"))
    with localcontext() as context:
        context.prec = 40
        expected = Decimal(48) + Decimal("7.123456789012345678901234") / 60
    assert nmea0183.Log(raw).positions[0]["latitude"] == expected


@pytest.mark.parametrize("ending", [b"\r\n", b"\n", b"\r", b""])
def test_original_bytes_and_repeated_sentences_survive_export(ending):
    raw = log(RMC, RMC, ending=ending) if ending else sentence(RMC)
    result = imported(raw)
    assert len(positions(result)) == (2 if ending else 1)
    assert list(export(data=result["results"]).values()) == [raw]


def test_other_sentences_proprietary_payload_and_ais_are_preserved_only():
    bodies = [sentence("GPGSV,1,1,00"), sentence("PGRMZ,93,f,3"), sentence("AIVDM,1,1,,A,1234,0", "!")]
    raw = b"\r\n".join(bodies)
    result = imported(raw)
    assert positions(result) == []
    assert values(dataset(result))["unhandled-sentence-count"] == ["3"]
    assert set(values(dataset(result))["sentence-type"]) == {"GSV", "PGRMZ", "VDM"}
    assert list(export(data=result["results"]).values()) == [raw]


@pytest.mark.parametrize(
    "body",
    [
        GGA.replace("4807.038", "4860.001"),
        GGA.replace("4807.038", "9000.001"),
        GGA.replace("01131.000", "18000.001"),
        GGA.replace(",N,", ",X,"),
        GGA.replace(",E,", ",,"),
        GGA.replace("4807.038", "-4807.038"),
        GGA.replace("4807.038", "NaN"),
        GGA.replace("545.4,M", "545.4,F"),
        GGA.replace("46.9,M", "46.9,F"),
        GGA.replace(",1,08,", ",9,08,"),
        GGA.replace(",08,", ",1.5,"),
        GGA.replace(",0.9,", ",-1,"),
        RMC.replace("311226", "310226"),
        RMC.replace("311226", ""),
        RMC.replace(",A,", ",X,"),
        RMC.replace("022.4", "-1"),
        RMC.replace("084.4", "360"),
        RMC + ",X",
        RMC + ",A,X",
        GLL.replace(",A,A", ",X,A"),
        GLL.replace("000002", "240000"),
        GLL.replace("000002", "235960"),
        GLL.replace("000002", "000002.1234567"),
        "GPGGA,000001",
        "GPRMC,000001",
        "GPGLL,000001",
        ZDA.replace("2026", "26"),
        ZDA.replace(",12,", ",13,"),
        "GPZDA,000000",
        "GPDTM,NAS,,,,,,,W84",
        "GPDTM,W84",
    ],
)
def test_invalid_fields_reject_entire_import_and_export(body):
    raw = log(RMC, body)
    result = importer.handler(request(raw))
    assert "error" in result and "results" not in result
    assert "Line 2:" in result["error"]
    result = exporter.handler(json.dumps({"data": {"Object": [stored(raw)]}}))
    assert "error" in result and "data" not in result


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\n\r\n",
        b"not NMEA",
        sentence(RMC).replace(b"*", b"*0"),
        sentence(RMC)[:-2] + b"00",
        sentence(RMC).split(b"*")[0],
        b"\xff",
        b"\x00" + sentence(RMC),
        b"2026-12-31T23:59:59Z " + sentence(RMC),
        b"\\tag*00\\" + sentence(RMC),
        b"$GPRMC,123*GG",
        b"$GPRMC,123*00*00",
    ],
)
def test_malformed_encoding_framing_and_checksums(raw):
    assert "error" in importer.handler(request(raw))
    assert "error" in exporter.handler(json.dumps({"data": {"Object": [stored(raw)]}}))


@pytest.mark.parametrize("raw", ["{", "null", "[]", "{}", '{"data":42}', '{"data":"%%%"}'])
@pytest.mark.parametrize("module", [importer, exporter])
def test_invalid_envelopes(module, raw):
    assert "error" in module.handler(raw)


@pytest.mark.parametrize("name", [0, False, [], {}, "bad\nname.nmea"])
def test_invalid_filenames(name):
    assert "error" in importer.handler(request(filename=name))


@pytest.mark.parametrize(
    "limit,value", [("MAX_SIZE", 10), ("MAX_LINES", 1), ("MAX_POSITIONS", 1), ("MAX_LINE_LENGTH", 10)]
)
def test_limits_apply_before_returning_any_results(monkeypatch, limit, value):
    monkeypatch.setattr(nmea0183, limit, value)
    assert "error" in importer.handler(request())
    assert "error" in exporter.handler(json.dumps({"data": {"Object": [stored()]}}))


def test_blank_lines_count_towards_line_limit(monkeypatch):
    monkeypatch.setattr(nmea0183, "MAX_LINES", 2)
    assert "line limit" in importer.handler(request(b"\n\n" + sentence(RMC)))["error"]


def test_export_separate_logs_paths_and_duplicate_filenames():
    files = export([stored(filename="../../receiver.nmea"), stored(filename="C:\\uploads\\receiver.nmea")])
    assert files == {"0001-receiver.nmea": RAW, "0002-receiver.nmea": RAW}
    assert export([stored(filename="../..")]) == {"0001-log.nmea": RAW}


def test_export_never_mixes_receiver_dates():
    first, second = log(RMC), log(GGA)
    files = export(data=[{"Event": {"Object": [stored(first)]}}, {"Event": {}, "Object": [stored(second)]}])
    assert list(files.values()) == [first, second]
    assert nmea0183.Log(files["0002-receiver.nmea"]).positions[0]["timestamp"] is None


@pytest.mark.parametrize("level", ["event", "envelope", "object", "attribute"])
@pytest.mark.parametrize("flag", [True, 1, "true", "1"])
def test_deleted_records(level, flag):
    first, second = stored(), stored()
    data = {"Event": {"Object": [first, second]}}
    if level == "event":
        data["Event"]["deleted"] = flag
    elif level == "envelope":
        data["deleted"] = flag
    elif level == "object":
        first["deleted"] = flag
    else:
        first["Attribute"].append({"object_relation": "attachment", "value": "missing", "deleted": flag})
    if level in ("event", "envelope"):
        assert "error" in exporter.handler(json.dumps({"data": data}))
    else:
        assert len(export(data=data)) == (1 if level == "object" else 2)


def test_export_false_flags_and_missing_attachments():
    assert len(export([stored(deleted="false")])) == 1
    for objects in (
        [{"name": "geolocation", "Attribute": []}],
        [{"name": "nmea", "Attribute": []}],
        [{"name": "nmea", "Attribute": [{"object_relation": "attachment", "value": "file.nmea"}]}],
        [stored(RAW, filename=42)],
    ):
        assert "error" in exporter.handler(json.dumps({"data": {"Object": objects}}))


@pytest.mark.parametrize("limit", ["MAX_SIZE", "MAX_LINES", "MAX_POSITIONS"])
def test_combined_limits(monkeypatch, limit):
    raw = log(RMC)
    source = nmea0183.Log(raw)
    threshold = {"MAX_SIZE": len(raw), "MAX_LINES": source.line_count, "MAX_POSITIONS": len(source.positions)}[limit]
    monkeypatch.setattr(nmea0183, limit, threshold)
    assert "error" in exporter.handler(json.dumps({"data": {"Object": [stored(raw), stored(raw)]}}))


def test_archive_limits(monkeypatch):
    monkeypatch.setattr(exporter, "MAX_LOGS", 1)
    assert "log limit" in exporter.handler(json.dumps({"data": {"Object": [stored(), stored()]}}))["error"]
    monkeypatch.setattr(exporter, "MAX_ARCHIVE_SIZE", 1)
    assert "archive" in exporter.handler(json.dumps({"data": {"Object": [stored()]}}))["error"]


class TestNMEAHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.previous, self.cache = service.MODULES_HANDLERS.copy(), service.ListModules.CACHE
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(
            {
                "nmea_import": importer,
                "type:nmea_import": "import_mod",
                "nmea_export": exporter,
                "type:nmea_export": "export_mod",
            }
        )
        service.ListModules.CACHE = None
        return Application([(r"/modules", service.ListModules), (r"/query", service.QueryModule)])

    def tearDown(self):
        service.MODULES_HANDLERS.clear()
        service.MODULES_HANDLERS.update(self.previous)
        service.ListModules.CACHE = self.cache
        super().tearDown()

    def test_discovery_import_export(self):
        descriptors = json.loads(self.fetch("/modules").body)
        assert len(descriptors) == 2
        assert importer.handler() is exporter.handler() is False
        assert importer.introspection()["format"] == "misp_standard"
        assert exporter.introspection()["outputFileExtension"] == "zip"
        response = self.fetch("/query", method="POST", body=request(module="nmea_import"))
        assert response.code == 200
        data = json.loads(response.body)["results"]
        response = self.fetch("/query", method="POST", body=json.dumps({"module": "nmea_export", "data": data}))
        assert response.code == 200
        with ZipFile(BytesIO(base64.b64decode(json.loads(response.body)["data"]))) as archive:
            assert archive.read("0001-import.nmea") == RAW
