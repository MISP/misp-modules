import base64
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest
from pymisp import MISPObject

from misp_modules.lib import file_metadata
from misp_modules.modules.expansion import file_metadata as expansion
from misp_modules.modules.import_mod import file_metadata_import as importer

ATTACHMENT_UUID = "d2f0b2d5-96ef-49be-9005-2619b600c413"
BYTES = b"test file"
DATA = base64.b64encode(BYTES).decode("ascii")
SAMPLE_TAGS = {
    "SourceFile": "upload.jpg",
    "ExifTool:Main:ExifToolVersion": "13.64",
    "File:Main:FileType": "JPEG",
    "File:Main:MIMEType": "image/jpeg",
    "File:Main:FileTypeExtension": "JPG",
    "System:Main:FileModifyDate": "2026:10:01 14:05:06",
    "Composite:Main:GPSPosition": "48.2,2.6",
    "EXIF:ExifIFD:Main:DateTimeOriginal": "2024:03:30 23:59:59",
    "EXIF:ExifIFD:Main:OffsetTimeOriginal": "+02:00",
    "EXIF:ExifIFD:Main:SubSecTimeOriginal": "0123",
    "EXIF:ExifIFD:Main:SerialNumber": "000123",
    "EXIF:ExifIFD:Main:ExposureTime": "0.002",
    "EXIF:GPS:Main:GPSLatitude": "48.2",
    "EXIF:GPS:Main:GPSLatitudeRef": "N",
    "XMP:XMP-xmp:Main:CreateDate": "2024:03:30 23:59:59.1200-06:30",
    "XMP:XMP-xmp:Doc2:Copy1:CreateDate": "2024-03",
    "XMP:XMP-iptcExt:Main:LocationShown": [{"City": "Paris", "GPSLatitude": "48.1234"}],
    "EXIF:IFD1:Main:ThumbnailImage": "(Binary data 42 bytes, use -b option to extract)",
}
XMP = b"""<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about=""
 xmlns:exif="http://ns.adobe.com/exif/1.0/"
 xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/Iptc4xmpExt/">
 <exif:DateTimeOriginal>2024-03-30T01:02:03.1200</exif:DateTimeOriginal>
 <Iptc4xmpExt:LocationShown><rdf:Bag><rdf:li rdf:parseType="Resource">
 <Iptc4xmpExt:City>Paris</Iptc4xmpExt:City>
 </rdf:li></rdf:Bag></Iptc4xmpExt:LocationShown>
</rdf:Description></rdf:RDF></x:xmpmeta>"""


def query(module, **payload):
    result = module.handler(json.dumps(payload))
    assert "error" not in result, result
    return result


def file_and_metadata(result):
    file, metadata = result["results"]["Object"]
    assert file["name"] == "file" and metadata["name"] == "file-metadata"
    assert metadata["ObjectReference"][0]["referenced_uuid"] == file["uuid"]
    assert metadata["ObjectReference"][0]["relationship_type"] == "extracted-from"
    for obj in (file, metadata):
        opts = {"misp_objects_template_custom": file_metadata._template()} if obj == metadata else {}
        misp_obj = MISPObject(obj["name"], strict=True, standalone=False, **opts)
        misp_obj.from_dict(**obj)
        assert json.loads(misp_obj.to_json(strict=True))["uuid"] == obj["uuid"]
        assert all(a["to_ids"] is False and a["disable_correlation"] is True for a in obj["Attribute"])
    return file, metadata


def attribute(obj, relation):
    return next(attr for attr in obj["Attribute"] if attr["object_relation"] == relation)


def claims(obj, relation):
    records = [json.loads(attr["value"]) for attr in obj["Attribute"] if attr["object_relation"] == relation]
    return {item["tag"]: item for item in records}


@pytest.fixture
def tags(monkeypatch):
    tags = SAMPLE_TAGS.copy()
    monkeypatch.setattr(file_metadata, "_extract", lambda *args: (tags, "13.64", []))
    return tags


def test_import_preserves_provenance_values_and_unverified_claims(tags):
    result = query(importer, data=DATA, filename=r"C:\evidence\photo.jpg", config={"include_original": "yes"})
    file, metadata = file_and_metadata(result)
    digest = hashlib.sha256(BYTES).hexdigest()
    assert attribute(file, "filename")["value"] == "photo.jpg"
    assert attribute(file, "sha256")["value"] == attribute(metadata, "source-sha256")["value"] == digest
    assert attribute(file, "attachment")["data"] == DATA
    assert attribute(file, "mimetype")["value"] == "image/jpeg"
    assert attribute(metadata, "parser-version")["value"] == "13.64"
    assert attribute(metadata, "extraction-profile")["value"] == "standard"

    raw = claims(metadata, "metadata-tag")
    timestamps = claims(metadata, "timestamp-claim")
    locations = claims(metadata, "location-claim")
    assert raw["EXIF:ExifIFD:Main:SerialNumber"]["value"] == "000123"
    assert raw["EXIF:ExifIFD:Main:ExposureTime"]["value"] == "0.002"
    assert timestamps["EXIF:ExifIFD:Main:DateTimeOriginal"]["timezone"] == "unspecified"
    assert timestamps["EXIF:ExifIFD:Main:OffsetTimeOriginal"]["offset"] == "+02:00"
    assert timestamps["EXIF:ExifIFD:Main:SubSecTimeOriginal"]["fractional_digits"] == 4
    assert timestamps["XMP:XMP-xmp:Main:CreateDate"] == {
        "tag": "XMP:XMP-xmp:Main:CreateDate",
        "value": "2024:03:30 23:59:59.1200-06:30",
        "verification": "unverified",
        "precision": "fractional-second",
        "fractional_digits": 4,
        "timezone": "explicit",
        "offset": "-06:30",
    }
    assert timestamps["XMP:XMP-xmp:Doc2:Copy1:CreateDate"]["precision"] == "month"
    assert locations["EXIF:GPS:Main:GPSLatitudeRef"]["value"] == "N"
    assert locations["XMP:XMP-iptcExt:Main:LocationShown"]["value"] == tags["XMP:XMP-iptcExt:Main:LocationShown"]
    assert all(claim["verification"] == "unverified" for claim in (timestamps | locations).values())
    assert all(not tag.startswith(("System:", "Composite:")) for tag in raw | timestamps | locations)
    assert result["summary"]["binary_tags_skipped"] == 1


def test_attachment_expansion_links_existing_evidence(tags):
    attachment = {"type": "attachment", "uuid": ATTACHMENT_UUID, "value": "photo.jpg", "data": DATA}
    result = query(expansion, attribute=attachment)
    file, metadata = file_and_metadata(result)
    assert file["ObjectReference"][0]["referenced_uuid"] == ATTACHMENT_UUID
    assert not any(a["type"] == "attachment" for a in file["Attribute"])
    assert query(expansion, attribute=attachment)["results"] == result["results"]
    embedded = query(expansion, attribute=attachment, config={"scan_embedded": "1"})["results"]["Object"]
    assert embedded[0]["uuid"] == file["uuid"]
    assert embedded[1]["uuid"] != metadata["uuid"]
    another = query(expansion, attribute=dict(attachment, uuid="ebb67ad2-70f9-4714-89f5-4b4483298628"))
    assert another["results"]["Object"][0]["uuid"] != file["uuid"]


def test_limits_report_omissions_without_truncating_tag_values(tags, monkeypatch):
    tags["XMP:XMP-dc:Main:Description"] = "x" * 1000
    monkeypatch.setattr(file_metadata, "MAX_TAG_BYTES", 512)
    monkeypatch.setattr(file_metadata, "MAX_TAGS", 2)
    result = query(importer, data=DATA)
    _, metadata = file_and_metadata(result)
    assert result["summary"]["metadata_tags"] == 2
    assert result["summary"]["omitted_tags"] == 10
    assert "omitted" in attribute(metadata, "warning")["value"]
    assert "XMP:XMP-dc:Main:Description" not in claims(metadata, "metadata-tag")


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"data": "!!!"}, "base64"),
        ({"data": ""}, "between 1 byte"),
        ({"data": DATA, "filename": "../.."}, "printable filename"),
        ({"data": DATA, "filename": False}, "must be text"),
        ({"data": DATA, "config": {"scan_embedded": "maybe"}}, "must be a boolean"),
    ],
)
def test_upload_validation(payload, message):
    assert message in importer.handler(json.dumps(payload))["error"]


def test_missing_or_outdated_exiftool(tmp_path, monkeypatch):
    monkeypatch.setattr(file_metadata.shutil, "which", lambda _: None)
    assert "on the module service PATH" in importer.handler(json.dumps({"data": DATA}))["error"]
    monkeypatch.setattr(file_metadata.shutil, "which", lambda _: str(tmp_path / "exiftool"))
    old = dict(SAMPLE_TAGS, **{"ExifTool:Main:ExifToolVersion": "12.88"})
    monkeypatch.setattr(file_metadata, "_run_exiftool", lambda *args: (0, json.dumps([old]).encode(), b""))
    assert "13.00 or later" in importer.handler(json.dumps({"data": DATA}))["error"]


def test_extraction_profiles_and_warnings(tmp_path, monkeypatch):
    monkeypatch.setattr(file_metadata.shutil, "which", lambda _: str(tmp_path / "exiftool"))
    tags = dict(SAMPLE_TAGS, **{"ExifTool:Doc1:Warning": "Sample diagnostic"})

    def run(command, directory):
        assert command[1:3] == ["-config", ""]
        assert "-ee3" in command
        assert command[-1] == "upload.jpg"
        assert (Path(directory) / command[-1]).read_bytes() == BYTES
        return 0, json.dumps([tags]).encode(), b"Sample stderr"

    monkeypatch.setattr(file_metadata, "_run_exiftool", run)
    result = query(importer, data=DATA, filename="-config.jpg", config={"scan_embedded": True})
    assert result["warnings"] == ["Sample diagnostic", "ExifTool emitted additional diagnostics on stderr."]
    assert attribute(result["results"]["Object"][1], "warning")["value"] == "Sample diagnostic"


def test_subprocess_time_and_pipe_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(file_metadata, "MAX_TOOL_OUTPUT", 256)
    monkeypatch.setattr(file_metadata, "MAX_DIAGNOSTICS", 256)
    for pipe in ("stdout", "stderr"):
        with pytest.raises(ValueError, match="output limit"):
            file_metadata._run_exiftool([sys.executable, "-c", f"import sys; sys.{pipe}.write('x' * 1000)"], tmp_path)
    monkeypatch.setattr(file_metadata, "TIMEOUT_SECONDS", 0.1)
    with pytest.raises(ValueError, match="processing limit"):
        file_metadata._run_exiftool([sys.executable, "-c", "import time; time.sleep(10)"], tmp_path)


@pytest.mark.skipif(shutil.which("exiftool") is None, reason="ExifTool is required for integration tests")
def test_real_xmp_and_pdf():
    result = query(importer, data=base64.b64encode(XMP).decode("ascii"), filename="claims.xmp")
    _, xmp = file_and_metadata(result)
    assert result["summary"]["format"] == "XMP"
    times = claims(xmp, "timestamp-claim")
    assert times["XMP:XMP-exif:Main:DateTimeOriginal"]["timezone"] == "unspecified"
    assert times["XMP:XMP-exif:Main:DateTimeOriginal"]["fractional_digits"] == 4
    locations = claims(xmp, "location-claim")
    show_location = next(value for tag, value in locations.items() if tag.endswith(":LocationShown"))
    assert show_location["value"] == [{"City": "Paris"}]

    data = Path(__file__).with_name("test_files").joinpath("test.pdf").read_bytes()
    result = query(importer, data=base64.b64encode(data).decode("ascii"), filename="test.pdf")
    _, pdf = file_and_metadata(result)
    assert result["summary"]["format"] == "PDF"
    assert claims(pdf, "timestamp-claim")["PDF:Main:CreateDate"]["offset"] == "+02:00"
