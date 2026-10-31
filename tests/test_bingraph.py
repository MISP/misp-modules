import base64
import hashlib
import json
import struct
import zipfile
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from unittest.mock import patch

import numpy as np
import pytest
from pymisp import MISPEvent

from misp_modules.modules.expansion import bingraph as module

UUID = "32876e4a-916d-4935-9e51-7b69a76718f8"
SAMPLE = b"benign binGraph test sample\x00\xff" * 32
# ZipCrypto archive generated with `zip -P infected`: MISP's two-member layout.
ENCRYPTED = (
    "UEsDBBQACQAIAA1KWl0D3B0vNAAAAKADAAAgABwAY2RmYTRlZTk0NDM1NWJmMGNkMzk0ZDU3MmQ0ODdlZDFVVAkAA2ka32ppGt9q"
    "dXgLAAEE6AMAAAToAwAAnOwvk7VODNsvxrIxeXaBbPGSxthi09rLm0fT7LPNcw2DsPyKh3/izBv/UMhVg6EupyPXJVBLBwgD3B0v"
    "NAAAAKADAABQSwMECgAJAAAADUpaXaXKBSkWAAAACgAAAC0AHABjZGZhNGVlOTQ0MzU1YmYwY2QzOTRkNTcyZDQ4N2VkMS5maWxlbmFt"
    "ZS50eHRVVAkAA2ka32ppGt9qdXgLAAEE6AMAAAToAwAAfYWXCZ0itFwfghHm9zIXI3bdfoLK91BLBwilygUpFgAAAAoAAABQSwECHgMU"
    "AAkACAANSlpdA9wdLzQAAACgAwAAIAAYAAAAAAAAAAAAgIEAAAAAY2RmYTRlZTk0NDM1NWJmMGNkMzk0ZDU3MmQ0ODdlZDFVVAUAA2ka32p1"
    "eAsAAQToAwAABOgDAABQSwECHgMKAAkAAAANSlpdpcoFKRYAAAAKAAAALQAYAAAAAAABAAAAgIGeAAAAY2RmYTRlZTk0NDM1NWJmMGNkMzk0"
    "ZDU3MmQ0ODdlZDEuZmlsZW5hbWUudHh0VVQFAANpGt9qdXgLAAEE6AMAAAToAwAAUEsFBgAAAAACAAIA2QAAACsBAAAAAA=="
)


def query(raw=SAMPLE, kind="attachment", value="sample.bin", config=None):
    return {
        "attribute": {
            "type": kind,
            "value": value,
            "uuid": UUID,
            "data": base64.b64encode(raw).decode(),
            "to_ids": True,
            "comment": "Original context",
        },
        "config": config,
    }


def archive(files):
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, data in files.items():
            zipped.writestr(name, data)
    return output.getvalue()


def image(result):
    assert "results" in result, result
    obj = result["results"]["Object"][0]
    assert obj["name"] == "image"
    attrs = {a["object_relation"]: a for a in obj["Attribute"]}
    return obj, attrs, json.loads(attrs["image-text"]["value"])


def test_discovery():
    assert module.handler(False) is False
    assert module.introspection() == {"input": ["attachment", "malware-sample"], "format": "misp_standard"}
    assert module.version()["config"] == module.moduleconfig


@pytest.mark.parametrize("graph_type,dimensions", [("all", (1440, 960)), ("ent", (1440, 600)), ("hist", (1440, 600))])
def test_png_round_trip_and_source_preservation(graph_type, dimensions):
    request = query(config={"graph_type": graph_type})
    result = module.handler(json.dumps(request))
    obj, attrs, metadata = image(result)
    assert result["results"]["Attribute"] == [request["attribute"]]
    assert obj["template_uuid"] == "ca78ec03-3321-4ed3-9840-9bfd52b91d82"
    assert all(a["to_ids"] is False and a["disable_correlation"] for a in attrs.values())
    assert obj["ObjectReference"][0]["referenced_uuid"] == UUID
    assert obj["ObjectReference"][0]["relationship_type"] == "visualizes"
    assert metadata["sha256"] == hashlib.sha256(SAMPLE).hexdigest()
    assert metadata["size_in_bytes"] == len(SAMPLE)
    png = base64.b64decode(attrs["attachment"]["data"])
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert struct.unpack(">II", png[16:24]) == dimensions
    event = MISPEvent()
    event.from_dict(info="binGraph test event", **result["results"])
    assert event.objects[0].name == "image"


def test_entropy_and_complete_histogram():
    result = module._analyse(b"\x00" * 256 + bytes(range(256)) + b"\xff", 750)
    assert result["offsets"] == [0, 256, 512]
    assert result["entropies"] == [0.0, 8.0, 0.0]
    assert result["zeroes"] == [100.0, 100 / 256, 0.0]
    assert result["ones"] == [0.0, 100 / 256, 100.0]
    assert result["histogram"].sum() == 513
    assert result["histogram"][0] == 257
    assert result["histogram"][255] == 2
    assert np.all(result["histogram"][1:255] == 1)
    assert module._analyse(bytes(range(256)), 750)["entropy"] == 8.0


@pytest.mark.parametrize(
    "raw", [b"\x00", b"\xff" * 1024, bytes(range(256))], ids=["single-byte", "constant", "uniform"]
)
def test_short_and_constant_files_render(raw):
    _, _, metadata = image(module.dict_handler(query(raw)))
    assert 0 <= metadata["entropy_bits_per_byte"] <= 8


def test_encrypted_modern_misp_sample_is_unpacked_and_source_is_unchanged():
    request = query(base64.b64decode(ENCRYPTED), "malware-sample", "sample.bin|cdfa4ee944355bf0cd394d572d487ed1")
    result = module.dict_handler(request)
    _, _, metadata = image(result)
    assert metadata["sha256"] == hashlib.sha256(SAMPLE).hexdigest()
    assert metadata["size_in_bytes"] == len(SAMPLE)
    assert result["results"]["Attribute"] == [request["attribute"]]


def test_legacy_single_member_zip_and_md5_validation():
    raw = archive({"../../sample.bin": SAMPLE})
    value = "sample.bin|" + hashlib.md5(SAMPLE).hexdigest()
    assert module._sample(query(raw, "malware-sample", value)["attribute"], 10000) == SAMPLE
    bad = query(raw, "malware-sample", "sample.bin|" + "0" * 32)
    assert "MD5" in module.dict_handler(bad)["error"]


@pytest.mark.parametrize("raw", [b"invalid", archive({}), archive({"a": SAMPLE, "b": SAMPLE}), archive({"dir/": b""})])
def test_invalid_or_ambiguous_zip(raw):
    result = module.dict_handler(query(raw, "malware-sample", "sample.bin|" + hashlib.md5(SAMPLE).hexdigest()))
    assert "error" in result


def test_archive_decompression_limit():
    raw = archive({"sample": b"x" * (1024 * 1024 + 1)})
    result = module.dict_handler(query(raw, "malware-sample", "sample.bin|" + "0" * 32, {"max_size_mb": 1}))
    assert "unpacked sample exceeds" in result["error"]


def test_base64_limit_before_decode():
    request = query(b"x" * (1024 * 1024 + 5), config={"max_size_mb": 1})
    with patch.object(module.base64, "b64decode", side_effect=AssertionError("Must not decode oversized input")):
        assert "exceeds" in module.dict_handler(request)["error"]


@pytest.mark.parametrize("value", [None, "", "!!!", 5])
def test_missing_or_invalid_base64(value):
    request = query()
    request["attribute"]["data"] = value
    assert "error" in module.dict_handler(request)


@pytest.mark.parametrize("raw", ["{", "[]", "null", "{}", '{"attribute": []}'])
def test_invalid_envelope(raw):
    assert "error" in module.handler(raw)


@pytest.mark.parametrize("field,value", [("type", "sha256"), ("value", []), ("uuid", "bad"), ("uuid", 3)])
def test_invalid_attribute(field, value):
    request = query()
    request["attribute"][field] = value
    assert "error" in module.dict_handler(request)


@pytest.mark.parametrize(
    "config",
    [
        [],
        {"graph_type": "svg"},
        {"chunks": 0},
        {"chunks": 4097},
        {"chunks": True},
        {"chunks": 1.5},
        {"max_size_mb": 51},
        {"max_size_mb": "no"},
    ],
)
def test_invalid_config(config):
    assert "error" in module.dict_handler(query(config=config))


def test_empty_attachment():
    assert "error" in module.dict_handler(query(b""))


def test_chunks_and_safe_title():
    request = query(bytes(range(256)) * 32, value="../../evil\n$invalid_{title}.bin", config={"chunks": "2"})
    _, _, metadata = image(module.dict_handler(request))
    assert metadata["window_size_in_bytes"] == 4096
    assert metadata["window_count"] == 2
    assert metadata["filename"] == "evil_$invalid_{title}.bin"


def test_concurrent_requests_keep_separate_images():
    requests = [query(b"\x00" * 256), query(bytes(range(256)))]
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(module.dict_handler, requests))
    assert [image(result)[2]["entropy_bits_per_byte"] for result in results] == [0.0, 8.0]
