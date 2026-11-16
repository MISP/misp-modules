"""Synthetic content exercises real hashing, decoding and temporal comparison."""

import base64
import hashlib
import json
import random
import shutil
import struct
import subprocess
import zlib
from unittest.mock import patch

import pytest
from pymisp import MISPEvent
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application

import misp_modules
from misp_modules import __main__ as server
from misp_modules.modules.expansion import content_fingerprint as module

SOURCE_UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
REFERENCE_UUID = "b3936b7a-f6f1-4aa5-8d26-41f2e602af00"
ARTICLE = (
    "Researchers studying the ancient forest discovered several rare plants along the river bank. "
    "The team recorded changes in temperature and rainfall during the summer season. Local volunteers "
    "helped collect samples from different parts of the valley each morning. Scientists compared these "
    "observations with historical records from the nearby university. Their findings suggest that careful "
    "conservation can protect this remarkable landscape for future generations. The project will continue "
    "next year with additional monitoring stations and improved methods for analysing the collected data."
)


def attribute(value=ARTICLE, name=None, uuid=SOURCE_UUID):
    result = {"type": "attachment" if name else "text", "value": name or value, "uuid": uuid}
    if name:
        result["data"] = base64.b64encode(value).decode()
    return result


def run(source=None, reference=None, **config):
    request = {"attribute": source or attribute(), "config": config}
    if reference is not None:
        request["reference"] = reference
    return module.handler(json.dumps(request))


def objects(result, name="content-fingerprint"):
    assert "error" not in result, result
    return [obj for obj in result["results"]["Object"] if obj["name"] == name]


def value(obj, relation):
    return next(a["value"] for a in obj["Attribute"] if a["object_relation"] == relation)


def report(result, index=0):
    return json.loads(value(objects(result)[index], "metadata"))


def comparison(result):
    return json.loads(value(objects(result, "annotation")[0], "text"))


def pixels(seed, width=64):
    generator = random.Random(seed)
    tiles = [generator.randrange(30, 200) for _ in range(64)]
    return bytes(tiles[(y * 8 // width) * 8 + x * 8 // width] for y in range(width) for x in range(width))


def png(data, width=64, colour_type=0):
    def chunk(kind, content):
        return struct.pack("!I", len(content)) + kind + content + struct.pack("!I", zlib.crc32(kind + content))

    stride = width * (4 if colour_type == 6 else 1)
    rows = b"".join(b"\0" + data[y * stride : (y + 1) * stride] for y in range(width))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack("!IIBBBBB", width, width, 8, colour_type, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


MEDIA = pytest.mark.skipif(not (shutil.which("ffmpeg") and shutil.which("ffprobe")), reason="FFmpeg >= 5 required")


@pytest.fixture
def videos(tmp_path):
    def encode(seeds):
        destination = tmp_path / ("clip-" + "-".join(map(str, seeds)) + ".mkv")
        data = b"".join(pixels(seed) * 2 for seed in seeds)
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-threads",
                "1",
                "-f",
                "rawvideo",
                "-pixel_format",
                "gray",
                "-video_size",
                "64x64",
                "-framerate",
                "2",
                "-i",
                "pipe:0",
                "-c:v",
                "ffv1",
                "-y",
                str(destination),
            ],
            input=data,
            check=True,
            timeout=15,
            capture_output=True,
        )
        return destination.read_bytes()

    return encode


def test_exact_hash_versions_and_provenance():
    source = {**attribute(), "comment": "preserve source", "to_ids": True, "Tag": [{"name": "tlp:clear"}]}
    result = run(source)
    obj = objects(result)[0]
    metadata = report(result)
    assert value(obj, "sha256") == hashlib.sha256(ARTICLE.encode()).hexdigest()
    assert metadata["exact_algorithm"]["version"] == "FIPS-180-4"
    assert metadata["text"]["simhash"]["version"].startswith("v1-u")
    assert metadata["text"]["simhash"]["shingle_words"] == 5
    assert metadata["text"]["simhash"]["usable"] is True
    assert result["results"]["Attribute"] == [source]
    assert obj["ObjectReference"][0]["referenced_uuid"] == SOURCE_UUID
    assert all(a["to_ids"] is False for a in obj["Attribute"])
    assert all(
        a["disable_correlation"] == (a["object_relation"] in ("metadata", "content-type")) for a in obj["Attribute"]
    )
    event = MISPEvent()
    event.from_dict(info="Content fingerprints", **result["results"])
    assert event.objects[0].name == "content-fingerprint"
    assert objects(run(source))[0]["uuid"] == obj["uuid"]


def test_normalisation_case_unicode_and_whitespace():
    first = attribute("ＣＡＦÉ and the forest team collected many samples from the ancient river valley today.")
    second = attribute(
        "café AND the forest team collected\n many samples from the ancient river valley today!", uuid=REFERENCE_UUID
    )
    result = run(first, second)
    evidence = comparison(result)
    assert evidence["exact_match"] is False
    assert evidence["normalised_match"] is True
    assert evidence["hamming_distance"] == 0
    assert evidence["jaccard"] == 1
    assert evidence["similar"] is True


def test_edited_article_similarity_and_shared_evidence():
    edited = ARTICLE.replace("rare plants", "unusual plants").replace("summer season", "autumn season")
    result = run(attribute(), attribute(edited, uuid=REFERENCE_UUID))
    evidence = comparison(result)
    assert not evidence["exact_match"]
    assert evidence["similar"]
    assert 0 < evidence["hamming_distance"] <= 10
    assert 0.5 < evidence["jaccard"] < 1
    assert evidence["shared_shingles"] > 30
    assert evidence["matching_shingle_examples"]
    annotations = objects(result, "annotation")
    assert {r["referenced_uuid"] for r in annotations[0]["ObjectReference"]} == {o["uuid"] for o in objects(result)}


def test_unrelated_and_short_text_do_not_claim_similarity():
    unrelated = " ".join(f"different{number}" for number in range(80))
    assert not comparison(run(attribute(), attribute(unrelated, uuid=REFERENCE_UUID)))["similar"]
    short = run(attribute("hello"), attribute("hello", uuid=REFERENCE_UUID))
    assert comparison(short)["exact_match"]
    assert not comparison(short)["usable"]
    assert not comparison(short)["similar"]
    punctuation = report(run(attribute("!!!")))
    assert punctuation["text"]["simhash"]["value"] is None
    assert not any(a["object_relation"] == "fingerprint" for a in objects(run(attribute("!!!")))[0]["Attribute"])


def test_algorithm_version_vectors():
    # Fixed vectors make accidental algorithm changes require an explicit version bump.
    text, _ = module.text_profile(b"one two three four five six seven eight nine")
    assert text["simhash"]["value"] == "3bc600f0569fc1a3"
    # Independently verified with a NumPy DCT-II matrix, without adding a runtime dependency.
    perceptual = module.phash(pixels(42, 32))
    assert perceptual["value"] == "6d6f560c5b84a1b1"


def test_text_attachment_and_config_reference():
    source = attribute(ARTICLE.encode(), "article.txt")
    reference = attribute(ARTICLE, uuid=REFERENCE_UUID)
    result = run(source, **{"reference": json.dumps(reference)})
    assert comparison(result)["exact_match"]
    assert report(result)["sha256"] == report(result, 1)["sha256"]
    request = {"attribute": {k: v for k, v in source.items() if k != "data"}, "data": source["data"]}
    assert report(module.handler(json.dumps(request)))["sha256"] == report(result)["sha256"]


@MEDIA
def test_image_changes_preserve_perceptual_similarity():
    original = attribute(png(pixels(42)), "meme.png")
    altered = attribute(png(bytes(v + 15 for v in pixels(42, 128)), 128), "altered.png", REFERENCE_UUID)
    result = run(original, altered)
    evidence = comparison(result)
    assert not evidence["exact_match"]
    assert evidence["similar"]
    assert evidence["matching_frames"][0]["hamming_distance"] <= 4
    assert report(result)["media"]["decoder"].startswith("ffmpeg version")
    assert report(result)["media"]["algorithm"] == "phash63-dct32-v1"
    assert report(result)["media"]["frames"][0]["usable"]
    unrelated = run(original, attribute(png(pixels(999)), "other.png", REFERENCE_UUID))
    assert not comparison(unrelated)["similar"]


@MEDIA
def test_image_magic_detection_and_uninformative_images():
    assert report(run(attribute(png(pixels(4)), "unknown.bin")))["content_type"] == "image"
    flat = run(attribute(png(bytes([0]) * 4096), "flat.png"))
    assert not report(flat)["media"]["frames"][0]["usable"]
    assert not any(a["object_relation"] == "fingerprint" for a in objects(flat)[0]["Attribute"])
    invisible = bytes(component for luma in pixels(42) for component in (luma, luma, luma, 0))
    transparent = report(run(attribute(png(invisible, colour_type=6), "transparent.png")))
    assert not transparent["media"]["frames"][0]["usable"]


@MEDIA
def test_reused_video_clip_has_offset_and_monotonic_frame_evidence(videos):
    source = attribute(videos([1, 2, 3, 4, 5, 6]), "full.mkv")
    reference = attribute(videos([3, 4, 5]), "clip.mkv", REFERENCE_UUID)
    result = run(source, reference)
    evidence = comparison(result)
    assert not evidence["exact_match"]
    assert evidence["similar"]
    assert evidence["longest_matching_run"] == 3
    matches = evidence["matching_frames"]
    assert [(m["source_seconds"], m["reference_seconds"]) for m in matches] == [(2, 0), (3, 1), (4, 2)]
    assert all(m["hamming_distance"] == 0 for m in matches)
    assert report(result)["media"]["truncated"] is False
    reordered = run(source, attribute(videos([3, 5, 4]), "reordered.mkv", REFERENCE_UUID))
    assert not comparison(reordered)["similar"]


@MEDIA
def test_video_sample_limit_is_explicit(videos):
    source = attribute(videos([1, 2, 3, 4]), "long.mkv")
    result = run(source, max_frames=2)
    media = report(result)["media"]
    assert len(media["frames"]) == 2
    assert media["truncated"] is True
    assert media["sample_interval_seconds"] == 1
    assert objects(run(source, max_frames=3))[0]["uuid"] != objects(result)[0]["uuid"]


def test_video_matching_requires_consistent_timing():
    def profile(times):
        return {
            "content_type": "video",
            "sha256": "different bytes",
            "media": {
                "algorithm": module.PHASH_VERSION,
                "decoder": "test-decoder",
                "sample_interval_seconds": 1,
                "truncated": False,
                "frames": [{"value": "1234567890abcdef", "usable": True, "timestamp_seconds": t} for t in times],
            },
        }

    evidence = module.compare(profile([0, 100]), profile([0, 1]), set(), set())
    assert not evidence["similar"]
    assert evidence["longest_matching_run"] == 1


@MEDIA
def test_bad_media_and_dimension_limit():
    assert "error" in run(attribute(b"invalid media", "broken.mp4"))
    with patch.object(module, "MAX_PIXELS", 100):
        assert "error" in run(attribute(png(pixels(1)), "large.png"))


def test_missing_decoder_and_cross_type_reference():
    with patch.object(module.shutil, "which", return_value=None):
        assert "FFmpeg" in run(attribute(b"fake png", "fake.png"))["error"]
    left = {"content_type": "text", "sha256": "a"}
    right = {"content_type": "image", "sha256": "b"}
    with pytest.raises(ValueError, match="same content type"):
        module.compare(left, right, set(), set())


@pytest.mark.parametrize("query", ["null", "[]", "{}", "bad json", '{"attribute": []}'])
def test_malformed_request(query):
    assert "error" in module.handler(query)


@pytest.mark.parametrize(
    "change",
    [{"uuid": None}, {"uuid": []}, {"uuid": "bad"}, {"value": ""}, {"value": 2}, {"type": "url"}, {"type": []}],
)
def test_invalid_attributes(change):
    assert "error" in run({**attribute(), **change})


@pytest.mark.parametrize(
    "config",
    [
        {"timeout": True},
        {"timeout": 0},
        {"timeout": 121},
        {"timeout": "x"},
        {"content_type": "other"},
        {"reference": "not json"},
    ],
)
def test_invalid_configuration(config):
    assert "error" in run(**config)


@pytest.mark.parametrize("data", ["!invalid", "a===", None, []])
def test_bad_base64(data):
    assert "error" in run({**attribute(b"abc", "test.txt"), "data": data})


def test_limits_and_reference_identity():
    with patch.object(module, "MAX_BYTES", 3):
        assert "error" in run(attribute("four"))
        assert "error" in run(attribute(b"four", "text.txt"))
    with patch.object(module, "MAX_TEXT_BYTES", 3):
        assert "error" in run(attribute("four"))
    with patch.object(module, "MAX_TOKENS", 2):
        assert "error" in run(attribute("one two three"))
    assert "error" in run(attribute(), attribute())
    assert "error" in run(attribute(b"\xff\xfe", "text.txt"))


@pytest.mark.parametrize(
    "reference_uuid",
    [SOURCE_UUID.upper(), "{" + SOURCE_UUID + "}", SOURCE_UUID.replace("-", ""), "urn:uuid:" + SOURCE_UUID],
)
@pytest.mark.parametrize("via_config", [False, True])
@pytest.mark.parametrize("reference_text", [ARTICLE, ARTICLE + " Additional observations."])
def test_reference_rejects_equivalent_uuid_representations(reference_uuid, via_config, reference_text):
    reference = attribute(reference_text, uuid=reference_uuid)
    result = run(**{"reference": json.dumps(reference)}) if via_config else run(reference=reference)
    assert result == {"error": "Reference must have a different attribute UUID."}


def test_distinct_noncanonical_reference_uuid_preserves_input_metadata():
    reference = {**attribute(uuid=REFERENCE_UUID.upper()), "comment": "Keep this spelling", "to_ids": True}
    result = run(reference=reference)
    assert comparison(result)["exact_match"]
    assert result["results"]["Attribute"][1] == reference
    fingerprints = objects(result)
    assert len({obj["uuid"] for obj in fingerprints}) == 2
    annotation = objects(result, "annotation")[0]
    assert len({ref["referenced_uuid"] for ref in annotation["ObjectReference"]}) == 2


def test_tool_timeout_and_output_limit(tmp_path):
    import sys

    with pytest.raises(ValueError, match="timeout"):
        module.run_tool([sys.executable, "-c", "import time; time.sleep(10)"], tmp_path, 0)
    with patch.object(module, "MAX_OUTPUT", 10), pytest.raises(ValueError, match="output limit"):
        module.run_tool([sys.executable, "-c", "print('a' * 100)"], tmp_path, module.time.monotonic() + 5)


def test_discovery_and_offline_text():
    assert module.handler() is False
    assert module.introspection()["format"] == "misp_standard"
    assert module.version()["module-type"] == ["expansion"]
    assert misp_modules.is_valid_module(
        module.resources.files("misp_modules").joinpath("modules/expansion/content_fingerprint.py")
    )
    with patch("socket.socket", side_effect=AssertionError("No network")):
        assert objects(run())


class TestContentFingerprintHTTP(AsyncHTTPTestCase):
    def get_app(self):
        self.patch = patch.object(
            server, "MODULES_HANDLERS", {"content_fingerprint": module, "type:content_fingerprint": "expansion"}
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)
        return Application([(r"/modules", server.ListModules), (r"/query", server.QueryModule)])

    def test_discovery_and_comparison(self):
        discovery = json.loads(self.fetch("/modules").body)
        assert discovery[0]["name"] == "content_fingerprint"
        response = self.fetch(
            "/query",
            method="POST",
            body=json.dumps(
                {
                    "module": "content_fingerprint",
                    "attribute": attribute(),
                    "reference": attribute(ARTICLE, uuid=REFERENCE_UUID),
                }
            ),
        )
        assert response.code == 200
        assert comparison(json.loads(response.body))["exact_match"]
