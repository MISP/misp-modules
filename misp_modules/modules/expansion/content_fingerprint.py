"""Offline exact and approximate fingerprints with optional pairwise comparison."""

import base64
import binascii
import hashlib
import json
import math
import re
import shutil
import statistics
import subprocess
import time
import unicodedata
from importlib import resources
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid5

from pymisp import MISPObject

mispattributes = {"input": ["text", "attachment"], "format": "misp_standard"}
moduleconfig = ["content_type", "reference", "sample_interval", "max_frames", "timeout"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "Content fingerprint",
    "description": "Fingerprint text, images and video, and compare supplied content with a reference item.",
    "module-type": ["expansion"],
    "requirements": [
        "pymisp",
        "FFmpeg and ffprobe >= 5 on PATH for image/video input",
        "Bundled content-fingerprint object template",
    ],
    "references": ["https://ffmpeg.org/ffmpeg.html", "https://doi.org/10.1145/509907.509965"],
    "features": (
        "Offline SHA-256, Unicode-normalised text hashes, word-shingle SimHash and perceptual image/video frame hashes."
        " Records algorithm versions, parameters, decoder version and sample timestamps. An optional reference returns"
        " distances, shared text shingles or aligned video frames. All derived attributes use to_ids=false. See"
        " https://github.com/MISP/misp-modules/blob/main/documentation/expansion/content_fingerprint.md."
    ),
    "input": "A text attribute or base64 image/video/text attachment; optional reference attribute.",
    "output": "content-fingerprint objects and an optional annotation object containing pairwise similarity evidence.",
}

MAX_BYTES = 50 * 1024 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_TOKENS = 100000
MAX_PIXELS = 16000000
MAX_OUTPUT = 1024 * 1024
TEXT_VERSION = "v1-u" + unicodedata.unidata_version
PHASH_VERSION = "phash63-dct32-v1"
FORMATS = "mov,matroska,webm,avi,png_pipe,jpeg_pipe,webp_pipe,bmp_pipe,tiff_pipe,gif,image2"
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff", ".gif"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".m4v", ".webm", ".mkv", ".avi"}
COSINES = [[math.cos(math.pi * (2 * x + 1) * u / 64) for x in range(32)] for u in range(8)]


def integer(config, name, default, minimum, maximum):
    value = config.get(name)
    if value in (None, ""):
        return default
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)) or not minimum <= int(value) <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}.")
    return int(value)


def read_attribute(attribute, fallback_data=None):
    if not isinstance(attribute, dict) or attribute.get("type") not in mispattributes["input"]:
        raise ValueError("Expected a text or attachment attribute with type, value and uuid.")
    if not isinstance(attribute.get("value"), str) or not attribute["value"].strip():
        raise ValueError("The input attribute must have a nonempty string value.")
    UUID(attribute.get("uuid", ""))
    attribute = dict(attribute)
    if attribute["type"] == "text":
        raw = attribute["value"].encode("utf-8")
    else:
        data = attribute.get("data", fallback_data)
        if not isinstance(data, str) or len(data) > 4 * ((MAX_BYTES + 2) // 3):
            raise ValueError("Missing base64 attachment data or input exceeds 50 MiB.")
        try:
            raw = base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("Invalid base64 attachment data.") from error
        attribute["data"] = data
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("Input must contain between 1 byte and 50 MiB.")
    return attribute, raw


def content_type(attribute, raw, selected):
    if selected not in ("auto", "text", "image", "video"):
        raise ValueError("content_type must be auto, text, image or video.")
    if selected != "auto":
        return selected
    if attribute["type"] == "text":
        return "text"
    extension = Path(attribute["value"]).suffix.lower()
    if extension in IMAGE_EXTENSIONS:
        return "image"
    if extension in VIDEO_EXTENSIONS:
        return "video"
    if raw.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM", b"II*\0", b"MM\0*")):
        return "image"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image"
    if raw[4:8] == b"ftyp" or raw.startswith(b"\x1aE\xdf\xa3") or (raw[:4] == b"RIFF" and raw[8:12] == b"AVI "):
        return "video"
    return "text"


def text_profile(raw):
    if len(raw) > MAX_TEXT_BYTES:
        raise ValueError("Text input exceeds 2 MiB.")
    text = raw.decode("utf-8-sig")
    tokens = re.findall(r"[^\W_]+", unicodedata.normalize("NFKC", text).casefold())
    if len(tokens) > MAX_TOKENS:
        raise ValueError("Text input exceeds 100000 tokens.")
    normalised = " ".join(tokens)
    shingles = {" ".join(tokens[i : i + 5]) for i in range(max(0, len(tokens) - 4))}
    weights = [0] * 64
    for shingle in sorted(shingles):
        value = int.from_bytes(hashlib.sha256(shingle.encode()).digest()[:8], "big")
        for bit in range(64):
            weights[bit] += 1 if value & (1 << bit) else -1
    value = sum(1 << bit for bit, weight in enumerate(weights) if weight >= 0)
    return {
        "normalised_sha256": hashlib.sha256(normalised.encode()).hexdigest() if tokens else None,
        "normalisation": {
            "version": TEXT_VERSION,
            "steps": ["UTF-8-sig", "NFKC", "casefold", "Unicode word tokens", "join with ASCII space"],
        },
        "simhash": {
            "algorithm": "simhash64",
            "version": TEXT_VERSION,
            "value": f"{value:016x}" if shingles else None,
            "shingle_words": 5,
            "shingle_weighting": "distinct",
            "feature_hash": "SHA-256 first 64 bits big-endian",
            "tie_bit": 1,
            "usable": len(shingles) >= 3,
        },
        "token_count": len(tokens),
        "distinct_shingles": len(shingles),
    }, shingles


def run_tool(command, directory, deadline):
    """Bound subprocess time and captured output, including malformed-media diagnostics."""
    if time.monotonic() >= deadline:
        raise ValueError("Media processing exceeded its timeout.")
    out, err = Path(directory) / "stdout", Path(directory) / "stderr"
    with out.open("wb") as stdout, err.open("wb") as stderr:
        try:
            with subprocess.Popen(command, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL) as process:
                while process.poll() is None:
                    if (
                        time.monotonic() >= deadline
                        or out.stat().st_size > MAX_OUTPUT
                        or err.stat().st_size > MAX_OUTPUT
                    ):
                        process.kill()
                        process.wait()
                        raise ValueError("Media processing exceeded its timeout or 1 MiB output limit.")
                    time.sleep(0.02)
                if process.returncode:
                    raise ValueError("FFmpeg could not decode the supplied media.")
        except OSError as error:
            raise ValueError("Unable to execute FFmpeg/ffprobe; install FFmpeg >= 5 on PATH.") from error
    if out.stat().st_size > MAX_OUTPUT or err.stat().st_size > MAX_OUTPUT:
        raise ValueError("Media processing exceeded the 1 MiB output limit.")
    return out.read_bytes(), err.read_text(errors="replace")


def phash(pixels):
    """DCT-II on 32x32 luma; 63 AC bits, median threshold, DC fixed to zero."""
    rows = [[sum(pixels[y * 32 + x] * COSINES[u][x] for x in range(32)) for u in range(8)] for y in range(32)]
    coefficients = []
    for v in range(8):
        for u in range(8):
            factor = (1 / math.sqrt(2) if u == 0 else 1) * (1 / math.sqrt(2) if v == 0 else 1)
            coefficients.append(factor * sum(rows[y][u] * COSINES[v][y] for y in range(32)))
    median = statistics.median(coefficients[1:])
    value = sum(1 << (63 - i) for i, coefficient in enumerate(coefficients) if i and coefficient > median)
    deviation = statistics.pstdev(pixels)
    return {"value": f"{value:016x}", "usable": deviation >= 5, "luma_stddev": round(deviation, 4)}


def media_profile(raw, kind, config, deadline):
    ffmpeg, ffprobe = shutil.which("ffmpeg"), shutil.which("ffprobe")
    if not ffmpeg or not ffprobe:
        raise ValueError("Image/video fingerprints require FFmpeg and ffprobe >= 5 on PATH.")
    interval = integer(config, "sample_interval", 1, 1, 60)
    limit = integer(config, "max_frames", 120, 2, 300)
    with TemporaryDirectory(prefix="misp-content-fingerprint-") as directory:
        path = Path(directory) / "media.bin"
        path.write_bytes(raw)
        version, _ = run_tool([ffmpeg, "-version"], directory, deadline)
        decoder = version.decode(errors="replace").splitlines()[0]
        options = [
            "-max_alloc",
            "67108864",
            "-protocol_whitelist",
            "file,pipe",
            "-format_whitelist",
            FORMATS,
            "-max_pixels",
            str(MAX_PIXELS),
        ]
        output, _ = run_tool(
            [
                ffprobe,
                "-v",
                "error",
                *options,
                "-select_streams",
                "v:0",
                "-show_entries",
                "stream=width,height,codec_name:format=duration,format_name",
                "-of",
                "json",
                str(path),
            ],
            directory,
            deadline,
        )
        probe = json.loads(output)
        streams = probe.get("streams", [])
        if not streams or not isinstance(streams[0], dict):
            raise ValueError("Media must contain a decodable visual stream.")
        stream = streams[0]
        width, height = stream.get("width", 0), stream.get("height", 0)
        if (
            not isinstance(width, int)
            or not isinstance(height, int)
            or min(width, height) < 1
            or width * height > MAX_PIXELS
        ):
            raise ValueError("Media dimensions must be positive and at most 16 million pixels.")
        select = f"select='isnan(prev_selected_t)+gte(t-prev_selected_t,{interval})'," if kind == "video" else ""
        output, diagnostics = run_tool(
            [
                ffmpeg,
                "-hide_banner",
                "-nostdin",
                "-v",
                "info",
                "-threads",
                "1",
                *options,
                "-i",
                str(path),
                "-map",
                "0:v:0",
                "-an",
                "-sn",
                "-dn",
                "-vf",
                select + "format=rgba,premultiply=inplace=1,scale=32:32:flags=area,format=gray,showinfo",
                "-frames:v",
                str(limit + 1 if kind == "video" else 1),
                "-fps_mode",
                "passthrough",
                "-pix_fmt",
                "gray",
                "-f",
                "rawvideo",
                "pipe:1",
            ],
            directory,
            deadline,
        )
    if not output or len(output) % 1024:
        raise ValueError("FFmpeg returned incomplete frame data.")
    timestamps = [float(t) for t in re.findall(r"\bn:\s*\d+\s+pts:\s*-?\d+\s+pts_time:([-+\d.eE]+)", diagnostics)]
    count = len(output) // 1024
    if len(timestamps) != count or any(not math.isfinite(t) for t in timestamps):
        raise ValueError("FFmpeg did not return reliable frame timestamps.")
    frames = [
        {"index": i, "timestamp_seconds": timestamps[i], **phash(output[i * 1024 : (i + 1) * 1024])}
        for i in range(min(count, limit))
    ]
    return {
        "algorithm": PHASH_VERSION,
        "version": 1,
        "bits": 63,
        "decoder": decoder,
        "preprocessing": (
            "FFmpeg autorotate, first visual stream, RGBA premultiply onto black, area resize to 32x32, gray pixel"
            " format"
        ),
        "parameters": {
            "DCT": (
                "II, orthogonal DC factors, 8x8 low frequencies, exclude DC, strict greater-than median AC, row-major"
                " MSB-first"
            )
        },
        "width": width,
        "height": height,
        "codec": stream.get("codec_name"),
        "sample_interval_seconds": interval if kind == "video" else None,
        "truncated": count > limit,
        "coverage": "first image frame" if kind == "image" else "sampled frames; audio excluded",
        "frames": frames,
    }


def profile(attribute, raw, config, deadline):
    kind = content_type(attribute, raw, config.get("content_type") or "auto")
    report = {
        "schema_version": 1,
        "content_type": kind,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "exact_algorithm": {
            "name": "SHA-256",
            "version": "FIPS-180-4",
            "scope": "original bytes; UTF-8 for text attributes",
        },
        "size_bytes": len(raw),
    }
    shingles = set()
    if kind == "text":
        report["text"], shingles = text_profile(raw)
    else:
        report["media"] = media_profile(raw, kind, config, deadline)
    return report, shingles


def distance(a, b):
    return (int(a, 16) ^ int(b, 16)).bit_count()


def compare(left, right, left_shingles, right_shingles):
    kind = left["content_type"]
    if kind != right["content_type"]:
        raise ValueError("Input and reference must have the same content type.")
    result = {
        "schema_version": 1,
        "content_type": kind,
        "exact_match": left["sha256"] == right["sha256"],
        "source_sha256": left["sha256"],
        "reference_sha256": right["sha256"],
        "interpretation": "Candidate content similarity, not proof of common authorship or ownership.",
    }
    if kind == "text":
        a, b = left["text"], right["text"]
        shared = left_shingles & right_shingles
        union = left_shingles | right_shingles
        hamming = (
            distance(a["simhash"]["value"], b["simhash"]["value"])
            if a["simhash"]["value"] and b["simhash"]["value"]
            else None
        )
        jaccard = len(shared) / len(union) if union else None
        usable = a["simhash"]["usable"] and b["simhash"]["usable"]
        result.update(
            algorithm="simhash64",
            version=TEXT_VERSION,
            hamming_distance=hamming,
            normalised_match=bool(a["normalised_sha256"] and a["normalised_sha256"] == b["normalised_sha256"]),
            shared_shingles=len(shared),
            jaccard=jaccard,
            matching_shingle_examples=sorted(shared)[:5],
            usable=usable,
            similar=bool(usable and hamming <= 10 and jaccard >= 0.5),
            decision_rule={"max_hamming": 10, "min_jaccard": 0.5, "min_distinct_shingles_per_item": 3},
        )
    else:
        a, b = left["media"], right["media"]
        if a["algorithm"] != b["algorithm"] or a["decoder"] != b["decoder"]:
            raise ValueError("Media comparisons require the same fingerprint and decoder versions.")
        rows = [0] * (len(b["frames"]) + 1)
        best, end = 0, (0, 0)
        tolerance = 0.25 * (a["sample_interval_seconds"] or 1)
        for i, first in enumerate(a["frames"]):
            current = [0] * len(rows)
            for j, second in enumerate(b["frames"]):
                if first["usable"] and second["usable"] and distance(first["value"], second["value"]) <= 10:
                    aligned = (
                        i > 0
                        and j > 0
                        and abs(
                            (first["timestamp_seconds"] - a["frames"][i - 1]["timestamp_seconds"])
                            - (second["timestamp_seconds"] - b["frames"][j - 1]["timestamp_seconds"])
                        )
                        <= tolerance
                    )
                    current[j + 1] = rows[j] + 1 if aligned else 1
                    if current[j + 1] > best:
                        best, end = current[j + 1], (i + 1, j + 1)
            rows = current
        matches = [
            {
                "source_frame": x,
                "reference_frame": y,
                "source_seconds": a["frames"][x]["timestamp_seconds"],
                "reference_seconds": b["frames"][y]["timestamp_seconds"],
                "hamming_distance": distance(a["frames"][x]["value"], b["frames"][y]["value"]),
            }
            for x, y in zip(range(end[0] - best, end[0]), range(end[1] - best, end[1]))
        ]
        result.update(
            algorithm=PHASH_VERSION,
            version=1,
            bits=63,
            max_hamming=10,
            matching_frames=matches,
            longest_matching_run=best,
            similar=best >= (2 if kind == "video" else 1),
            min_matching_run=2 if kind == "video" else 1,
            max_step_difference_seconds=tolerance if kind == "video" else None,
            source_truncated=a["truncated"],
            reference_truncated=b["truncated"],
        )
    return result


def fingerprint_object(attribute, report):
    template = json.loads(
        resources.files("misp_modules").joinpath("data/content-fingerprint/definition.json").read_text()
    )
    obj = MISPObject("content-fingerprint", strict=True, standalone=False, misp_objects_template_custom=template)
    obj.uuid = uuid5(UUID(attribute["uuid"]), "content-fingerprint-v1:" + json.dumps(report, sort_keys=True))
    obj.add_attribute("sha256", value=report["sha256"], to_ids=False, disable_correlation=False)
    obj.add_attribute("content-type", value=report["content_type"], to_ids=False, disable_correlation=True)
    obj.add_attribute("metadata", value=json.dumps(report, sort_keys=True), to_ids=False, disable_correlation=True)
    keys = []
    if "text" in report:
        text = report["text"]
        if text["normalised_sha256"]:
            keys.append(f"text-normalised-sha256-{TEXT_VERSION}:{text['normalised_sha256']}")
        if text["simhash"]["usable"]:
            keys.append(f"text-simhash64-{TEXT_VERSION}:{text['simhash']['value']}")
    else:
        keys.extend(f"{PHASH_VERSION}:{frame['value']}" for frame in report["media"]["frames"] if frame["usable"])
    for key in sorted(set(keys)):
        obj.add_attribute("fingerprint", value=key, to_ids=False, disable_correlation=False)
    obj.add_reference(attribute["uuid"], "fingerprint-of")
    return obj


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Expected a JSON object.")
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("config must be an object.")
        deadline = time.monotonic() + integer(config, "timeout", 60, 1, 120)
        source, raw = read_attribute(request.get("attribute"), request.get("data"))
        report, shingles = profile(source, raw, config, deadline)
        source_object = fingerprint_object(source, report)
        attributes, objects = [source], [source_object]
        reference = request.get("reference", config.get("reference"))
        if isinstance(reference, str) and reference:
            reference = json.loads(reference)
        if reference not in (None, ""):
            ref, ref_raw = read_attribute(reference)
            if UUID(ref["uuid"]) == UUID(source["uuid"]):
                raise ValueError("Reference must have a different attribute UUID.")
            ref_report, ref_shingles = profile(ref, ref_raw, config, deadline)
            comparison = compare(report, ref_report, shingles, ref_shingles)
            ref_object = fingerprint_object(ref, ref_report)
            annotation = MISPObject("annotation", standalone=False)
            annotation.add_attribute(
                "text", value=json.dumps(comparison, sort_keys=True), to_ids=False, disable_correlation=True
            )
            annotation.add_reference(source_object.uuid, "compares")
            annotation.add_reference(ref_object.uuid, "compares")
            attributes.append(ref)
            objects.extend([ref_object, annotation])
        return {"results": {"Attribute": attributes, "Object": [json.loads(obj.to_json()) for obj in objects]}}
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError) as error:
        return {"error": str(error)}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
