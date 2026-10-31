"""Generate binGraph-style static plots without executing or writing the sample."""

import base64
import binascii
import hashlib
import json
import logging
import math
import re
import zipfile
from io import BytesIO
from threading import Lock
from uuid import UUID

import numpy as np
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
from matplotlib.ticker import FuncFormatter
from pymisp import MISPObject

mispattributes = {"input": ["attachment", "malware-sample"], "format": "misp_standard"}
moduleconfig = ["graph_type", "chunks", "max_size_mb"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "binGraph",
    "description": "Create entropy and byte histogram PNG plots of an attachment or malware sample.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["matplotlib", "numpy", "pymisp"],
    "features": (
        "Local static analysis inspired by geekscrapy/binGraph. Returns an image object referencing the source"
        " attribute. graph_type: all (default), ent or hist. chunks: maximum entropy windows (default 750)."
        " max_size_mb: maximum input and unpacked sample size (default 10, maximum 50 MiB)."
        " MISP malware-sample ZIPs use password infected; the unpacked MD5 is verified."
    ),
    "references": ["https://github.com/geekscrapy/binGraph"],
    "input": "An attachment or malware-sample attribute with UUID and base64-encoded data.",
    "output": "An image MISP object containing a PNG, analysis metadata and a visualizes reference to the source.",
}
_RENDER_LOCK = Lock()  # Matplotlib font and rendering state is shared across request threads.
_LOG = logging.getLogger(__name__)


class ModuleError(ValueError):
    """An input error safe to return to the caller."""


def _integer(config, name, default, maximum):
    value = config.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not str(value).isdigit() or not 1 <= int(value) <= maximum:
        raise ModuleError(f"{name} must be an integer between 1 and {maximum}.")
    return int(value)


def _sample(attribute, limit):
    encoded = attribute.get("data")
    if not isinstance(encoded, str) or not encoded:
        raise ModuleError("The attribute must contain nonempty base64-encoded data.")
    if len(encoded) > 4 * ((limit + 2) // 3):
        raise ModuleError("The encoded input exceeds max_size_mb.")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ModuleError("The attribute data is not valid base64.") from None
    if len(raw) > limit:
        raise ModuleError("The input exceeds max_size_mb.")
    if attribute["type"] == "attachment":
        if not raw:
            raise ModuleError("Empty files cannot be graphed.")
        return raw

    filename, separator, expected_md5 = attribute["value"].rpartition("|")
    if not separator or not filename or not re.fullmatch(r"[a-fA-F0-9]{32}", expected_md5):
        raise ModuleError("A malware-sample value must be filename|md5.")
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            members = archive.infolist()
            # Current MISP: <md5> plus <md5>.filename.txt. Legacy: one sample file.
            if len(members) == 2 and {m.filename for m in members} == {
                expected_md5.lower(),
                expected_md5.lower() + ".filename.txt",
            }:
                member = archive.getinfo(expected_md5.lower())
                metadata = archive.getinfo(expected_md5.lower() + ".filename.txt")
                if metadata.file_size > 4096:
                    raise ModuleError("The malware-sample filename metadata is too large.")
            elif len(members) == 1 and not members[0].is_dir():
                member = members[0]
            else:
                raise ModuleError("Expected a single sample or a MISP sample with filename metadata in the ZIP.")
            if member.file_size > limit:
                raise ModuleError("The unpacked sample exceeds max_size_mb.")
            with archive.open(member, pwd=b"infected") as stream:
                raw = stream.read(limit + 1)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError):
        raise ModuleError("Cannot read the malware-sample ZIP with password infected.") from None
    if len(raw) > limit:
        raise ModuleError("The unpacked sample exceeds max_size_mb.")
    if not raw:
        raise ModuleError("Empty files cannot be graphed.")
    if hashlib.md5(raw, usedforsecurity=False).hexdigest() != expected_md5.lower():
        raise ModuleError("The unpacked sample MD5 does not match the malware-sample attribute.")
    return raw


def _entropy(counts):
    probabilities = counts[counts > 0] / counts.sum()
    return float(-(probabilities * np.log2(probabilities)).sum())


def _analyse(raw, chunks):
    data = np.frombuffer(raw, dtype=np.uint8)
    # Keep short files meaningful: one-byte windows would always have zero entropy.
    window_size = max(256, math.ceil(len(raw) / chunks))
    offsets, entropies, zeroes, ones = [], [], [], []
    histogram = np.zeros(256, dtype=np.int64)
    for offset in range(0, len(raw), window_size):
        window = data[offset : offset + window_size]
        counts = np.bincount(window, minlength=256)
        histogram += counts
        offsets.append(offset)
        entropies.append(_entropy(counts))
        zeroes.append(100 * int(counts[0]) / len(window))
        ones.append(100 * int(counts[255]) / len(window))
    return {
        "histogram": histogram,
        "offsets": offsets,
        "entropies": entropies,
        "zeroes": zeroes,
        "ones": ones,
        "window_size": window_size,
        "entropy": _entropy(histogram),
    }


def _render(analysis, filename, size, sha256, graph_type):
    with _RENDER_LOCK:
        figure = Figure(figsize=(12, 8 if graph_type == "all" else 5), dpi=120)
        FigureCanvasAgg(figure)
        try:
            axes = np.atleast_1d(figure.subplots(2 if graph_type == "all" else 1, 1))
            figure.suptitle(f"binGraph — {filename}", fontsize=14, parse_math=False)
            if graph_type in ("all", "ent"):
                axis = axes[0]
                axis.plot(analysis["offsets"], analysis["entropies"], color="#ab277e", label="Entropy", marker=".")
                axis.set(xlabel="File offset (bytes)", ylabel="Shannon entropy (bits/byte)", ylim=(0, 8.2))
                axis.set_xlim(0, max(size, 1))
                axis.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f"0x{int(value):X}"))
                occurrence = axis.twinx()
                for key, label, color in (("zeroes", "0x00", "#248a34"), ("ones", "0xFF", "#c27900")):
                    occurrence.plot(
                        analysis["offsets"], analysis[key], label=label, color=color, alpha=0.65, marker="."
                    )
                occurrence.set(ylabel="Byte occurrence (%)", ylim=(0, 102))
                lines = axis.get_lines() + occurrence.get_lines()
                axis.legend(lines, [line.get_label() for line in lines], loc="upper right")
                axis.set_title(f"Entropy by window ({analysis['window_size']:,} bytes; final window may be shorter)")
                axis.grid(alpha=0.2)
            if graph_type in ("all", "hist"):
                axis = axes[-1]
                counts = analysis["histogram"]
                # Omit zeros, since they cannot be represented on a logarithmic scale.
                present = np.flatnonzero(counts)
                axis.bar(present, counts[present], color="#b13b4a", alpha=0.65, label="Byte value order")
                ranked = np.sort(counts)[::-1]
                axis.plot(range(256), np.where(ranked > 0, ranked, np.nan), color="#2763a0", label="Ranked counts")
                axis.set(xlabel="Byte value / frequency rank", ylabel="Count (log scale)", xlim=(-1, 256))
                axis.set_yscale("log")
                axis.set_xticks([0, 32, 64, 96, 128, 160, 192, 224, 255])
                axis.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{int(value):02X}"))
                axis.set_title("Byte histogram and frequency distribution")
                axis.legend(loc="upper right")
                axis.grid(axis="y", alpha=0.2)
            figure.text(
                0.02,
                0.02,
                f"{size:,} bytes | Overall entropy: {analysis['entropy']:.4f} bits/byte\nSHA-256: {sha256}",
                fontsize=8,
                family="monospace",
            )
            figure.tight_layout(rect=(0, 0.07, 1, 0.95))
            output = BytesIO()
            figure.savefig(output, format="png")
            return output.getvalue()
        finally:
            figure.clear()


def dict_handler(request):
    try:
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all(attribute.get(key) for key in ("type", "value", "uuid")):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Expected an attachment or malware-sample attribute.")
        if not isinstance(attribute["value"], str) or not attribute["value"].strip():
            raise ModuleError("The attribute value must be a nonempty filename.")
        UUID(attribute["uuid"])
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        graph_type = config.get("graph_type") or "all"
        if graph_type not in ("all", "ent", "hist"):
            raise ModuleError("graph_type must be all, ent or hist.")
        chunks = _integer(config, "chunks", 750, 4096)
        limit = _integer(config, "max_size_mb", 10, 50) * 1024 * 1024
        raw = _sample(attribute, limit)
        filename = attribute["value"].rsplit("|", 1)[0] if attribute["type"] == "malware-sample" else attribute["value"]
        # Untrusted filenames are display text only, never filesystem paths or math expressions.
        filename = re.sub(r"[^\x20-\x7e]", "_", filename.replace("\\", "/").rsplit("/", 1)[-1])[:100] or "sample"
        analysis = _analyse(raw, chunks)
        digest = hashlib.sha256(raw).hexdigest()
        png = _render(analysis, filename, len(raw), digest, graph_type)
        metadata = {
            "generator": "misp-modules/bingraph",
            "version": moduleinfo["version"],
            "filename": filename,
            "sha256": digest,
            "size_in_bytes": len(raw),
            "graph_type": graph_type,
            "entropy_bits_per_byte": analysis["entropy"],
            "requested_chunks": chunks,
            "window_size_in_bytes": analysis["window_size"],
            "window_count": len(analysis["offsets"]),
        }
        image = MISPObject("image", strict=True, standalone=False)
        image.comment = "Static binary visualization inspired by geekscrapy/binGraph."
        image_name = f"{digest}-bingraph-{graph_type}.png"
        for relation, value in (("filename", image_name), ("image-text", json.dumps(metadata, sort_keys=True))):
            image.add_attribute(relation, value=value, to_ids=False, disable_correlation=True)
        image.add_attribute("attachment", value=image_name, data=BytesIO(png), to_ids=False, disable_correlation=True)
        image.add_reference(attribute["uuid"], "visualizes")
        # Preserve the source verbatim, including binary data and any parent object context.
        return {"results": {"Attribute": [dict(attribute)], "Object": [json.loads(image.to_json())]}}
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return {"error": "Invalid binGraph request or configuration."}
    except Exception:
        _LOG.exception("binGraph image generation failed")
        return {"error": "Could not generate the binGraph image. Check the module server logs."}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (ValueError, TypeError):
        return {"error": "The request must be valid JSON."}
    return dict_handler(request)


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
