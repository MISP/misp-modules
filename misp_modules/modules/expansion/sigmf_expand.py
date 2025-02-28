# -*- coding: utf-8 -*-

import base64
import io
import json
import logging
import sys
import tarfile
import tempfile

import matplotlib.pyplot as plt
import numpy as np
from pymisp import MISPEvent, MISPObject
from sigmf import SigMFFile
from sigmf.archive import SIGMF_DATASET_EXT, SIGMF_METADATA_EXT

log = logging.getLogger("sigmf-expand")
log.setLevel(logging.DEBUG)
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
sh.setFormatter(fmt)
log.addHandler(sh)

misperrors = {"error": "Error"}
mispattributes = {
    "input": ["sigmf-recording", "sigmf-archive"],
    "output": ["MISP objects"],
    "format": "misp_standard",
}
moduleinfo = {
    "version": "0.1",
    "author": "Luciano Righetti",
    "description": (
        "Expands a SigMF Recording object into a SigMF Expanded Recording object, extracts a SigMF archive into a SigMF"
        " Recording object."
    ),
    "module-type": ["expansion"],
    "name": "SigMF Expansion",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}


def get_samples(data_bytes, data_type) -> np.ndarray:
    """
    Get samples from bytes.

    Source: https://github.com/IQEngine/IQEngine/blob/main/api/rf/samples.py

    Parameters
    ----------
    data_bytes : bytes
        The bytes to convert to samples.
    data_type : str
        The data type of the bytes.

    Returns
    -------
    np.ndarray
        The samples.
    """

    if data_type == "ci16_le" or data_type == "ci16":
        samples = np.frombuffer(data_bytes, dtype=np.int16)
        samples = samples[::2] + 1j * samples[1::2]
    elif data_type == "cf32_le":
        samples = np.frombuffer(data_bytes, dtype=np.complex64)
    elif data_type == "ci8" or data_type == "i8":
        samples = np.frombuffer(data_bytes, dtype=np.int8)
        samples = samples[::2] + 1j * samples[1::2]
    else:
        raise ("Datatype " + data_type + " not implemented")
    return samples


def generate_plots(recording, meta_filename, data_bytes):
    # FFT plot
    filename = meta_filename.replace(".sigmf-data", "")
    samples = get_samples(data_bytes, recording.get_global_info()["core:datatype"])
    sample_rate = recording.get_global_info()["core:sample_rate"]

    # Waterfall plot
    # snippet from https://pysdr.org/content/frequency_domain.html#fast-fourier-transform-fft
    fft_size = 1024
    # // is an integer division which rounds down
    num_rows = len(samples) // fft_size
    spectrogram = np.zeros((num_rows, fft_size))
    for i in range(num_rows):
        spectrogram[i, :] = 10 * np.log10(
            np.abs(np.fft.fftshift(np.fft.fft(samples[i * fft_size : (i + 1) * fft_size]))) ** 2
        )

    plt.figure(figsize=(10, 4))
    plt.title(filename)
    plt.imshow(
        spectrogram,
        aspect="auto",
        extent=[
            sample_rate / -2 / 1e6,
            sample_rate / 2 / 1e6,
            0,
            len(samples) / sample_rate,
        ],
    )
    plt.xlabel("Frequency [MHz]")
    plt.ylabel("Time [ms]")
    plt.savefig(filename + "-spectrogram.png")
    waterfall_buff = io.BytesIO()
    plt.savefig(waterfall_buff, format="png")
    waterfall_buff.seek(0)
    waterfall_png = base64.b64encode(waterfall_buff.read()).decode("utf-8")

    waterfall_attr = {
        "type": "attachment",
        "value": filename + "-waterfall.png",
        "data": waterfall_png,
        "comment": "Waterfall plot of the recording",
    }

    return [{"relation": "waterfall-plot", "attribute": waterfall_attr}]


def process_sigmf_archive(object):

    event = MISPEvent()
    sigmf_data_attr = None
    sigmf_meta_attr = None

    try:
        # get sigmf-archive attribute
        for attribute in object["Attribute"]:
            if attribute["object_relation"] == "SigMF-archive":

                # write temp data file to disk
                sigmf_archive_file = tempfile.NamedTemporaryFile(suffix=".sigmf")
                sigmf_archive_bin = base64.b64decode(attribute["data"])
                with open(sigmf_archive_file.name, "wb") as f:
                    f.write(sigmf_archive_bin)
                    f.close()

                sigmf_tarfile = tarfile.open(sigmf_archive_file.name, mode="r", format=tarfile.PAX_FORMAT)

            files = sigmf_tarfile.getmembers()

            for file in files:
                if file.name.endswith(SIGMF_METADATA_EXT):
                    metadata_reader = sigmf_tarfile.extractfile(file)
                    sigmf_meta_attr = {
                        "type": "attachment",
                        "value": file.name,
                        "data": base64.b64encode(metadata_reader.read()).decode("utf-8"),
                        "comment": "SigMF metadata file",
                        "object_relation": "SigMF-meta",
                    }

                if file.name.endswith(SIGMF_DATASET_EXT):
                    data_reader = sigmf_tarfile.extractfile(file)
                    sigmf_data_attr = {
                        "type": "attachment",
                        "value": file.name,
                        "data": base64.b64encode(data_reader.read()).decode("utf-8"),
                        "comment": "SigMF data file",
                        "object_relation": "SigMF-data",
                    }

            if sigmf_meta_attr is None:
                return {"error": "No SigMF metadata file found"}

            recording = MISPObject("sigmf-recording")
            recording.add_attribute(**sigmf_meta_attr)
            recording.add_attribute(**sigmf_data_attr)

            # add reference to original SigMF Archive object
            recording.add_reference(object["uuid"], "expands")

            event.add_object(recording)
            event = json.loads(event.to_json())

            return {"results": {"Object": event["Object"]}}

        # no sigmf-archive attribute found
        return {"error": "No SigMF-archive attribute found"}

    except Exception as e:
        logging.exception(e)
        return {"error": "An error occured when processing the SigMF archive"}


def process_sigmf_recording(object):

    event = MISPEvent()

    for attribute in object["Attribute"]:
        if attribute["object_relation"] == "SigMF-data":
            sigmf_data_attr = attribute

        if attribute["object_relation"] == "SigMF-meta":
            sigmf_meta_attr = attribute

    if sigmf_meta_attr is None:
        return {"error": "No SigMF-data attribute"}

    if sigmf_data_attr is None:
        return {"error": "No SigMF-meta attribute"}

    try:
        sigmf_meta = base64.b64decode(sigmf_meta_attr["data"]).decode("utf-8")
        sigmf_meta = json.loads(sigmf_meta)
    except Exception as e:
        logging.exception(e)
        return {"error": "Provided .sigmf-meta is not a valid JSON string"}

    # write temp data file to disk
    sigmf_data_file = tempfile.NamedTemporaryFile(suffix=".sigmf-data")
    sigmf_data_bin = base64.b64decode(sigmf_data_attr["data"])
    with open(sigmf_data_file.name, "wb") as f:
        f.write(sigmf_data_bin)
        f.close()

    try:
        recording = SigMFFile(metadata=sigmf_meta, data_file=sigmf_data_file.name)
    except Exception as e:
        logging.exception(e)
        return {"error": "Provided .sigmf-meta and .sigmf-data is not a valid SigMF file"}

    expanded_sigmf = MISPObject("sigmf-expanded-recording")

    if "core:author" in sigmf_meta["global"]:
        expanded_sigmf.add_attribute("author", **{"type": "text", "value": sigmf_meta["global"]["core:author"]})
    if "core:datatype" in sigmf_meta["global"]:
        expanded_sigmf.add_attribute(
            "datatype",
            **{"type": "text", "value": sigmf_meta["global"]["core:datatype"]},
        )
    if "core:description" in sigmf_meta["global"]:
        expanded_sigmf.add_attribute(
            "description",
            **{"type": "text", "value": sigmf_meta["global"]["core:description"]},
        )
    if "core:license" in sigmf_meta["global"]:
        expanded_sigmf.add_attribute("license", **{"type": "text", "value": sigmf_meta["global"]["core:license"]})
    if "core:num_channels" in sigmf_meta["global"]:
        expanded_sigmf.add_attribute(
            "num_channels",
            **{"type": "counter", "value": sigmf_meta["global"]["core:num_channels"]},
        )
    if "core:recorder" in sigmf_meta["global"]:
        expanded_sigmf.add_attribute(
            "recorder",
            **{"type": "text", "value": sigmf_meta["global"]["core:recorder"]},
        )
    if "core:sample_rate" in sigmf_meta["global"]:
        expanded_sigmf.add_attribute(
            "sample_rate",
            **{"type": "float", "value": sigmf_meta["global"]["core:sample_rate"]},
        )
    if "core:sha512" in sigmf_meta["global"]:
        expanded_sigmf.add_attribute("sha512", **{"type": "text", "value": sigmf_meta["global"]["core:sha512"]})
    if "core:version" in sigmf_meta["global"]:
        expanded_sigmf.add_attribute("version", **{"type": "text", "value": sigmf_meta["global"]["core:version"]})

    # add reference to original SigMF Recording object
    expanded_sigmf.add_reference(object["uuid"], "expands")

    # add FFT and waterfall plot
    try:
        plots = generate_plots(recording, sigmf_data_attr["value"], sigmf_data_bin)
    except Exception as e:
        logging.exception(e)
        return {"error": "Could not generate plots"}

    for plot in plots:
        expanded_sigmf.add_attribute(plot["relation"], **plot["attribute"])

    event.add_object(expanded_sigmf)
    event = json.loads(event.to_json())

    return {"results": {"Object": event["Object"]}}


def handler(q=False):
    request = json.loads(q)
    object = request.get("object")

    if not object:
        return {"error": "No object provided"}

    if "Attribute" not in object:
        return {"error": "Empty Attribute list"}

    # check if it's a SigMF Archive
    if object["name"] == "sigmf-archive":
        return process_sigmf_archive(object)

    # check if it's a SigMF Recording
    if object["name"] == "sigmf-recording":
        return process_sigmf_recording(object)

    # TODO: add support for SigMF Collection

    return {"error": "No SigMF object provided"}


def introspection():
    return mispattributes


def version():
    return moduleinfo
