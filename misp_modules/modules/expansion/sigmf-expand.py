# -*- coding: utf-8 -*-

import base64
import numpy as np
import matplotlib.pyplot as plt
import io
import json
import tempfile
import logging
import sys
from pymisp import MISPObject, MISPEvent
from sigmf import SigMFFile
import pymisp

log = logging.getLogger("sigmf-expand")
log.setLevel(logging.DEBUG)
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
fmt = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
sh.setFormatter(fmt)
log.addHandler(sh)

misperrors = {'error': 'Error'}
mispattributes = {'input': ['sigmf-recording'], 'output': [
    'MISP objects'], 'format': 'misp_standard'}
moduleinfo = {'version': '0.1', 'author': 'Luciano Righetti',
              'description': 'Expand a SigMF Recording object into a SigMF Expanded Recording object.',
              'module-type': ['expansion']}


def generate_plots(recording, meta_filename):
    # FFT plot
    filename = meta_filename.replace('.sigmf-data', '')
    # snippet from https://gist.github.com/daniestevez/0d519fd4044f3b9f44e170fd619fbb40
    NFFT = 2048
    N = NFFT * 4096
    fs = recording.get_global_info()['core:sample_rate']
    x = np.fromfile(recording.data_file, 'int16', count=2*N)
    x = x[::2] + 1j * x[1::2]

    # f = np.fft.fftshift(np.average(
    #     np.abs(np.fft.fft(x.reshape(-1, NFFT)))**2, axis=0))
    # freq = np.fft.fftshift(np.fft.fftfreq(NFFT, 1/fs))

    # plt.figure(figsize=(10, 4))
    # plt.plot(1e-6 * freq, 10*np.log10(f))
    # plt.title(filename)
    # plt.ylabel('PSD (dB)')
    # plt.xlabel('Baseband frequency (MHz)')
    # fft_buff = io.BytesIO()
    # plt.savefig(fft_buff, format='png')
    # fft_buff.seek(0)
    # fft_png = base64.b64encode(fft_buff.read()).decode('utf-8')

    # fft_attr = {
    #     'type': 'attachment',
    #     'value': filename + '-fft.png',
    #     'data': fft_png,
    #     'comment': 'FFT plot of the recording'
    # }

    # Waterfall plot
    # snippet from https://pysdr.org/content/frequency_domain.html#fast-fourier-transform-fft
    fft_size = 1024
    # // is an integer division which rounds down
    num_rows = len(x) // fft_size
    spectrogram = np.zeros((num_rows, fft_size))
    for i in range(num_rows):
        spectrogram[i, :] = 10 * \
            np.log10(np.abs(np.fft.fftshift(
                np.fft.fft(x[i*fft_size:(i+1)*fft_size])))**2)

    plt.figure(figsize=(10, 4))
    plt.title(filename)
    plt.imshow(spectrogram, aspect='auto', extent=[
               fs/-2/1e6, fs/2/1e6, 0, len(x)/fs])
    plt.xlabel("Frequency [MHz]")
    plt.ylabel("Time [ms]")
    plt.savefig(filename + '-spectrogram.png')
    waterfall_buff = io.BytesIO()
    plt.savefig(waterfall_buff, format='png')
    waterfall_buff.seek(0)
    waterfall_png = base64.b64encode(waterfall_buff.read()).decode('utf-8')

    waterfall_attr = {
        'type': 'attachment',
        'value': filename + '-waterfall.png',
        'data': waterfall_png,
        'comment': 'Waterfall plot of the recording'
    }

    # return [fft_attr, waterfall_attr]
    return [{'relation': 'waterfall-plot', 'attribute': waterfall_attr}]


def handler(q=False):
    request = json.loads(q)
    object = request.get("object")
    if not object:
        return {"error": "No object provided"}

    if 'Attribute' not in object:
        return {"error": "Empty Attribute list"}

    for attribute in object['Attribute']:
        if attribute['object_relation'] == 'SigMF-data':
            sigmf_data_attr = attribute

        if attribute['object_relation'] == 'SigMF-meta':
            sigmf_meta_attr = attribute

    if sigmf_meta_attr is None:
        return {"error": "No SigMF-data attribute"}

    if sigmf_data_attr is None:
        return {"error": "No SigMF-meta attribute"}

    try:
        sigmf_meta = base64.b64decode(sigmf_meta_attr['data']).decode('utf-8')
        sigmf_meta = json.loads(sigmf_meta)
    except Exception as e:
        logging.exception(e)
        return {"error": "Provided .sigmf-meta is not a valid JSON string"}

    # write temp data file to disk
    sigmf_data_file = tempfile.NamedTemporaryFile(suffix='.sigmf-data')
    sigmf_data_bin = base64.b64decode(sigmf_data_attr['data'])
    with open(sigmf_data_file.name, 'wb') as f:
        f.write(sigmf_data_bin)
        f.close()

    try:
        recording = SigMFFile(
            metadata=sigmf_meta,
            data_file=sigmf_data_file.name
        )
    except Exception as e:
        logging.exception(e)
        return {"error": "Provided .sigmf-meta and .sigmf-data is not a valid SigMF file"}

    event = MISPEvent()
    expanded_sigmf = MISPObject('sigmf-expanded-recording')

    if 'core:author' in sigmf_meta['global']:
        expanded_sigmf.add_attribute(
            'author', **{'type': 'text', 'value': sigmf_meta['global']['core:author']})
    if 'core:datatype' in sigmf_meta['global']:
        expanded_sigmf.add_attribute(
            'datatype', **{'type': 'text', 'value': sigmf_meta['global']['core:datatype']})
    if 'core:description' in sigmf_meta['global']:
        expanded_sigmf.add_attribute(
            'description', **{'type': 'text', 'value': sigmf_meta['global']['core:description']})
    if 'core:license' in sigmf_meta['global']:
        expanded_sigmf.add_attribute(
            'license', **{'type': 'text', 'value': sigmf_meta['global']['core:license']})
    if 'core:num_channels' in sigmf_meta['global']:
        expanded_sigmf.add_attribute(
            'num_channels', **{'type': 'counter', 'value': sigmf_meta['global']['core:num_channels']})
    if 'core:recorder' in sigmf_meta['global']:
        expanded_sigmf.add_attribute(
            'recorder', **{'type': 'text', 'value': sigmf_meta['global']['core:recorder']})
    if 'core:sample_rate' in sigmf_meta['global']:
        expanded_sigmf.add_attribute(
            'sample_rate', **{'type': 'float', 'value': sigmf_meta['global']['core:sample_rate']})
    if 'core:sha512' in sigmf_meta['global']:
        expanded_sigmf.add_attribute(
            'sha512', **{'type': 'text', 'value': sigmf_meta['global']['core:sha512']})
    if 'core:version' in sigmf_meta['global']:
        expanded_sigmf.add_attribute(
            'version', **{'type': 'text', 'value': sigmf_meta['global']['core:version']})

    # add reference to original SigMF Recording object
    expanded_sigmf.add_reference(object['uuid'], "expands")

    # add FFT and waterfall plot
    try:
        plots = generate_plots(recording, sigmf_data_attr['value'])
    except Exception as e:
        logging.exception(e)
        return {"error": "Could not generate plots"}

    for plot in plots:
        expanded_sigmf.add_attribute(plot['relation'], **plot['attribute'])

    event.add_object(expanded_sigmf)
    event = json.loads(event.to_json())

    return {"results": {'Object': event['Object']}}


def introspection():
    return mispattributes


def version():
    return moduleinfo
