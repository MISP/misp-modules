# -*- coding: utf-8 -*-

import base64
import json
import tempfile
import logging
import sys
from pymisp import MISPObject, MISPEvent
from sigmf import SigMFFile

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

    # TODO: geolocation (GeoJSON)

    # add reference to original SigMF Recording object
    expanded_sigmf.add_reference(object['uuid'], "expands")
    
    event.add_object(expanded_sigmf)
    event = json.loads(event.to_json())

    return {"results": {'Object': event['Object']}}


def introspection():
    return mispattributes


def version():
    return moduleinfo
