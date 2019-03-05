#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from pymisp import MISPEvent
from pymisp.tools import reportlab_generator

misperrors = {'error': 'Error'}

moduleinfo = {'version': '2',
              'author': 'Vincent Falconieri (prev. Raphaël Vinot)',
              'description': 'Simple export to PDF',
              'module-type': ['export'],
              'require_standard_format': True}

# config fields that your code expects from the site admin
moduleconfig = ["MISP_base_url_for_dynamic_link", "MISP_name_for_metadata", "Activate_textual_description", "Activate_galaxy_description", "Activate_related_events", "Activate_internationalization_fonts", "Custom_fonts_path"]
mispattributes = {}

outputFileExtension = "pdf"
responseType = "application/pdf"

types_to_attach = ['ip-dst', 'url', 'domain']
objects_to_attach = ['domain-ip']


class ReportGenerator():
    def __init__(self):
        self.report = ''

    def from_remote(self, event_id):
        from pymisp import PyMISP
        from keys import misp_url, misp_key, misp_verifycert
        misp = PyMISP(misp_url, misp_key, misp_verifycert)
        result = misp.get(event_id)
        self.misp_event = MISPEvent()
        self.misp_event.load(result)

    def from_event(self, event):
        self.misp_event = MISPEvent()
        self.misp_event.load(event)


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    if 'data' not in request:
        return False

    config = {}

    # Construct config object for reportlab_generator
    for config_item in moduleconfig:
        if (request.get('config')) and (request['config'].get(config_item) is not None):
            config[config_item] = request['config'].get(config_item)

    for evt in request['data']:
        misp_event = MISPEvent()
        misp_event.load(evt)

        pdf = reportlab_generator.get_base64_from_value(reportlab_generator.convert_event_in_pdf_buffer(misp_event, config))

        return {'response': [], 'data': str(pdf, 'utf-8')}


def introspection():
    modulesetup = {}
    try:
        responseType
        modulesetup['responseType'] = responseType
    except NameError:
        pass

    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        outputFileExtension
        modulesetup['outputFileExtension'] = outputFileExtension
    except NameError:
        pass
    try:
        inputSource
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
