#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import date
import json
import shlex
import subprocess
import base64

from pymisp import MISPEvent
from pymisp.tools import reportlab_generator

misperrors = {'error': 'Error'}

moduleinfo = {'version': '2',
              'author': 'Vincent Falconieri (prev. Raphaël Vinot)',
              'description': 'Simple export to PDF',
              'module-type': ['export'],
              'require_standard_format': True}

moduleconfig = []
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

    for evt in request['data']:

        misp_event = MISPEvent()
        misp_event.load(evt)

        pdf = reportlab_generator.get_base64_from_value(reportlab_generator.convert_event_in_pdf_buffer(misp_event))

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
