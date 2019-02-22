#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import date
import json
import shlex
import subprocess
import base64

print("test PDF pdf export (reportlab generator import)")

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

    '''
    def attributes(self):
        if not self.misp_event.attributes:
            return ''
        list_attributes = []
        for attribute in self.misp_event.attributes:
            if attribute.type in types_to_attach:
                list_attributes.append("* {}".format(attribute.value))
        for obj in self.misp_event.Object:
            if obj.name in objects_to_attach:
                for attribute in obj.Attribute:
                    if attribute.type in types_to_attach:
                        list_attributes.append("* {}".format(attribute.value))
        return attributes.format(list_attributes="\n".join(list_attributes))

    def _get_tag_info(self, machinetag):
        return self.taxonomies.revert_machinetag(machinetag)

    def report_headers(self):
        content = {'org_name': 'name',
                   'date': date.today().isoformat()}
        self.report += headers.format(**content)

    def event_level_tags(self):
        if not self.misp_event.Tag:
            return ''
        for tag in self.misp_event.Tag:
            # Only look for TLP for now
            if tag['name'].startswith('tlp'):
                tax, predicate = self._get_tag_info(tag['name'])
                return self.event_level_tags.format(value=predicate.predicate.upper(), expanded=predicate.expanded)

    def title(self):
        internal_id = ''
        summary = ''
        # Get internal refs for report
        if not hasattr(self.misp_event, 'Object'):
            return ''
        for obj in self.misp_event.Object:
            if obj.name != 'report':
                continue
            for a in obj.Attribute:
                if a.object_relation == 'case-number':
                    internal_id = a.value
                if a.object_relation == 'summary':
                    summary = a.value

        return title.format(internal_id=internal_id, title=self.misp_event.info,
                            summary=summary)

    def asciidoc(self, lang='en'):
        self.report += self.title()
        self.report += self.event_level_tags()
        self.report += self.attributes()
    '''

def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    if 'data' not in request:
        return False

    for evt in request['data']:

        '''
        print(" DATA ")
        print(request['data'])

        reportlab_generator.
        
        report = ReportGenerator()
        report.report_headers()
        report.from_event(evt)
        report.asciidoc()

        print(" REPORT : ")
        print(report)
        '''

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

import pprint

if __name__ == "__main__":
    pprint.pprint("test")