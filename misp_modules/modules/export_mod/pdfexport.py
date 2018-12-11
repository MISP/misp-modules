#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import date
import json
import shlex
import subprocess
import base64

from pymisp import MISPEvent


misperrors = {'error': 'Error'}

moduleinfo = {'version': '1',
              'author': 'Raphaël Vinot',
              'description': 'Simple export to PDF',
              'module-type': ['export'],
              'require_standard_format': True}

moduleconfig = []

mispattributes = {}
outputFileExtension = "pdf"
responseType = "application/pdf"

types_to_attach = ['ip-dst', 'url', 'domain']
objects_to_attach = ['domain-ip']

headers = """
:toc: right
:toclevels: 1
:toc-title: Daily Report
:icons: font
:sectanchors:
:sectlinks:
= Daily report by {org_name}
{date}

:icons: font

"""

event_level_tags = """
IMPORTANT: This event is classified TLP:{value}.

{expanded}

"""

attributes = """
=== Indicator(s) of compromise

{list_attributes}

"""

title = """
== ({internal_id}) {title}

{summary}

"""


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


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    if 'data' not in request:
        return False

    for evt in request['data']:
        report = ReportGenerator()
        report.report_headers()
        report.from_event(evt)
        report.asciidoc()

    command_line = 'asciidoctor-pdf -'
    args = shlex.split(command_line)
    with subprocess.Popen(args, stdout=subprocess.PIPE, stdin=subprocess.PIPE) as process:
        cmd_out, cmd_err = process.communicate(input=report.report.encode('utf-8'))
    return {'response': [], 'data': str(base64.b64encode(cmd_out), 'utf-8')}


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
