#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from pymisp import MISPEvent

try:
    from pymisp.tools import reportlab_generator
except NameError:
    raise ImportError("Failure when loading module 'reportlab_generator'")

misperrors = {"error": "Error"}

moduleinfo = {
    "version": "2",
    "author": "Vincent Falconieri (prev. Raphaël Vinot)",
    "description": "Simple export of a MISP event to PDF.",
    "module-type": ["export"],
    "name": "Event to PDF Export",
    "require_standard_format": True,
    "logo": "",
    "requirements": ["PyMISP", "reportlab"],
    "features": (
        "The module takes care of the PDF file building, and work with any MISP Event. Except the requirement of"
        " reportlab, used to create the file, there is no special feature concerning the Event. Some parameters can be"
        " given through the config dict. 'MISP_base_url_for_dynamic_link' is your MISP URL, to attach an hyperlink to"
        " your event on your MISP instance from the PDF. Keep it clear to avoid hyperlinks in the generated pdf.\n "
        " 'MISP_name_for_metadata' is your CERT or MISP instance name. Used as text in the PDF' metadata\n "
        " 'Activate_textual_description' is a boolean (True or void) to activate the textual description/header"
        " abstract of an event\n  'Activate_galaxy_description' is a boolean (True or void) to activate the description"
        " of event related galaxies.\n  'Activate_related_events' is a boolean (True or void) to activate the"
        " description of related event. Be aware this might leak information on confidential events linked to the"
        " current event !\n  'Activate_internationalization_fonts' is a boolean (True or void) to activate Noto fonts"
        " instead of default fonts (Helvetica). This allows the support of CJK alphabet. Be sure to have followed the"
        " procedure to download Noto fonts (~70Mo) in the right place (/tools/pdf_fonts/Noto_TTF), to allow PyMisp to"
        " find and use them during PDF generation.\n  'Custom_fonts_path' is a text (path or void) to the TTF file of"
        " your choice, to create the PDF with it. Be aware the PDF won't support bold/italic/special style anymore with"
        " this option "
    ),
    "references": ["https://acrobat.adobe.com/us/en/acrobat/about-adobe-pdf.html"],
    "input": "MISP Event",
    "output": "MISP Event in a PDF file.",
}

# config fields that your code expects from the site admin
moduleconfig = [
    "MISP_base_url_for_dynamic_link",
    "MISP_name_for_metadata",
    "Activate_textual_description",
    "Activate_galaxy_description",
    "Activate_related_events",
    "Activate_internationalization_fonts",
    "Custom_fonts_path",
]
mispattributes = {}

outputFileExtension = "pdf"
responseType = "application/pdf"

types_to_attach = ["ip-dst", "url", "domain"]
objects_to_attach = ["domain-ip"]


class ReportGenerator:
    def __init__(self):
        self.report = ""

    def from_remote(self, event_id):
        from keys import misp_key, misp_url, misp_verifycert
        from pymisp import PyMISP

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

    if "data" not in request:
        return False

    config = {}

    # Construct config object for reportlab_generator
    for config_item in moduleconfig:
        if (request.get("config")) and (request["config"].get(config_item) is not None):
            config[config_item] = request["config"].get(config_item)

    for evt in request["data"]:
        misp_event = MISPEvent()
        misp_event.load(evt)

        pdf = reportlab_generator.get_base64_from_value(
            reportlab_generator.convert_event_in_pdf_buffer(misp_event, config)
        )

        return {"response": [], "data": str(pdf, "utf-8")}


def introspection():
    modulesetup = {}
    try:
        responseType
        modulesetup["responseType"] = responseType
    except NameError:
        pass

    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    try:
        outputFileExtension
        modulesetup["outputFileExtension"] = outputFileExtension
    except NameError:
        pass
    try:
        inputSource
        modulesetup["inputSource"] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
