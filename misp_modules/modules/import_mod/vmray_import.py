#!/usr/bin/env python3

'''
Import VMRay results.

This version supports import from different analyze jobs, starting from one sample
(the supplied sample_id).

The expansion module vmray_submit and import module vmray_import are a two step
process to import data from VMRay.
You can automate this by setting the PyMISP example script 'vmray_automation'
as a cron job

'''

import json

from _vmray.parser import VMRayParser, VMRayParseError


misperrors = {'error': 'Error'}

moduleinfo = {'version': '0.4', 'author': 'Jens Thom (VMRay), Koen van Impe',
              'description': 'Import VMRay analysis results from a server',
              'module-type': ['import']}

mispattributes = {
    'inputSource': [],
    'output': ['MISP objects'],
    'format': 'misp_standard',
}

userConfig = {
    "Sample ID": {
        "type": "Integer",
        "errorMessage": "The VMRay sample ID to download the reports",
    },
    "VTI": {
        "type": "Boolean",
        "message": "Include VMRay Threat Identifiers",
        "checked": "True"
    },
    "IOCs": {
        "type": "Boolean",
        "message": "Include IOCs",
        "checked": "True"
    },
    "Artifacts": {
        "type": "Boolean",
        "message": "Include other Artifacts",
    },
    "Analysis Details": {
        "type": "Boolean",
        "message": "Include Analysis Details",
        "checked": "True"
    }
}

moduleconfig = ["apikey", "url", "disable_tags", "disable_misp_objects", "ignore_analysis_finished"]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    parser = VMRayParser()
    try:
        parser.from_api(request["config"])
        parser.parse()
    except VMRayParseError as exc:
        misperrors["error"] = str(exc)
        return misperrors

    event = parser.to_json()
    return event


def introspection():
    mispattributes["userConfig"] = userConfig
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
