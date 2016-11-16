#!/usr/bin/env python3

'''
Import VMRay results.

This version supports import from different analyze jobs, starting from one sample
(the supplied sample_id).

Requires "vmray_rest_api"

TODO:
 # Import one job (analyze_id)
 # Import STIX package (XML version)

'''

import json
import re
import sys
import os
base_dir = os.path.dirname(__file__) or '.'
sys.path.append(base_dir)
from vmray_rest_api import VMRayRESTAPI, VMRayRESTAPIError

misperrors = {'error': 'Error'}
inputSource = []
moduleinfo = {'version': '0.1', 'author': 'Koen Van Impe',
              'description': 'Import VMRay (VTI) results',
              'module-type': ['import']}
userConfig = {
               'include_textdescr': {
                 'type': 'Boolean',
                 'message': 'Include textual description'
               },
               'include_analysisid': {
                 'type': 'Boolean',
                 'message': 'Include VMRay analysis_id text'
               },
               'only_network_info': {
                 'type': 'Boolean',
                 'message': 'Only include network (src-ip, hostname, domain, ...) information'
               },
               'sample_id': {
                 'type': 'Integer',
                 'errorMessage': 'Expected a sample ID',
                 'message': 'The VMRay sample_id'
               }
             };
moduleconfig = ['apikey', 'url']

include_textdescr = False
include_analysisid = False
only_network_info = False

def handler(q=False):
    global include_textdescr
    global include_analysisid
    global only_network_info

    if q is False:
        return False
    request = json.loads(q)

    include_textdescr = request["config"].get("include_textdescr")
    include_analysisid = request["config"].get("include_analysisid")
    only_network_info = request["config"].get("only_network_info")
    if include_textdescr == "1":
        include_textdescr = True
    else:
        include_textdescr = False
    if include_analysisid == "1":
        include_analysisid = True
    else:
        include_analysisid = False
    if only_network_info == "1":
        only_network_info = True
    else:
        only_network_info = False

    sample_id = int(request["config"].get("sample_id"))

    if (request["config"].get("apikey") is None) or (request["config"].get("url") is None):
        misperrors["error"] = "Missing API key or server URL (hint: try cloud.vmray.com)"
        return misperrors

    if sample_id > 0:
        try:
            api = VMRayRESTAPI(request["config"].get("url"), request["config"].get("apikey"), False)
            vmray_results = {'results': []}
            # Get all information on the sample, returns a set of finished analyze jobs
            data = vmrayGetInfoAnalysis(api, sample_id)
            if data["data"]:
                vti_patterns_found = False
                for analysis in data["data"]:
                    analysis_id = analysis["analysis_id"]

                    if analysis_id > 0:
                        # Get the details for an analyze job
                        analysis_data = vmrayDownloadAnalysis(api, analysis_id)

                        if analysis_data:
                            p = vmrayVtiPatterns(analysis_data["vti_patterns"])
                            if p and len(p["results"]) > 0:
                                vti_patterns_found = True
                                vmray_results = {'results': vmray_results["results"] + p["results"] }

                            if include_analysisid:
                                a_id = {'results': []}
                                url1 = "https://cloud.vmray.com/user/analysis/view?from_sample_id=%u" % sample_id
                                url2 = "&id=%u" % analysis_id
                                url3 = "&sub=%2Freport%2Foverview.html"
                                a_id["results"].append({ "values": url1 + url2 + url3, "types": "link" })
                                vmray_results = {'results': vmray_results["results"] + a_id["results"] }

                # Clean up (remove doubles)
                if vti_patterns_found:
                    vmray_results = vmrayCleanup(vmray_results)
                    return vmray_results
                else:
                    misperrors['error'] = "No vti_results returned or jobs not finished"
                    return misperrors
            else:
                misperrors['error'] = "Unable to fetch sample id %u" % (sample_id)
                return misperrors
        except:
            misperrors['error'] = "Unable to access VMRay API"
            return misperrors
    else:
        misperrors['error'] = "Not a valid sample id"
        return misperrors



def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
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


def vmrayGetInfoAnalysis(api, sample_id):
    ''' Get information from a sample, returns a set of analyzed reports'''

    if sample_id:
        data = api.call("GET", "/rest/analysis/sample/%u" % (sample_id), raw_data=True)
        return json.loads(data.read().decode())
    else:
        return False


def vmrayDownloadAnalysis(api, analysis_id):
    ''' Get the details from an analysis'''
    if analysis_id:
        data = api.call("GET", "/rest/analysis/%u/archive/additional/vti_result.json" % (analysis_id), raw_data=True)
        return json.loads(data.read().decode())
    else:
        return False


def vmrayVtiPatterns(vti_patterns):
    ''' Match the VTI patterns to MISP data'''

    if vti_patterns:
        r = {'results': []}
        y = {'results': []}

        for pattern in vti_patterns:
            content = False
            if pattern["category"] == "_network" and pattern["operation"] == "_download_data":
                content = vmrayGeneric(pattern, "url", 1)
            elif pattern["category"] == "_network" and pattern["operation"] == "_connect":
                content = vmrayConnect(pattern)

            elif only_network_info == False and pattern["category"] == "_process" and pattern["operation"] == "_alloc_wx_page":
                content = vmrayGeneric(pattern)
            elif only_network_info == False and pattern["category"] == "_process" and pattern["operation"] == "_install_ipc_endpoint":
                content = vmrayGeneric(pattern, "mutex", 1)
            elif only_network_info == False and pattern["category"] == "_process" and pattern["operation"] == "_crashed_process":
                content = vmrayGeneric(pattern)

            elif only_network_info == False and pattern["category"] == "_anti_analysis" and pattern["operation"] == "_delay_execution":
                content = vmrayGeneric(pattern)
            elif only_network_info == False and pattern["category"] == "_anti_analysis" and pattern["operation"] == "_dynamic_api_usage":
                content = vmrayGeneric(pattern)

            elif only_network_info == False and pattern["category"] == "_static" and pattern["operation"] == "_drop_pe_file":
                content = vmrayGeneric(pattern, "filename", 1)
            elif only_network_info == False and pattern["category"] == "_static" and pattern["operation"] == "_execute_dropped_pe_file":
                content = vmrayGeneric(pattern, "filename", 1)

            elif only_network_info == False and pattern["category"] == "_injection" and pattern["operation"] == "_modify_memory":
                content = vmrayGeneric(pattern)
            elif only_network_info == False and pattern["category"] == "_injection" and pattern["operation"] == "_modify_control_flow":
                content = vmrayGeneric(pattern)
            elif only_network_info == False and pattern["category"] == "_file_system" and pattern["operation"] == "_create_many_files":
                content = vmrayGeneric(pattern)

            elif only_network_info == False and pattern["category"] == "_persistence" and pattern["operation"] == "_install_startup_script":
                content = vmrayGeneric(pattern, "regkey", 1)
            elif only_network_info == False and pattern["category"] == "_os" and pattern["operation"] == "_enable_process_privileges":
                content = vmrayGeneric(pattern)

            if content:
                r["results"].append( content["attributes"] )
                r["results"].append( content["text"] )

        # Remove empty results
        r["results"] = [x for x in r["results"] if isinstance(x, dict) and  len(x["values"]) != 0]
        for el in r["results"]:
            if not el in y["results"]:
                y["results"].append( el )
        return y
    else:
        return False


def vmrayCleanup(x):
    ''' Remove doubles'''
    y = {'results': []}

    for el in x["results"]:
        if not el in y["results"]:
            y["results"].append( el )
    return y


def vmraySanitizeInput(s):
    ''' Sanitize some input so it gets properly imported in MISP'''
    if s:
        s = s.replace('"','')
        s =  re.sub('\\\\', r'\\', s)
        return s
    else:
        return False


def vmrayGeneric(el, attr = "", attrpos = 1):
    ''' Convert a 'generic' VTI pattern to MISP data'''

    r = {"values": []}
    f = {"values": []}

    if el:
        content = el["technique_desc"]
        if content:
            if attr:
                content_split = content.split("\"")
                # Attributes are between open " and close "; so use >
                if len(content_split) > attrpos:
                    content_split[attrpos] = vmraySanitizeInput(content_split[attrpos])
                    r["values"].append(content_split[attrpos])
                    r["types"] = [attr]

            # Adding the value also as text to get the extra description,
            # but this is pretty useless for "url"
            if include_textdescr and attr != "url":
                f["values"].append(vmraySanitizeInput(content))
                f["types"] = ["text"]

            return {    "text": f,
                        "attributes": r}
        else:
            return False
    else:
        return False


def vmrayConnect(el):
    ''' Extension of vmrayGeneric , parse network connect data'''
    ipre = re.compile("([0-9]{1,3}.){3}[0-9]{1,3}")

    r = {"values": []}
    f = {"values": []}

    if el:
        content = el["technique_desc"]
        if content:
            target = content.split("\"")
            port = (target[1].split(":"))[1]
            host = (target[1].split(":"))[0]
            if ipre.match(str(host)):
                r["values"].append(host)
                r["types"] = ["ip-dst"]
            else:
                r["values"].append(host)
                r["types"] = ["domain", "hostname"]

            f["values"].append(vmraySanitizeInput(target[1]))
            f["types"] = ["text"]

            if include_textdescr:
                f["values"].append(vmraySanitizeInput(content))
                f["types"] = ["text"]

            return {    "text": f,
                        "attributes": r}
        else:
            return False
    else:
        return False
