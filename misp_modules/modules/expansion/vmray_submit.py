#!/usr/bin/env python3

'''
Submit sample to VMRay.

Requires "vmray_rest_api"

The expansion module vmray_submit and import module vmray_import are a two step
process to import data from VMRay.
You can automate this by setting the PyMISP example script 'vmray_automation'
as a cron job

'''

import json
import base64
from distutils.util import strtobool

import io
import zipfile

from ._vmray.vmray_rest_api import VMRayRESTAPI

misperrors = {'error': 'Error'}
mispattributes = {'input': ['attachment', 'malware-sample'], 'output': ['text', 'sha1', 'sha256', 'md5', 'link']}
moduleinfo = {'version': '0.3', 'author': 'Koen Van Impe',
              'description': 'Submit a sample to VMRay',
              'module-type': ['expansion']}
moduleconfig = ['apikey', 'url', 'shareable', 'do_not_reanalyze', 'do_not_include_vmrayjobids']


include_vmrayjobids = False


def handler(q=False):
    global include_vmrayjobids

    if q is False:
        return False
    request = json.loads(q)

    try:
        data = request.get("data")
        if 'malware-sample' in request:
            # malicious samples are encrypted with zip (password infected) and then base64 encoded
            sample_filename = request.get("malware-sample").split("|", 1)[0]
            data = base64.b64decode(data)
            fl = io.BytesIO(data)
            zf = zipfile.ZipFile(fl)
            sample_hashname = zf.namelist()[0]
            data = zf.read(sample_hashname, b"infected")
            zf.close()
        elif 'attachment' in request:
            # All attachments get base64 encoded
            sample_filename = request.get("attachment")
            data = base64.b64decode(data)

        else:
            misperrors['error'] = "No malware sample or attachment supplied"
            return misperrors
    except Exception:
        misperrors['error'] = "Unable to process submited sample data"
        return misperrors

    if (request["config"].get("apikey") is None) or (request["config"].get("url") is None):
        misperrors["error"] = "Missing API key or server URL (hint: try cloud.vmray.com)"
        return misperrors

    api = VMRayRESTAPI(request["config"].get("url"), request["config"].get("apikey"), False)

    shareable = request["config"].get("shareable")
    do_not_reanalyze = request["config"].get("do_not_reanalyze")
    do_not_include_vmrayjobids = request["config"].get("do_not_include_vmrayjobids")

    try:
        shareable = bool(strtobool(shareable))                                 # Do we want the sample to be shared?
        reanalyze = not bool(strtobool(do_not_reanalyze))                      # Always reanalyze the sample?
        include_vmrayjobids = not bool(strtobool(do_not_include_vmrayjobids))  # Include the references to VMRay job IDs
    except ValueError:
        misperrors["error"] = "Error while processing settings. Please double-check your values."
        return misperrors

    if data and sample_filename:
        args = {}
        args["shareable"] = shareable
        args["sample_file"] = {'data': io.BytesIO(data), 'filename': sample_filename}
        args["reanalyze"] = reanalyze

        try:
            vmraydata = vmraySubmit(api, args)
            if vmraydata["errors"] and "Submission not stored" not in vmraydata["errors"][0]["error_msg"]:
                misperrors['error'] = "VMRay: %s" % vmraydata["errors"][0]["error_msg"]
                return misperrors
            else:
                return vmrayProcess(vmraydata)
        except Exception:
            misperrors['error'] = "Problem when calling API."
            return misperrors
    else:
        misperrors['error'] = "No sample data or filename."
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


def vmrayProcess(vmraydata):
    ''' Process the JSON file returned by vmray'''
    if vmraydata:
        try:
            sample = vmraydata["samples"][0]
            jobs = vmraydata["jobs"]

            # Result received?
            if sample:
                r = {'results': []}
                r['results'].append({'types': 'md5', 'values': sample['sample_md5hash']})
                r['results'].append({'types': 'sha1', 'values': sample['sample_sha1hash']})
                r['results'].append({'types': 'sha256', 'values': sample['sample_sha256hash']})
                r['results'].append({'types': 'text', 'values': 'VMRay Sample ID: %s' % sample['sample_id'], 'tags': 'workflow:state="incomplete"'})
                r['results'].append({'types': 'link', 'values': sample['sample_webif_url']})

                # Include data from different jobs
                if include_vmrayjobids and len(jobs) > 0:
                    for job in jobs:
                        job_id = job["job_id"]
                        job_vm_name = job["job_vm_name"]
                        job_configuration_name = job["job_configuration_name"]
                        r["results"].append({"types": "text", "values": "VMRay Job ID %s (%s - %s)" % (job_id, job_vm_name, job_configuration_name)})
                return r
            else:
                misperrors['error'] = "No valid results returned."
                return misperrors
        except Exception:
            misperrors['error'] = "No valid submission data returned."
            return misperrors
    else:
        misperrors['error'] = "Unable to parse results."
        return misperrors


def vmraySubmit(api, args):
    ''' Submit the sample to VMRay'''
    vmraydata = api.call("POST", "/rest/sample/submit", args)
    return vmraydata
